// ---------------------------------------------------------------------------
// Bridge routes — Lumina platform ↔ Paperclip workspace integration
// ---------------------------------------------------------------------------
// These endpoints are called by the Lumina platform's PaperclipWorkspaceAdapter
// during SSO bridge handoff. They handle:
//
//   POST /upsert-user         — create or update a local auth user
//   POST /sync-membership     — create or update a company membership
//   POST /create-session      — mint a local Better Auth session
//   POST /revoke-access       — suspend membership + delete sessions
//
// All endpoints are authenticated with a short-lived Bridge JWT signed with
// PAPERCLIP_AGENT_JWT_SECRET.
//
// Security:
//   - All inputs validated before DB operations (length, format, role allowlist)
//   - Parameterized queries only (Drizzle ORM)
//   - No user-supplied values in error messages
//   - Bridge JWT verified on every request (60-second TTL, issuer check)
//   - JTI replay prevention (in-process nonce set with TTL eviction)
//   - Session revocation scoped to company (no cross-tenant side effects)
// ---------------------------------------------------------------------------

import { Router, type Request, type Response, type NextFunction } from "express";
import { eq, and } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { authUsers, authSessions, companyMemberships, companies, instanceUserRoles } from "@paperclipai/db";
import { verifyBridgeJwt } from "../bridge-auth-jwt.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALLOWED_ROLES = new Set(["owner", "admin", "member"]);
const MAX_STRING_LENGTH = 255;
const MAX_ID_LENGTH = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UpsertUserBody {
  platform_user_id: string;
  email: string;
  name: string;
}

interface SyncMembershipBody {
  company_id: string;
  user_id: string;
  role: string;
}

interface CreateSessionBody {
  user_id: string;
}

interface RevokeAccessBody {
  user_id: string;
  company_id: string;
}

interface BootstrapBody {
  company_name: string;
  admin_user_id: string;
}

// ---------------------------------------------------------------------------
// JTI replay prevention (CRIT-1 fix)
// ---------------------------------------------------------------------------

const usedJtis = new Map<string, number>();

function checkAndRecordJti(jti: string, exp: number): boolean {
  const now = Math.floor(Date.now() / 1000);

  // Evict expired entries (keep map bounded)
  for (const [k, e] of usedJtis) {
    if (e < now) usedJtis.delete(k);
  }

  if (usedJtis.has(jti)) return false;
  usedJtis.set(jti, exp);
  return true;
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function isBoundedString(value: unknown, maxLen: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLen;
}

function validateUpsertUser(body: unknown): UpsertUserBody | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (
    !isBoundedString(b.platform_user_id, MAX_ID_LENGTH) ||
    !isBoundedString(b.email, MAX_STRING_LENGTH) ||
    !isBoundedString(b.name, MAX_STRING_LENGTH)
  ) {
    return null;
  }
  return {
    platform_user_id: b.platform_user_id,
    email: b.email,
    name: b.name,
  };
}

function validateSyncMembership(body: unknown): SyncMembershipBody | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (
    !isBoundedString(b.company_id, MAX_ID_LENGTH) ||
    !isBoundedString(b.user_id, MAX_ID_LENGTH) ||
    !isBoundedString(b.role, MAX_ID_LENGTH)
  ) {
    return null;
  }
  // CRIT-3 fix: enforce role allowlist
  if (!ALLOWED_ROLES.has(b.role as string)) {
    return null;
  }
  return {
    company_id: b.company_id,
    user_id: b.user_id,
    role: b.role as string,
  };
}

function validateCreateSession(body: unknown): CreateSessionBody | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (!isBoundedString(b.user_id, MAX_ID_LENGTH)) return null;
  return { user_id: b.user_id };
}

function validateBootstrap(body: unknown): BootstrapBody | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (
    !isBoundedString(b.company_name, MAX_STRING_LENGTH) ||
    !isBoundedString(b.admin_user_id, MAX_ID_LENGTH)
  ) {
    return null;
  }
  return { company_name: b.company_name, admin_user_id: b.admin_user_id };
}

function validateRevokeAccess(body: unknown): RevokeAccessBody | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (
    !isBoundedString(b.user_id, MAX_ID_LENGTH) ||
    !isBoundedString(b.company_id, MAX_ID_LENGTH)
  ) {
    return null;
  }
  return { user_id: b.user_id, company_id: b.company_id };
}

// ---------------------------------------------------------------------------
// Bridge JWT auth middleware
// ---------------------------------------------------------------------------

function bridgeAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or invalid Authorization header" });
    return;
  }

  const token = authHeader.slice(7);
  const claims = verifyBridgeJwt(token);
  if (!claims) {
    res.status(401).json({ error: "Invalid or expired bridge token" });
    return;
  }

  // CRIT-1 fix: reject replayed tokens
  if (!checkAndRecordJti(claims.jti, claims.exp)) {
    res.status(401).json({ error: "Token already used" });
    return;
  }

  (req as Request & { bridgeClaims: typeof claims }).bridgeClaims = claims;
  next();
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

function generateId(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export function bridgeRoutes(db: Db) {
  const router = Router();

  // ── GET /sso-landing ──────────────────────────────────────────────────
  // Browser redirect target for cross-domain SSO. Registered BEFORE the
  // bridgeAuth middleware because this is a browser GET (no Bearer token).
  // The handoff JWT itself is verified inline for authentication.
  router.get("/sso-landing", async (req: Request, res: Response) => {
    const handoff = req.query.handoff;
    if (typeof handoff !== "string" || !handoff) {
      res.status(400).json({ error: "Missing handoff parameter" });
      return;
    }

    // Verify the handoff JWT (same verification as bridge auth)
    const claims = verifyBridgeJwt(handoff);
    if (!claims) {
      res.status(401).json({ error: "Invalid or expired handoff token" });
      return;
    }

    // Reject replayed tokens
    if (!checkAndRecordJti(claims.jti, claims.exp)) {
      res.status(401).json({ error: "Token already used" });
      return;
    }

    // Extract session token from JWT claims
    const parts = handoff.split(".");
    if (parts.length !== 3) {
      res.status(400).json({ error: "Malformed handoff token" });
      return;
    }

    let sessionToken: string | undefined;
    try {
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      sessionToken = typeof payload.session_token === "string" ? payload.session_token : undefined;
    } catch {
      res.status(400).json({ error: "Malformed handoff token" });
      return;
    }

    if (!sessionToken) {
      res.status(400).json({ error: "Missing session token in handoff" });
      return;
    }

    // Verify the session exists in the database
    const session = await db
      .select({ id: authSessions.id })
      .from(authSessions)
      .where(eq(authSessions.token, sessionToken))
      .limit(1);

    if (session.length === 0) {
      res.status(400).json({ error: "Invalid session" });
      return;
    }

    // Set the Better Auth session cookie on this domain.
    // Behind a reverse proxy, Better Auth's auto-detection of secure cookies
    // may vary. Set both variants so the correct one always matches.
    const isSecure = req.protocol === "https" || req.headers["x-forwarded-proto"] === "https";
    const cookieOpts = {
      httpOnly: true,
      secure: isSecure,
      sameSite: "lax" as const,
      path: "/",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days (matches session TTL)
    };
    res.cookie("better-auth.session_token", sessionToken, cookieOpts);
    if (isSecure) {
      res.cookie("__Secure-better-auth.session_token", sessionToken, cookieOpts);
    }

    res.redirect("/");
  });

  // All remaining bridge routes require bridge JWT auth
  router.use(bridgeAuth);

  // ── POST /upsert-user ───────────────────────────────────────────────────
  router.post("/upsert-user", async (req: Request, res: Response) => {
    const body = validateUpsertUser(req.body);
    if (!body) {
      res.status(400).json({ error: "Invalid request body" });
      return;
    }

    const now = new Date();

    const existing = await db
      .select({ id: authUsers.id })
      .from(authUsers)
      .where(eq(authUsers.id, body.platform_user_id))
      .limit(1);

    if (existing.length > 0) {
      await db
        .update(authUsers)
        .set({
          name: body.name,
          email: body.email,
          emailVerified: true,
          updatedAt: now,
        })
        .where(eq(authUsers.id, body.platform_user_id));

      res.json({ user_id: existing[0].id });
      return;
    }

    await db.insert(authUsers).values({
      id: body.platform_user_id,
      name: body.name,
      email: body.email,
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
    });

    res.json({ user_id: body.platform_user_id });
  });

  // ── POST /sync-membership ───────────────────────────────────────────────
  router.post("/sync-membership", async (req: Request, res: Response) => {
    const body = validateSyncMembership(req.body);
    if (!body) {
      res.status(400).json({ error: "Invalid request body" });
      return;
    }

    const now = new Date();

    const existing = await db
      .select({ id: companyMemberships.id })
      .from(companyMemberships)
      .where(
        and(
          eq(companyMemberships.companyId, body.company_id),
          eq(companyMemberships.principalType, "user"),
          eq(companyMemberships.principalId, body.user_id),
        ),
      )
      .limit(1);

    if (existing.length > 0) {
      await db
        .update(companyMemberships)
        .set({
          membershipRole: body.role,
          status: "active",
          updatedAt: now,
        })
        .where(eq(companyMemberships.id, existing[0].id));
    } else {
      await db.insert(companyMemberships).values({
        companyId: body.company_id,
        principalType: "user",
        principalId: body.user_id,
        membershipRole: body.role,
        status: "active",
        createdAt: now,
        updatedAt: now,
      });
    }

    res.json({ ok: true });
  });

  // ── POST /create-session ────────────────────────────────────────────────
  router.post("/create-session", async (req: Request, res: Response) => {
    const body = validateCreateSession(req.body);
    if (!body) {
      res.status(400).json({ error: "Invalid request body" });
      return;
    }

    const user = await db
      .select({ id: authUsers.id })
      .from(authUsers)
      .where(eq(authUsers.id, body.user_id))
      .limit(1);

    if (user.length === 0) {
      res.status(400).json({ error: "Invalid request" });
      return;
    }

    const now = new Date();
    const sessionId = generateId();
    const sessionToken = generateId();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days

    await db.insert(authSessions).values({
      id: sessionId,
      token: sessionToken,
      userId: body.user_id,
      expiresAt,
      createdAt: now,
      updatedAt: now,
    });

    res.json({ session_token: sessionToken });
  });

  // ── POST /revoke-access ─────────────────────────────────────────────────
  router.post("/revoke-access", async (req: Request, res: Response) => {
    const body = validateRevokeAccess(req.body);
    if (!body) {
      res.status(400).json({ error: "Invalid request body" });
      return;
    }

    const now = new Date();

    // Suspend membership (scoped to company)
    await db
      .update(companyMemberships)
      .set({ status: "suspended", updatedAt: now })
      .where(
        and(
          eq(companyMemberships.companyId, body.company_id),
          eq(companyMemberships.principalType, "user"),
          eq(companyMemberships.principalId, body.user_id),
        ),
      );

    // CRIT-2 fix: Only delete sessions if user has NO remaining active
    // memberships in any company on this instance. This prevents
    // cross-company session invalidation.
    const remainingMemberships = await db
      .select({ id: companyMemberships.id })
      .from(companyMemberships)
      .where(
        and(
          eq(companyMemberships.principalType, "user"),
          eq(companyMemberships.principalId, body.user_id),
          eq(companyMemberships.status, "active"),
        ),
      )
      .limit(1);

    if (remainingMemberships.length === 0) {
      await db
        .delete(authSessions)
        .where(eq(authSessions.userId, body.user_id));
    }

    res.json({ ok: true });
  });

  // ── POST /bootstrap ──────────────────────────────────────────────────
  // Idempotent first-time setup: create company + grant instance_admin role.
  // Called by Lumina platform after claiming a warm pool instance.
  router.post("/bootstrap", async (req: Request, res: Response) => {
    const body = validateBootstrap(req.body);
    if (!body) {
      res.status(400).json({ error: "Invalid request body" });
      return;
    }

    const now = new Date();

    // Verify the admin user exists
    const user = await db
      .select({ id: authUsers.id })
      .from(authUsers)
      .where(eq(authUsers.id, body.admin_user_id))
      .limit(1);

    if (user.length === 0) {
      res.status(400).json({ error: "Admin user not found — call upsert-user first" });
      return;
    }

    // Create company (idempotent — check if one already exists)
    const existingCompanies = await db
      .select({ id: companies.id })
      .from(companies)
      .limit(1);

    let companyId: string;

    if (existingCompanies.length > 0) {
      companyId = existingCompanies[0].id;
    } else {
      const [newCompany] = await db
        .insert(companies)
        .values({
          name: body.company_name,
          status: "active",
          issuePrefix: "LUM",
          createdAt: now,
          updatedAt: now,
        })
        .returning({ id: companies.id });
      companyId = newCompany.id;
    }

    // Grant instance_admin role (idempotent — ON CONFLICT DO NOTHING via check)
    const existingRole = await db
      .select({ id: instanceUserRoles.id })
      .from(instanceUserRoles)
      .where(
        and(
          eq(instanceUserRoles.userId, body.admin_user_id),
          eq(instanceUserRoles.role, "instance_admin"),
        ),
      )
      .limit(1);

    if (existingRole.length === 0) {
      await db.insert(instanceUserRoles).values({
        userId: body.admin_user_id,
        role: "instance_admin",
        createdAt: now,
        updatedAt: now,
      });
    }

    // Create owner membership in the company
    const existingMembership = await db
      .select({ id: companyMemberships.id })
      .from(companyMemberships)
      .where(
        and(
          eq(companyMemberships.companyId, companyId),
          eq(companyMemberships.principalType, "user"),
          eq(companyMemberships.principalId, body.admin_user_id),
        ),
      )
      .limit(1);

    if (existingMembership.length === 0) {
      await db.insert(companyMemberships).values({
        companyId,
        principalType: "user",
        principalId: body.admin_user_id,
        membershipRole: "owner",
        status: "active",
        createdAt: now,
        updatedAt: now,
      });
    }

    res.json({ company_id: companyId, ok: true });
  });

  return router;
}
