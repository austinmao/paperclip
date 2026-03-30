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
import { authUsers, authSessions, companyMemberships } from "@paperclipai/db";
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

  // All bridge routes require bridge JWT auth
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

  return router;
}
