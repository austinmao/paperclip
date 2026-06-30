/**
 * openclaw-idp.ts — THE single customization surface for the Paperclip IdP.
 * ===========================================================================
 *
 * spec-201 (better-auth 1.4.18 → 1.6.19 + `@better-auth/oauth-provider@1.6.19`).
 *
 * This module is the ONE file upstream (`paperclipai/paperclip`) never touches.
 * It is injected into the fork's stock `createBetterAuthInstance` via a single
 * one-line edit:
 *
 *     plugins: [...openclawIdpPlugins(config)]
 *
 * and the assembled plugin set is pinned by a seam contract test (C-IDP-4), so
 * an upstream refactor of `createBetterAuthInstance` fails LOUD instead of
 * silently producing a mis-configured IdP. This replaces — and at cutover
 * RETIRES — the fragile, line-anchored patch-package dist overlay at
 * `infra/paperclip/patches/@paperclipai+server+2026.609.0.patch` (R2).
 *
 * What this overlay adds to the stock better-auth config, ported verbatim from
 * the 1.4 patch and re-expressed against the 1.6 API:
 *
 *   - `jwt()` — EdDSA/Ed25519 signing (better-auth default); JWKS at
 *     `<basePath>/jwks`. The signing key MUST be preserved across cutover so
 *     `kid` is stable (data-model continuity rule; C-IDP-5). Also backs the
 *     guarded S2S mint route (`signJWT`).
 *
 *   - `oauthProvider({...})` (1.4→1.6: replaces 1.4's `oidcProvider`):
 *       · `validAudiences` — includes the canonical connector audience
 *         `https://connector.getglance.com/mcp`. 1.6 issues a *verifiable JWT*
 *         access token (carrying `aud` + `org_id`) when the token request names
 *         a `resource` in this list; a request for an audience NOT in the list
 *         is rejected — never a silent opaque downgrade (C-IDP-1, C-IDP-3).
 *       · `customAccessTokenClaims({user,resource})` — injects `org_id` into the
 *         JWT body AND the introspection response (1.4→1.6: replaces the 1.4
 *         `getAdditionalUserInfoClaim(user)` userinfo-only hook). Sourced from
 *         `resolveOrgIdForUser` with the deterministic exactly-one-membership
 *         guard (C-IDP-1, C-IDP-3). `customIdTokenClaims` /
 *         `customUserInfoClaims` mirror it for id_token / userinfo parity.
 *       · trusted first-party clients `openclaw-admin` (spec-180) and
 *         `openclaw-connector` (spec-189) — env-derived secrets + exact
 *         redirect URIs, NO wildcards. PKCE required, S256-only, consent
 *         skipped (1.4→1.6: in 1.6 `requirePKCE`/`skipConsent` are PER-CLIENT
 *         fields and there is no top-level `trustedClients` array — clients are
 *         seeded as `oauthClient` rows and marked immutable/trusted via
 *         `cachedTrustedClients`).
 *
 *   - `/internal/gateway-token` S2S mint handler — `x-machine-mint-key`
 *     timing-safe compare, slug validated against the company registry, `org_id`
 *     constructed SERVER-SIDE (caller-supplied claims are structurally
 *     impossible). Unchanged 1.4→1.6 (`auth.api.signJWT`).
 *
 *   - password-reset redaction — the reset URL is a bearer secret; we log a
 *     NON-secret event only (no URL, no token). Unchanged 1.4→1.6.
 *
 * Secrets are env-only (Doppler-held), NEVER hardcoded. Env var names are
 * preserved verbatim from the 1.4 patch so Doppler/operator config carries over.
 *
 * Contract map: C-IDP-1 (verifiable JWT + org_id) → `oauthProviderConfig` +
 * `customAccessTokenClaims` + `resolveOrgIdForUser`; C-IDP-3 (audience + tenant
 * guard) → `validAudiences` + the `rows.length !== 1` rule; C-IDP-4 (seam) →
 * `openclawIdpPlugins` + `getOpenclawTrustedClients`.
 */

import { APIError, type BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { jwt, magicLink } from "better-auth/plugins";
// 1.4→1.6: `oidcProvider` moved out of `better-auth/plugins` core into the
// dedicated `@better-auth/oauth-provider` package and was renamed
// `oauthProvider`. It issues verifiable JWT access tokens + RFC7662
// introspection (the whole point of spec-201).
import { oauthProvider } from "@better-auth/oauth-provider";
import type { OAuthOptions, SchemaClient } from "@better-auth/oauth-provider";
import { jwtVerify } from "jose";
import { sql, type SQL } from "drizzle-orm";
import { timingSafeEqual, createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// Constants (issuer/audience/TTL). Values that are environment-specific stay in
// env; these are protocol identities fixed by the deployment.
// ---------------------------------------------------------------------------

/** First-party admin web client (spec-180). */
const OPENCLAW_ADMIN_CLIENT_ID = "openclaw-admin";
/** Per-tenant MCP connector client — the claude.ai surface (spec-189). */
const OPENCLAW_CONNECTOR_CLIENT_ID = "openclaw-connector";

/**
 * Connector audience (C-IDP-1). A token requested with this `resource` is
 * issued as a JWT whose `aud` includes it; the connector verifies offline via
 * JWKS (R5). MUST appear in `validAudiences` or the request is rejected.
 */
export const OPENCLAW_CONNECTOR_AUDIENCE = "https://connector.getglance.com/mcp";
/** Back-compat alias for older contract names; same canonical getglance resource. */
export const OPENCLAW_CONNECTOR_GETGLANCE_AUDIENCE = OPENCLAW_CONNECTOR_AUDIENCE;

/** Issuer — matches Better Auth baseURL + OIDC discovery metadata (one `iss`). */
export const OPENCLAW_IDP_ISSUER = "https://agents.getglance.com";

/** S2S gateway-token mint constants (ported verbatim from the 1.4 patch). */
const GATEWAY_TOKEN_AUDIENCE = "lumina-gateway";
const GATEWAY_TOKEN_TTL_SECONDS = 300;
const MINT_RATE_LIMIT_WINDOW_MS = 60_000;
const MINT_RATE_LIMIT_MAX = 30;
const MINT_RATE_LIMIT_BUCKET_CAP = 10_000;
const MAX_TENANT_SLUG_LENGTH = 200;
const TENANT_SLUG_RE = /^[a-z0-9][a-z0-9_-]*$/i;
const OPENCLAW_DCR_MAX_CLIENTS_DEFAULT = 500;
const OPENCLAW_DCR_ALERT_PER_HOUR_DEFAULT = 50;
const AGENTS_SSO_AUDIENCE = "glance-agents-sso";
const AGENTS_SSO_NONCE_PREFIX = "openclaw-agents-sso:";

/**
 * Minimal structural type for the IdP config the fork passes through. Kept
 * loose on purpose — the overlay only reads what it needs and never widens the
 * upstream config surface.
 */
export interface OpenclawIdpConfig {
  /** Better Auth baseURL / issuer (defaults to {@link OPENCLAW_IDP_ISSUER}). */
  readonly baseUrl?: string;
}

/**
 * A `db.execute`-capable handle (drizzle). The param is the drizzle `SQL` type the
 * overlay actually passes (every call is `db.execute(sql`…`)`); typing it that way
 * (not `unknown`) lets the fork's real `PostgresJsDatabase` satisfy this structural
 * type under strictFunctionTypes contravariance — `unknown` is too wide, so a
 * `(string | SQLWrapper) => …` execute is otherwise not assignable to it.
 */
type DbExecutor = {
  execute: (query: SQL) => Promise<unknown>;
};

/** Better Auth instance shape the mint handler needs (only `api.signJWT`). */
type SignJwtCapableAuth = {
  api: { signJWT: (input: { body: { payload: Record<string, unknown> } }) => Promise<{ token: string }> };
};

// ---------------------------------------------------------------------------
// Trusted-client construction (ported from the 1.4 patch
// buildTrustedClient/buildOpenclawTrustedClients/getOpenclawTrustedClients).
//
// 1.4→1.6: in 1.4 these objects went into the top-level `oidcProvider({
// trustedClients: [...] })` array. 1.6 has NO such option — `requirePKCE` and
// `skipConsent` are per-client (`SchemaClient`) fields and `redirectUrls` was
// renamed `redirectUris`. The clients are seeded into the `oauthClient` table
// and marked trusted/immutable via `cachedTrustedClients` (a Set of client_ids).
// We keep an owned in-memory collection so (a) the seam contract test can assert
// the exact membership/config and (b) the seeder + `cachedTrustedClients` derive
// from one source.
// ---------------------------------------------------------------------------

/** A trusted client as this overlay models it (1.6 `SchemaClient` subset). */
export type OpenclawTrustedClient = SchemaClient & {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
};

function parseRedirectUrlsFromEnv(envName: string): string[] {
  return (process.env[envName] ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

/**
 * A8 (ported verbatim): redirect URIs are an exact-match allowlist from env —
 * NEVER wildcards, NEVER derived from request input.
 */
function assertNoWildcardRedirects(redirectUris: string[], envName: string): void {
  if (redirectUris.some((value) => value.includes("*"))) {
    throw new Error(`${envName} must not contain wildcard entries (spec-180 A8).`);
  }
}

function buildTrustedClient(args: {
  clientId: string;
  name: string;
  secretEnv: string;
  redirectEnv: string;
  notSetHint?: string;
}): OpenclawTrustedClient | null {
  const clientSecret = process.env[args.secretEnv] ?? "";
  const redirectUris = parseRedirectUrlsFromEnv(args.redirectEnv);
  assertNoWildcardRedirects(redirectUris, args.redirectEnv);
  if (!clientSecret || redirectUris.length === 0) {
    console.warn(
      `[paperclip-idp] ${args.secretEnv} / ${args.redirectEnv} not set — the ` +
        `${args.clientId} trusted OIDC client is NOT registered.${args.notSetHint ? " " + args.notSetHint : ""}`,
    );
    return null;
  }
  return {
    clientId: args.clientId,
    clientSecret,
    name: args.name,
    type: "web",
    // 1.4→1.6: `redirectUrls` → `redirectUris`.
    redirectUris,
    disabled: false,
    // 1.4→1.6: per-client flags (were top-level oidcProvider options in 1.4).
    requirePKCE: true,
    skipConsent: true,
    metadata: "{}",
  };
}

/**
 * Build the trusted first-party clients from env. `openclaw-admin` (spec-180)
 * and `openclaw-connector` (spec-189) are independently optional: each
 * registers only when its own secret + redirect env is set.
 *
 * Env names preserved verbatim from the 1.4 patch:
 *   OPENCLAW_ADMIN_CLIENT_SECRET, OPENCLAW_ADMIN_REDIRECT_URLS,
 *   OPENCLAW_CONNECTOR_CLIENT_SECRET, OPENCLAW_CONNECTOR_REDIRECT_URLS.
 */
export function buildOpenclawTrustedClients(): OpenclawTrustedClient[] {
  const clients = [
    buildTrustedClient({
      clientId: OPENCLAW_ADMIN_CLIENT_ID,
      name: "OpenClaw Admin",
      secretEnv: "OPENCLAW_ADMIN_CLIENT_SECRET",
      redirectEnv: "OPENCLAW_ADMIN_REDIRECT_URLS",
    }),
    buildTrustedClient({
      clientId: OPENCLAW_CONNECTOR_CLIENT_ID,
      name: "OpenClaw Connector",
      secretEnv: "OPENCLAW_CONNECTOR_CLIENT_SECRET",
      redirectEnv: "OPENCLAW_CONNECTOR_REDIRECT_URLS",
      notSetHint: "(spec-189 per-tenant MCP connector).",
    }),
  ];
  return clients.filter((client): client is OpenclawTrustedClient => client !== null);
}

let cachedTrustedClients: OpenclawTrustedClient[] | null = null;

/**
 * Memoized trusted-client set. Read by the plugin config, the seam contract
 * test (C-IDP-4), and the client seeder. Idempotent and side-effect free.
 */
export function getOpenclawTrustedClients(): OpenclawTrustedClient[] {
  if (cachedTrustedClients === null) {
    cachedTrustedClients = buildOpenclawTrustedClients();
  }
  return cachedTrustedClients;
}

// ---------------------------------------------------------------------------
// Anonymous DCR cumulative cap + volume signal (spec-199 WS3).
//
// @better-auth/oauth-provider@1.6.19 exposes config for DCR, anonymous DCR,
// scope limits, client-secret TTL, and endpoint velocity limits, but no
// documented pre-persist registration callback. Better Auth plugin before-hooks
// are the clean owned seam: this overlay inserts a tiny guard plugin before the
// oauth-provider plugin, so `/oauth2/register` is checked before oauth-provider
// persists a new oauthClient row.
//
// The cap is intentionally cumulative over self-registered oauthClient rows:
// reaching it is a fail-closed operator signal to prune junk rows or raise the
// ceiling, not an active-client TTL window.
// ---------------------------------------------------------------------------

export interface DcrRegistrationLimits {
  maxClients: number;
  alertPerHour: number;
}

export interface DcrRegistrationCounts {
  totalSelfRegistered: number;
  recentSelfRegistered: number;
}

export function dcrClientMetadataRequestsConsentBypass(input: unknown): boolean {
  if (input === null || typeof input !== "object") {
    return false;
  }
  const record = input as Record<string, unknown>;
  if ("skipConsent" in record || "skip_consent" in record) {
    return true;
  }
  const metadata = record.metadata;
  if (metadata && typeof metadata === "object") {
    return dcrClientMetadataRequestsConsentBypass(metadata);
  }
  if (typeof metadata === "string" && metadata.trim().startsWith("{")) {
    try {
      return dcrClientMetadataRequestsConsentBypass(JSON.parse(metadata));
    } catch {
      return false;
    }
  }
  return false;
}

function parseNonNegativeIntEnv(name: string, fallback: number): number {
  const raw = (process.env[name] ?? "").trim();
  if (!raw) {
    return fallback;
  }
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

export function resolveDcrRegistrationLimits(): DcrRegistrationLimits {
  return {
    maxClients: parseNonNegativeIntEnv(
      "OPENCLAW_DCR_MAX_CLIENTS",
      OPENCLAW_DCR_MAX_CLIENTS_DEFAULT,
    ),
    alertPerHour: parseNonNegativeIntEnv(
      "OPENCLAW_DCR_ALERT_PER_HOUR",
      OPENCLAW_DCR_ALERT_PER_HOUR_DEFAULT,
    ),
  };
}

function numberFromCount(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function firstCount(result: unknown): number {
  const row = extractRows(result)[0] as { count?: unknown } | undefined;
  return numberFromCount(row?.count);
}

/**
 * Count self-registered clients only. Seeded/trusted first-party clients are
 * identified by stable client_id values and are intentionally excluded from
 * both the cumulative cap and the hourly alert threshold.
 */
export async function getDcrRegistrationCounts(db: DbExecutor): Promise<DcrRegistrationCounts> {
  const total = await db.execute(sql`
    select count(*)::int as count
      from "oauthClient"
     where "clientId" not in (${OPENCLAW_ADMIN_CLIENT_ID}, ${OPENCLAW_CONNECTOR_CLIENT_ID})
  `);
  const recent = await db.execute(sql`
    select count(*)::int as count
      from "oauthClient"
     where "clientId" not in (${OPENCLAW_ADMIN_CLIENT_ID}, ${OPENCLAW_CONNECTOR_CLIENT_ID})
       and "createdAt" >= now() - interval '1 hour'
  `);
  return {
    totalSelfRegistered: firstCount(total),
    recentSelfRegistered: firstCount(recent),
  };
}

function throwDcrCapExceeded(counts: DcrRegistrationCounts, limits: DcrRegistrationLimits): never {
  throw new APIError("TOO_MANY_REQUESTS", {
    error: "invalid_client_metadata",
    error_description:
      "dynamic client registration capacity exceeded; contact the service operator",
    max_clients: limits.maxClients,
    current_clients: counts.totalSelfRegistered,
  });
}

function throwDcrConsentBypassRejected(): never {
  throw new APIError("BAD_REQUEST", {
    error: "invalid_client_metadata",
    error_description: "dynamic clients cannot request consent bypass",
  });
}

/**
 * Enforce the cumulative DCR cap and emit a greppable warn-level volume signal.
 * Called from the Better Auth before-hook before oauth-provider persists the
 * client row. It intentionally logs only aggregate counts and env names.
 */
export async function assertDcrRegistrationBudget(
  db: DbExecutor,
  limits: DcrRegistrationLimits = resolveDcrRegistrationLimits(),
): Promise<DcrRegistrationCounts> {
  // Serialize concurrent register callers before counting. Better Auth already
  // runs the registration path through the request-scoped adapter/transaction,
  // so this advisory xact lock keeps the cap check aligned with the eventual
  // oauthClient insert instead of racing on a plain count.
  await db.execute(sql`
    select pg_advisory_xact_lock(
      hashtext('openclaw'),
      hashtext('dcr:register')
    )
  `);
  const counts = await getDcrRegistrationCounts(db);
  if (counts.totalSelfRegistered >= limits.maxClients) {
    throwDcrCapExceeded(counts, limits);
  }

  const projectedHourlyCount = counts.recentSelfRegistered + 1;
  if (projectedHourlyCount > limits.alertPerHour) {
    console.warn(
      "[paperclip-idp] dcr.volume.alert " +
        `recent_count=${projectedHourlyCount} threshold=${limits.alertPerHour} ` +
        `total_count=${counts.totalSelfRegistered + 1} env=OPENCLAW_DCR_ALERT_PER_HOUR`,
    );
  }
  return counts;
}

export function isDcrRegistrationPath(path: string | null | undefined): boolean {
  const normalized = (path ?? "").split("?")[0]?.replace(/\/+$/u, "") || "/";
  return normalized === "/oauth2/register" || normalized.endsWith("/oauth2/register");
}

export function dcrRegistrationGuardPlugin(db: DbExecutor): BetterAuthPlugin {
  return {
    id: "openclaw-dcr-registration-guard",
    hooks: {
      before: [
        {
          matcher: (context) => isDcrRegistrationPath(context.path),
          handler: async (context) => {
            if (dcrClientMetadataRequestsConsentBypass((context as { body?: unknown }).body)) {
              throwDcrConsentBypassRejected();
            }
            await assertDcrRegistrationBudget(db);
          },
        },
      ],
    },
  };
}

// ---------------------------------------------------------------------------
// Agents SSO bridge.
//
// Platform app sessions (`__ba_session`) and Paperclip sessions are intentionally
// different cookie/session contracts. The bridge accepts a 60-second HS256 token
// minted by app.getglance.com, resolves the same Better Auth user inside
// Paperclip, creates a native Paperclip Better Auth session, and lets Better Auth
// set its own signed session cookie.
// ---------------------------------------------------------------------------

type AgentsSsoUser = {
  id: string;
  email?: string | null;
  name?: string | null;
};

type AgentsSsoEndpointContext = {
  query: { token?: unknown };
  context: {
    internalAdapter: {
      findVerificationValue: (identifier: string) => Promise<unknown>;
      createVerificationValue: (value: {
        identifier: string;
        value: string;
        expiresAt: Date;
      }) => Promise<unknown>;
      findUserById: (id: string) => Promise<AgentsSsoUser | null>;
      findUserByEmail: (email: string) => Promise<{ user?: AgentsSsoUser | null } | null>;
      createSession: (userId: string) => Promise<{ token?: string } | null>;
    };
  };
  json: (body: unknown, init?: { status?: number }) => unknown;
  redirect: (url: string) => unknown;
};

export function expectedAgentsSsoIssuer(): string {
  return (process.env.PLATFORM_APP_ORIGIN ?? "https://app.getglance.com").replace(/\/+$/, "");
}

export function agentsSsoSecret(): string {
  return process.env.AGENTS_SSO_BRIDGE_SECRET?.trim() ?? "";
}

export function isSafeAgentsSsoReturnTo(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  if (!value.startsWith("/") || value.startsWith("//")) return false;
  if (value.includes(":") || value.includes("\\")) return false;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 0x1f || c === 0x7f) return false;
  }
  return true;
}

type VerifiedAgentsSsoClaims = {
  sub: string;
  email: string;
  jti: string;
  returnTo: string;
  exp: number;
};

export async function verifyAgentsSsoToken(token: string): Promise<VerifiedAgentsSsoClaims> {
  const secret = agentsSsoSecret();
  if (!secret) {
    throw new APIError("INTERNAL_SERVER_ERROR", { body: { error: "agents_sso_not_configured" } });
  }

  const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
    issuer: expectedAgentsSsoIssuer(),
    audience: AGENTS_SSO_AUDIENCE,
    algorithms: ["HS256"],
  });

  if (
    typeof payload.sub !== "string" ||
    typeof payload.email !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.exp !== "number" ||
    !isSafeAgentsSsoReturnTo(payload.returnTo)
  ) {
    throw new APIError("UNAUTHORIZED", { body: { error: "invalid_agents_sso_claims" } });
  }

  return {
    sub: payload.sub,
    email: payload.email,
    jti: payload.jti,
    returnTo: payload.returnTo,
    exp: payload.exp,
  };
}

async function consumeAgentsSsoNonce(
  ctx: AgentsSsoEndpointContext,
  claims: VerifiedAgentsSsoClaims,
): Promise<boolean> {
  const identifier = `${AGENTS_SSO_NONCE_PREFIX}${claims.jti}`;
  const existing = await ctx.context.internalAdapter.findVerificationValue(identifier);
  if (existing) return false;
  try {
    await ctx.context.internalAdapter.createVerificationValue({
      identifier,
      value: claims.sub,
      expiresAt: new Date(claims.exp * 1000),
    });
    return true;
  } catch {
    return false;
  }
}

async function resolveAgentsSsoUser(
  ctx: AgentsSsoEndpointContext,
  claims: VerifiedAgentsSsoClaims,
): Promise<AgentsSsoUser | null> {
  const byId = await ctx.context.internalAdapter.findUserById(claims.sub);
  if (byId?.id) {
    if (byId.email && byId.email.toLowerCase() !== claims.email.toLowerCase()) {
      return null;
    }
    return byId;
  }
  const byEmail = await ctx.context.internalAdapter.findUserByEmail(claims.email);
  return byEmail?.user?.id ? byEmail.user : null;
}

export async function handleAgentsSsoConsume(ctx: AgentsSsoEndpointContext): Promise<unknown> {
  const rawToken = ctx.query.token;
  if (typeof rawToken !== "string" || rawToken.length === 0) {
    return ctx.json({ error: "missing_agents_sso_token" }, { status: 400 });
  }

  let claims: VerifiedAgentsSsoClaims;
  try {
    claims = await verifyAgentsSsoToken(rawToken);
  } catch (err) {
    if (err instanceof APIError) throw err;
    throw new APIError("UNAUTHORIZED", { body: { error: "invalid_agents_sso_token" } });
  }

  if (!(await consumeAgentsSsoNonce(ctx, claims))) {
    throw new APIError("UNAUTHORIZED", { body: { error: "agents_sso_token_replayed" } });
  }

  const user = await resolveAgentsSsoUser(ctx, claims);
  if (!user?.id) {
    throw new APIError("FORBIDDEN", { body: { error: "agents_sso_user_not_found" } });
  }

  const session = await ctx.context.internalAdapter.createSession(user.id);
  if (!session?.token) {
    throw new APIError("INTERNAL_SERVER_ERROR", { body: { error: "agents_sso_session_failed" } });
  }

  await setSessionCookie(ctx as never, { session, user } as never, false, {
    sameSite: "lax",
  });
  throw ctx.redirect(claims.returnTo);
}

export function agentsSsoBridgePlugin(): BetterAuthPlugin {
  return {
    id: "openclaw-agents-sso-bridge",
    endpoints: {
      openclawAgentsSsoConsume: createAuthEndpoint(
        "/openclaw-sso/consume",
        {
          method: "GET",
          requireHeaders: true,
        },
        async (ctx) => handleAgentsSsoConsume(ctx as unknown as AgentsSsoEndpointContext),
      ),
    },
  } as unknown as BetterAuthPlugin;
}

type AgentsSsoRedirectRequest = {
  path?: string;
  originalUrl?: string;
  method?: string;
  actor?: { source?: string };
};
type AgentsSsoRedirectResponse = {
  redirect: (status: number, url: string) => void;
};
type AgentsSsoRedirectMiddlewareOptions = {
  resolveSession?: (req: AgentsSsoRedirectRequest) => Promise<unknown>;
};

function shouldRedirectAgentsHtmlRequest(req: AgentsSsoRedirectRequest): boolean {
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;
  const path = req.path ?? "/";
  if (
    path.startsWith("/api/") ||
    path.startsWith("/assets/") ||
    path.startsWith("/openclaw-sso/") ||
    path === "/health" ||
    path === "/favicon.ico" ||
    path === "/site.webmanifest"
  ) {
    return false;
  }
  return true;
}

export function createOpenclawAgentsSsoRedirectMiddleware(opts: AgentsSsoRedirectMiddlewareOptions = {}) {
  return async (
    req: AgentsSsoRedirectRequest,
    res: AgentsSsoRedirectResponse,
    next: (err?: unknown) => void,
  ) => {
    if (!shouldRedirectAgentsHtmlRequest(req)) {
      next();
      return;
    }
    if (req.actor?.source === "session") {
      next();
      return;
    }
    if (opts.resolveSession) {
      try {
        if (await opts.resolveSession(req)) {
          next();
          return;
        }
      } catch (err) {
        next(err);
        return;
      }
    }
    const platformOrigin = expectedAgentsSsoIssuer();
    const returnTo = isSafeAgentsSsoReturnTo(req.originalUrl) ? req.originalUrl : "/";
    const launch = new URL("/api/auth/agents/launch", platformOrigin);
    launch.searchParams.set("returnTo", returnTo);
    res.redirect(307, launch.toString());
  };
}

// ---------------------------------------------------------------------------
// org_id resolution (ported VERBATIM in semantics from the 1.4 patch).
// ---------------------------------------------------------------------------

/**
 * Resolve the holder's tenant slug for the `org_id` claim (C-IDP-1 / C-IDP-3).
 *
 * `userId` is the Better Auth user id (= token `sub` =
 * company_memberships.principal_id for principal_type='user'); companies.name
 * IS the tenant slug (company↔tenant 1:1, spec-175).
 *
 * Deterministic guard: emit `org_id` ONLY when the user has EXACTLY ONE active
 * membership in an active company. Zero or more-than-one → `null` (omitted):
 * picking an arbitrary tenant for a multi-company operator would mis-route them
 * (codex-gate #984 H2). `limit 2` distinguishes "exactly one" from "more than
 * one" without scanning every membership. Any error → `null` (fail-safe — never
 * throws, since a throw would break JWT/userinfo/id_token issuance for every
 * login).
 */
export async function resolveOrgIdForUser(
  db: DbExecutor,
  userId: string | null | undefined,
): Promise<string | null> {
  if (!userId) {
    return null;
  }
  try {
    const result = await db.execute(
      sql`select co.name as org_id
            from company_memberships cm
            join companies co on co.id = cm.company_id
           where cm.principal_id = ${userId}
             and cm.principal_type = 'user'
             and cm.status = 'active'
             and co.status = 'active'
           order by cm.created_at asc, cm.id asc
           limit 2`,
    );
    const rows = extractRows(result);
    if (rows.length !== 1) {
      if (rows.length > 1) {
        console.warn(
          `[paperclip-idp] user ${userId} has multiple active memberships; ` +
            `omitting org_id (ambiguous tenant — bind explicitly)`,
        );
      }
      return null;
    }
    const slug = (rows[0] as { org_id?: unknown })?.org_id;
    return typeof slug === "string" && slug.length > 0 ? slug : null;
  } catch (error) {
    console.warn(
      "[paperclip-idp] org_id claim lookup failed; omitting org_id",
      error instanceof Error ? error.message : error,
    );
    return null;
  }
}

/** drizzle `db.execute` returns either an array or `{ rows }` depending on driver. */
function extractRows(result: unknown): unknown[] {
  if (Array.isArray(result)) {
    return result;
  }
  const rows = (result as { rows?: unknown[] } | null)?.rows;
  return Array.isArray(rows) ? rows : [];
}

// ---------------------------------------------------------------------------
// Plugin set — the single export the fork's createBetterAuthInstance consumes.
// ---------------------------------------------------------------------------

/**
 * Build the `@better-auth/oauth-provider` config (split out so the seam
 * contract test (C-IDP-4) can assert it directly).
 */
export function buildOauthProviderConfig(
  config: OpenclawIdpConfig,
  db: DbExecutor,
): OAuthOptions {
  const issuer = config.baseUrl ?? OPENCLAW_IDP_ISSUER;
  const trustedClients = getOpenclawTrustedClients();
  return {
    // C-IDP-1/3: drives JWT issuance. The connector audience + the issuer's own
    // userinfo audience are valid; anything else is rejected (no opaque
    // downgrade). Issuer baseURL is included so first-party /userinfo still works.
    validAudiences: [OPENCLAW_CONNECTOR_AUDIENCE, issuer],
    allowDynamicClientRegistration: true,
    allowUnauthenticatedClientRegistration: true,
    rateLimit: {
      register: { window: 60, max: 5 },
    },
    clientRegistrationClientSecretExpiration: "30d",
    clientRegistrationAllowedScopes: ["openid", "profile", "email", "offline_access"],
    // 1.4→1.6: trusted clients are seeded as oauthClient rows; here we mark
    // their ids immutable/trusted so the CRUD endpoints can't mutate them and
    // they are cached per-request.
    cachedTrustedClients: new Set(trustedClients.map((client) => client.clientId)),
    // Default login = /oidc-login (server-rendered in app.js): the compiled SPA
    // /login page does not follow the OAuth resume URL after sign-in. Dynamic
    // DCR clients then need a distinct consent page; pointing consentPage back
    // at login causes a post-login loop for non-trusted clients.
    loginPage: process.env.OPENCLAW_OIDC_LOGIN_PAGE ?? "/oidc-login",
    consentPage: process.env.OPENCLAW_OIDC_CONSENT_PAGE ?? "/oidc-consent",
    // 1.4→1.6: org_id now injected via customAccessTokenClaims (into the JWT
    // body AND the introspection response) instead of the 1.4
    // getAdditionalUserInfoClaim (userinfo-only). `resource` is the requested
    // audience; org_id is resolved server-side, fail-safe to omitted.
    customAccessTokenClaims: async ({ user }) => {
      const orgId = await resolveOrgIdForUser(db, user?.id);
      return orgId ? { org_id: orgId } : {};
    },
    // Mirror org_id onto the id_token + userinfo for OIDC parity (the 1.4
    // userinfo claim behavior is preserved here).
    customIdTokenClaims: async ({ user }) => {
      const orgId = await resolveOrgIdForUser(db, user?.id);
      return orgId ? { org_id: orgId } : {};
    },
    customUserInfoClaims: async ({ user }) => {
      const orgId = await resolveOrgIdForUser(db, user?.id);
      return orgId ? { org_id: orgId } : {};
    },
  };
}

// ---------------------------------------------------------------------------
// JWKS first-boot mint guard (codex-gate spec-202 HIGH-1).
//
// The jwt plugin mints a fresh Ed25519 signing key LAZILY on the first
// /jwks (or sign) call if the `jwks` table is empty. On a partial or bad
// cutover (e.g. the 1.4→1.6 migration didn't run, or ran against the wrong
// store) that silent mint rotates the signing key — breaking every already
// issued token AND claude.ai's cached JWKS. This is the exact failure that
// forced the 2026-06-19 rollback.
//
// In prod (REQUIRE_PRESEEDED_JWKS=true) we PREFLIGHT the `jwks` table BEFORE
// the plugin set is constructed (i.e. before anything can trigger a lazy
// mint) and FAIL CLOSED if the preserved key is absent. Dev/clean boots leave
// REQUIRE_PRESEEDED_JWKS unset/false and keep the stock lazy-mint behavior.
// Reuses the overlay's existing `db.execute(sql\`…\`)` mechanism (no new pg dep).
//
// Runtime note: the compiled adapter maps the better-auth `jwks` model onto the
// `auth_jwks` table (see the patch). This TS mirror keeps `jwks` for readability;
// the authoritative query is in @paperclipai+server+2026.609.0.patch.
// ---------------------------------------------------------------------------

/**
 * Fail-closed preflight: assert the `jwks` table already holds the preserved
 * signing key BEFORE any plugin can lazily mint a fresh one. No-op unless
 * `REQUIRE_PRESEEDED_JWKS=true`. When `EXPECTED_SIGNING_KID` is set, the
 * preserved key MUST match that kid; otherwise any single pre-seeded key
 * suffices. Throws (aborting boot) when the expectation is unmet — never
 * allows the IdP to come up and rotate the key.
 */
export async function assertPreseededJwks(db: DbExecutor): Promise<void> {
  if ((process.env.REQUIRE_PRESEEDED_JWKS ?? "").trim().toLowerCase() !== "true") {
    return; // dev / clean boot — preserve stock lazy-mint behavior.
  }
  const expectedKid = (process.env.EXPECTED_SIGNING_KID ?? "").trim();
  // Order by created_at desc: the better-auth jwt plugin signs with the
  // LATEST-created key (getJwksAdapter.getLatestKey) and lazily MINTS a fresh
  // one when the latest key is missing OR filtered out as expired. So ONLY the
  // latest row decides the signing kid — "expected kid present anywhere" is
  // insufficient (a newer wrong key, or an expired latest key, shadows the
  // preserved one and still triggers a rotation).
  const result = await db.execute(sql`select id, expires_at from jwks order by created_at desc`);
  const rows = extractRows(result).filter(
    (row): row is { id: string; expires_at?: unknown } =>
      typeof (row as { id?: unknown })?.id === "string" &&
      (row as { id: string }).id.length > 0,
  );
  const latest = rows[0];
  if (!latest) {
    throw new Error(
      "[paperclip-idp] REQUIRE_PRESEEDED_JWKS=true but the jwks table is EMPTY. " +
        "Refusing to boot — the jwt plugin would mint a NEW signing key and rotate " +
        "the kid, breaking every issued token + claude.ai's cached JWKS. Run the " +
        "1.4→1.6 migration (infra/paperclip/migrate-idp-1.4-to-1.6.mjs) to seed the " +
        "preserved key before boot (spec-202 cutover §4).",
    );
  }
  const latestExpiry =
    latest.expires_at == null ? null : new Date(latest.expires_at as string).getTime();
  if (latestExpiry !== null && Number.isFinite(latestExpiry) && latestExpiry <= Date.now()) {
    throw new Error(
      `[paperclip-idp] REQUIRE_PRESEEDED_JWKS=true but the latest jwks key (${latest.id}) is EXPIRED ` +
        `(expires_at=${String(latest.expires_at)}). Refusing to boot — the jwt plugin would filter it out and ` +
        "mint a NEW signing key, rotating the kid. Re-seed a non-expired preserved key before boot (spec-202 cutover §4).",
    );
  }
  if (expectedKid && latest.id !== expectedKid) {
    throw new Error(
      `[paperclip-idp] REQUIRE_PRESEEDED_JWKS=true and EXPECTED_SIGNING_KID=${expectedKid} ` +
        `but the LATEST jwks key is ${latest.id} (the jwt plugin signs with the latest-created key). Refusing to boot — ` +
        "the preserved key is not the one that will sign (wrong/partial cutover or a stray re-mint left a newer key). " +
        "Re-run the 1.4→1.6 migration against the correct store and remove any newer keys before boot (spec-202 cutover §4).",
    );
  }
}

/**
 * THE injected plugin set. Hook into upstream `createBetterAuthInstance` with:
 *
 *     plugins: [...openclawIdpPlugins(config)]
 *
 * Returns DCR guard + agents SSO bridge + `[ jwt(), magicLink(), oauthProvider(...) ]`
 * (C-IDP-4). PKCE/S256/skipConsent are carried by the seeded trusted-client rows
 * (1.6 per-client model). The EdDSA-signed JWT (jwt plugin) is what the connector
 * verifies offline (R5).
 */
export function openclawIdpPlugins(
  config: OpenclawIdpConfig,
  db: DbExecutor,
): BetterAuthPlugin[] {
  assertHostedAuthEmailConfigured();
  return [
    dcrRegistrationGuardPlugin(db),
    agentsSsoBridgePlugin(),
    // EdDSA/Ed25519 by default; JWKS served at <basePath>/jwks. Signing key
    // MUST be preserved across cutover (kid stability — C-IDP-5).
    jwt({ jwt: { issuer: config.baseUrl ?? OPENCLAW_IDP_ISSUER } }) as unknown as BetterAuthPlugin,
    magicLink({
      sendMagicLink: ({ email, url }) => {
        void sendMagicLinkEmail({ email, magicUrl: url }).catch((err) => {
          console.error(
            `[paperclip-idp] magic link email delivery failed for ${email}: ` +
              `${err instanceof Error ? err.message : String(err)}`,
          );
        });
      },
    }) as unknown as BetterAuthPlugin,
    // The config's scopes are typed `InternallySupportedScopes[]` (a subset of
    // better-auth's `Scope`, which also includes ""); the oauthProvider scope generic
    // is invariant (scopes appear in a `shouldRedirect` callback param), so cast the
    // arg to oauthProvider's exact param type. Runtime config is valid for any Scope.
    oauthProvider(
      buildOauthProviderConfig(config, db) as Parameters<typeof oauthProvider>[0],
    ) as unknown as BetterAuthPlugin,
  ];
}

// ---------------------------------------------------------------------------
// Trusted-client seeding. 1.4→1.6: the 1.4 patch passed trustedClients inline
// to oidcProvider, which seeded them implicitly. 1.6 reads clients from the
// `oauthClient` table, so the overlay must upsert the two first-party clients
// at boot (idempotent). Call once after auth init, before serving traffic.
// ---------------------------------------------------------------------------

/**
 * Idempotently upsert the trusted first-party clients into the `oauthClient`
 * table so 1.6 can resolve them. Safe to call on every boot. Env-derived
 * secrets/redirects only; no wildcards (enforced in {@link buildTrustedClient}).
 */
export async function seedOpenclawTrustedClients(db: DbExecutor): Promise<void> {
  const clients = getOpenclawTrustedClients();
  for (const client of clients) {
    const redirectUris = JSON.stringify(client.redirectUris);
    // better-auth 1.6 oauth-provider stores client secrets via `defaultHasher`
    // (SHA-256 → base64url, no padding) when the jwt plugin is enabled (the
    // default `storeClientSecret: "hashed"`), and `validateClientCredentials`
    // compares `defaultHasher(presented)` to the stored value. A raw plaintext
    // secret therefore fails the token endpoint with `invalid_client`. Seed the
    // hashed form so the first-party clients authenticate. (SHA-256/base64url is
    // byte-identical to @better-auth/utils' `createHash("SHA-256")` + base64Url.)
    const clientSecretHash = createHash("sha256").update(client.clientSecret).digest("base64url");
    await db.execute(
      sql`insert into "oauthClient"
            (id, "clientId", "clientSecret", name, type, "redirectUris",
             disabled, "requirePKCE", "skipConsent", metadata, "createdAt", "updatedAt")
          values
            (${client.clientId}, ${client.clientId}, ${clientSecretHash}, ${client.name ?? null},
             'web', ${redirectUris}::jsonb, false, true, true, '{}'::jsonb, now(), now())
          on conflict ("clientId") do update set
            "clientSecret" = excluded."clientSecret",
            "redirectUris" = excluded."redirectUris",
            "requirePKCE"  = excluded."requirePKCE",
            "skipConsent"  = excluded."skipConsent",
            disabled       = false,
            "updatedAt"    = now()`,
    );
  }
}

// ---------------------------------------------------------------------------
// Hosted auth email delivery.
//
// SECURITY: magic and reset URLs are bearer secrets. Deliver them to Resend and
// log only redacted URL metadata. Pass `sendResetPasswordRedacted` into the
// fork's `emailAndPassword.sendResetPassword`.
// ---------------------------------------------------------------------------

type ResetPasswordArgs = {
  user: { email: string };
  url?: string;
};

type ResendSendResult = {
  id?: string;
  error?: { message?: string };
};

function authEmailFromAddress(): string {
  return (
    process.env.OPENCLAW_IDP_RESEND_FROM ??
    process.env.RESEND_FROM_EMAIL ??
    "Glance <noreply@getglance.com>"
  );
}

export function assertHostedAuthEmailConfigured(): void {
  if (!process.env.RESEND_API_KEY?.trim()) {
    throw new Error("RESEND_API_KEY is required for hosted Glance login email delivery");
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function resetPasswordHtml(resetUrl: string): string {
  const safeUrl = escapeHtml(resetUrl);
  return [
    "<!doctype html>",
    '<html lang="en">',
    '<body style="font-family:Arial,sans-serif;background:#f7f8fb;margin:0;padding:32px;">',
    '<main style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;padding:32px;">',
    '<p style="color:#0d9488;font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;">Password Recovery</p>',
    '<h1 style="color:#111827;font-size:24px;line-height:1.25;margin:0 0 16px;">Reset your Glance password</h1>',
    '<p style="color:#374151;font-size:15px;line-height:1.6;">Use the secure link below to choose a new password.</p>',
    `<p><a href="${safeUrl}" style="display:inline-block;background:#14b8a6;color:#fff;padding:14px 20px;border-radius:6px;text-decoration:none;font-weight:700;">Reset Password</a></p>`,
    '<p style="color:#6b7280;font-size:13px;line-height:1.6;">If you did not request this password reset, you can safely ignore this email.</p>',
    '<p style="color:#6b7280;font-size:12px;line-height:1.6;">For help, contact hello@getglance.com.</p>',
    "</main>",
    "</body>",
    "</html>",
  ].join("");
}

function resetPasswordText(resetUrl: string): string {
  return [
    "Reset your Glance password",
    "",
    "Use the secure link below to choose a new password.",
    resetUrl,
    "",
    "If you did not request this password reset, you can safely ignore this email.",
    "For help, contact hello@getglance.com.",
  ].join("\n");
}

function magicLinkHtml(magicUrl: string): string {
  const safeUrl = escapeHtml(magicUrl);
  return [
    "<!doctype html>",
    '<html lang="en">',
    '<body style="font-family:Arial,sans-serif;background:#f7f8fb;margin:0;padding:32px;">',
    '<main style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;padding:32px;">',
    '<p style="color:#0d9488;font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;">Workspace Access</p>',
    '<h1 style="color:#111827;font-size:24px;line-height:1.25;margin:0 0 16px;">Access your Glance workspace</h1>',
    '<p style="color:#374151;font-size:15px;line-height:1.6;">Use the secure link below to continue to your workspace.</p>',
    `<p><a href="${safeUrl}" style="display:inline-block;background:#14b8a6;color:#fff;padding:14px 20px;border-radius:6px;text-decoration:none;font-weight:700;">Access Workspace</a></p>`,
    '<p style="color:#6b7280;font-size:13px;line-height:1.6;">If you did not request this link, you can safely ignore this email.</p>',
    "</main>",
    "</body>",
    "</html>",
  ].join("");
}

function magicLinkText(magicUrl: string): string {
  return [
    "Access your Glance workspace",
    "",
    "Use the secure link below to continue to your workspace.",
    magicUrl,
    "",
    "If you did not request this link, you can safely ignore this email.",
  ].join("\n");
}

function redactResetPasswordUrl(authUrl: string | undefined): string {
  if (!authUrl) return "missing";
  try {
    const url = new URL(authUrl);
    for (const key of Array.from(url.searchParams.keys())) {
      url.searchParams.set(key, "[redacted]");
    }
    if (url.hash) url.hash = "[redacted]";
    return url.toString();
  } catch {
    return "[redacted-url]";
  }
}

export async function sendResetPasswordEmail(args: {
  email: string;
  resetUrl: string;
}): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    throw new Error("RESEND_API_KEY is required for IdP password reset delivery");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: authEmailFromAddress(),
      to: args.email,
      subject: "Reset your Glance password",
      html: resetPasswordHtml(args.resetUrl),
      text: resetPasswordText(args.resetUrl),
      tags: [
        { name: "source", value: "paperclip_idp" },
        { name: "kind", value: "password_reset" },
      ],
    }),
  });

  const result = (await response.json().catch(() => ({}))) as ResendSendResult;
  if (!response.ok || result.error) {
    throw new Error(result.error?.message ?? `Resend password reset send failed: ${response.status}`);
  }

  console.info(
    `[paperclip-idp] password reset email queued for ${args.email} ` +
      `(message_id=${result.id ?? "unknown"}; reset_url=${redactResetPasswordUrl(args.resetUrl)})`,
  );
}

export async function sendMagicLinkEmail(args: {
  email: string;
  magicUrl: string;
}): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    throw new Error("RESEND_API_KEY is required for IdP magic link delivery");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: authEmailFromAddress(),
      to: args.email,
      subject: "Access your Glance workspace",
      html: magicLinkHtml(args.magicUrl),
      text: magicLinkText(args.magicUrl),
      tags: [
        { name: "source", value: "paperclip_idp" },
        { name: "kind", value: "magic_link" },
      ],
    }),
  });

  const result = (await response.json().catch(() => ({}))) as ResendSendResult;
  if (!response.ok || result.error) {
    throw new Error(result.error?.message ?? `Resend magic link send failed: ${response.status}`);
  }

  console.info(
    `[paperclip-idp] magic link email queued for ${args.email} ` +
      `(message_id=${result.id ?? "unknown"}; magic_url=${redactResetPasswordUrl(args.magicUrl)})`,
  );
}

export async function sendResetPasswordRedacted(args: ResetPasswordArgs): Promise<void> {
  if (!args.url) {
    throw new Error("Better Auth password reset callback did not provide a reset URL");
  }
  void sendResetPasswordEmail({
    email: args.user.email,
    resetUrl: args.url,
  }).catch((err) => {
    console.error(
      `[paperclip-idp] password reset email delivery failed for ${args.user.email}: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    );
  });
  console.info(
    `[paperclip-idp] password reset requested for ${args.user.email} ` +
      "(reset link withheld from logs)",
  );
}

// ---------------------------------------------------------------------------
// S2S gateway-token mint (ported verbatim from the 1.4 patch).
// ---------------------------------------------------------------------------

function timingSafeEqualStrings(presented: string, expected: string): boolean {
  const presentedBuffer = Buffer.from(String(presented));
  const expectedBuffer = Buffer.from(String(expected));
  if (presentedBuffer.length !== expectedBuffer.length) {
    // Burn a comparison anyway so length mismatch is not a timing oracle.
    timingSafeEqual(expectedBuffer, expectedBuffer);
    return false;
  }
  return timingSafeEqual(presentedBuffer, expectedBuffer);
}

const mintRateBuckets = new Map<string, { start: number; count: number }>();

function isMintRateLimited(ip: string): boolean {
  const now = Date.now();
  if (mintRateBuckets.size > MINT_RATE_LIMIT_BUCKET_CAP) {
    mintRateBuckets.clear();
  }
  const bucket = mintRateBuckets.get(ip);
  if (!bucket || now - bucket.start >= MINT_RATE_LIMIT_WINDOW_MS) {
    mintRateBuckets.set(ip, { start: now, count: 1 });
    return false;
  }
  bucket.count += 1;
  return bucket.count > MINT_RATE_LIMIT_MAX;
}

/** Express-ish req/res surface (loose to avoid an express type dependency in the overlay). */
type MintRequest = {
  get?: (header: string) => string | undefined;
  headers: Record<string, unknown>;
  socket?: { remoteAddress?: string };
  body?: { tenant_slug?: unknown };
};
type MintResponse = {
  status: (code: number) => MintResponse;
  set: (header: string, value: string) => MintResponse;
  json: (body: unknown) => void;
  headersSent: boolean;
};

async function handleGatewayTokenMint(
  auth: SignJwtCapableAuth,
  db: DbExecutor,
  req: MintRequest,
  res: MintResponse,
): Promise<void> {
  // Trust chain (A1e): caller proves possession of the S2S secret (Doppler;
  // only the admin web/ deployment holds it) → tenant_slug validated against
  // the company registry → org_id constructed HERE, server-side. The payload
  // shape is fixed; caller-supplied org_id/claims are structurally impossible.
  const expectedSecret =
    process.env.GATEWAY_MINT_S2S_SECRET ?? process.env.GATEWAY_MACHINE_MINT_SECRET ?? "";
  const presentedSecret = req.get?.("x-machine-mint-key") ?? "";
  if (!expectedSecret || !timingSafeEqualStrings(presentedSecret, expectedSecret)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  const forwardedFor = req.headers["x-forwarded-for"];
  const callerIp =
    (typeof forwardedFor === "string" ? forwardedFor.split(",")[0]?.trim() : undefined) ||
    req.socket?.remoteAddress ||
    "unknown";
  if (isMintRateLimited(callerIp)) {
    res.status(429).set("Retry-After", "60").json({ error: "rate_limited" });
    return;
  }
  const tenantSlug = typeof req.body?.tenant_slug === "string" ? req.body.tenant_slug.trim() : "";
  if (!tenantSlug || tenantSlug.length > MAX_TENANT_SLUG_LENGTH || !TENANT_SLUG_RE.test(tenantSlug)) {
    res.status(400).json({ error: "invalid_tenant_slug" });
    return;
  }
  const result = await db.execute(
    sql`select id from companies where name = ${tenantSlug} and status = 'active' limit 1`,
  );
  if (extractRows(result).length === 0) {
    res.status(404).json({ error: "unknown_tenant" });
    return;
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  // Fixed payload (gateway-jwt-claims contract): sub = machine principal,
  // org_id = validated tenant slug, aud = lumina-gateway, exp = iat + 300s.
  // iss inherited from the jwt plugin (Better Auth baseURL). 1.4→1.6: signJWT
  // is unchanged.
  const { token } = await auth.api.signJWT({
    body: {
      payload: {
        sub: `machine:corpus-bridge:${tenantSlug}`,
        org_id: tenantSlug,
        aud: GATEWAY_TOKEN_AUDIENCE,
        iat: nowSeconds,
        exp: nowSeconds + GATEWAY_TOKEN_TTL_SECONDS,
      },
    },
  });
  res.json({ jwt: token });
}

/**
 * Build the guarded `/internal/gateway-token` S2S mint handler. Wire into the
 * fork the same way the 1.4 patch did:
 *
 *     app.post("/internal/gateway-token", gatewayTokenMintHandler(auth, db));
 */
export function gatewayTokenMintHandler(
  auth: SignJwtCapableAuth,
  db: DbExecutor,
): (req: MintRequest, res: MintResponse) => void {
  return (req, res) => {
    void handleGatewayTokenMint(auth, db, req, res).catch((error) => {
      console.error("[paperclip-idp] gateway token mint failed", error);
      if (!res.headersSent) {
        res.status(500).json({ error: "internal_error" });
      }
    });
  };
}
