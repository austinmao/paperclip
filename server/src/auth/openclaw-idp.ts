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
 *       · `validAudiences` — includes the connector audience
 *         `https://connector.holalumina.com/mcp`. 1.6 issues a *verifiable JWT*
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

import { jwt } from "better-auth/plugins";
// 1.4→1.6: `oidcProvider` moved out of `better-auth/plugins` core into the
// dedicated `@better-auth/oauth-provider` package and was renamed
// `oauthProvider`. It issues verifiable JWT access tokens + RFC7662
// introspection (the whole point of spec-201).
import { oauthProvider } from "@better-auth/oauth-provider";
import type { OAuthOptions, SchemaClient, Scope } from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
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
export const OPENCLAW_CONNECTOR_AUDIENCE = "https://connector.holalumina.com/mcp";

/** Issuer — matches Better Auth baseURL + OIDC discovery metadata (one `iss`). */
export const OPENCLAW_IDP_ISSUER = "https://paperclip.holalumina.com";

/** S2S gateway-token mint constants (ported verbatim from the 1.4 patch). */
const GATEWAY_TOKEN_AUDIENCE = "lumina-gateway";
const GATEWAY_TOKEN_TTL_SECONDS = 300;
const MINT_RATE_LIMIT_WINDOW_MS = 60_000;
const MINT_RATE_LIMIT_MAX = 30;
const MINT_RATE_LIMIT_BUCKET_CAP = 10_000;
const MAX_TENANT_SLUG_LENGTH = 200;
const TENANT_SLUG_RE = /^[a-z0-9][a-z0-9_-]*$/i;

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
 * overlay actually passes (every call is `db.execute(sql`...`)`); typing it that way
 * (not `unknown`) lets the fork's real `PostgresJsDatabase` satisfy this structural
 * type under strictFunctionTypes contravariance.
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
): OAuthOptions<Scope[]> {
  const issuer = config.baseUrl ?? OPENCLAW_IDP_ISSUER;
  const trustedClients = getOpenclawTrustedClients();
  return {
    // C-IDP-1/3: drives JWT issuance. The connector audience + the issuer's own
    // userinfo audience are valid; anything else is rejected (no opaque
    // downgrade). Issuer baseURL is included so first-party /userinfo still works.
    validAudiences: [OPENCLAW_CONNECTOR_AUDIENCE, issuer],
    // 1.4→1.6: trusted clients are seeded as oauthClient rows; here we mark
    // their ids immutable/trusted so the CRUD endpoints can't mutate them and
    // they are cached per-request.
    cachedTrustedClients: new Set(trustedClients.map((client) => client.clientId)),
    // Default = /oidc-login (server-rendered in app.js): the compiled SPA
    // /login page does not follow the OAuth resume URL after sign-in,
    // dead-ending the flow (1.4 live-E2E finding B6). Required option in 1.6.
    loginPage: process.env.OPENCLAW_OIDC_LOGIN_PAGE ?? "/oidc-login",
    consentPage: process.env.OPENCLAW_OIDC_CONSENT_PAGE ?? "/oidc-login",
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

/**
 * THE injected plugin set. Hook into upstream `createBetterAuthInstance` with:
 *
 *     plugins: [...openclawIdpPlugins(config)]
 *
 * Returns `[ jwt(), oauthProvider(...) ]` (C-IDP-4). PKCE/S256/skipConsent are
 * carried by the seeded trusted-client rows (1.6 per-client model). The
 * EdDSA-signed JWT (jwt plugin) is what the connector verifies offline (R5).
 */
export function openclawIdpPlugins(
  config: OpenclawIdpConfig,
  db: DbExecutor,
): BetterAuthPlugin[] {
  return [
    // EdDSA/Ed25519 by default; JWKS served at <basePath>/jwks. Signing key
    // MUST be preserved across cutover (kid stability — C-IDP-5).
    jwt({ jwt: { issuer: config.baseUrl ?? OPENCLAW_IDP_ISSUER } }) as unknown as BetterAuthPlugin,
    // The config's scopes are typed as a supported-scopes subset; oauthProvider's
    // scope generic is invariant because scopes also appear in callback params.
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
// Password-reset redaction (ported verbatim from the 1.4 patch).
//
// SECURITY: the reset URL is a bearer secret — logging it shipped
// account-takeover tokens into server logs. We log a NON-secret event only.
// Wire a real mailer here to restore self-serve delivery. Pass this into the
// fork's `emailAndPassword.sendResetPassword`.
// ---------------------------------------------------------------------------

export async function sendResetPasswordRedacted(args: { user: { email: string } }): Promise<void> {
  console.info(
    `[paperclip-idp] password reset requested for ${args.user.email} ` +
      `(reset link withheld from logs; deliver via admin tooling)`,
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
