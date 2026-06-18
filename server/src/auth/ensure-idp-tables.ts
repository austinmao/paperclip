/**
 * ensure-idp-tables.ts — boot-time DDL for the 5 better-auth 1.6 IdP tables that
 * are NOT shipped in `@paperclipai/db`.
 * ===========================================================================
 *
 * spec-201 (better-auth 1.4 → 1.6). The 1.4 patch-package overlay created
 * CUSTOM `auth_*` tables because 1.4's models weren't in @paperclipai/db. For
 * 1.6 we instead create the STOCK 1.6 oauth-provider + jwt tables so the plugin
 * set (`jwt()` + `oauthProvider(...)` from `openclaw-idp.ts`) resolves them.
 *
 * The AUTHORITATIVE column list is the @better-auth/cli-generated reference at
 * `infra/paperclip/overlay/idp-schema-1.6.reference.sql` (SQLite dialect). This
 * module is the Postgres translation:
 *   - `text` → `text`
 *   - boolean-ish `integer` (disabled, skipConsent, enableEndSession, public,
 *     requirePKCE) → `boolean`
 *   - `date` → `timestamptz`
 *   - **`string[]` / `json` fields → `jsonb`** (NOT `text`). The CLI reference is
 *     SQLite, where a `string[]` column is `text` because SQLite has no JSON
 *     type. On Postgres better-auth's own migration generator emits a JSON column
 *     for every `string[]`/`json` field (`db/get-migration.mjs`: a `string[]`
 *     column's data type "includes json"), and the oauth-provider reads these
 *     back as JS arrays (`client.redirectUris.find(...)`). A plain `text` column
 *     returns a string → `redirectUris?.find is not a function` at
 *     `authorizeEndpoint`. So `redirectUris`, `postLogoutRedirectUris`,
 *     `grantTypes`, `responseTypes`, `contacts`, every `scopes`, and `metadata`
 *     MUST be `jsonb` so the drizzle adapter round-trips real arrays/objects.
 *   - quoted camelCase identifiers preserved EXACTLY ("clientId", "redirectUris",
 *     "requirePKCE", etc.)
 *   - PRIMARY KEY / UNIQUE / FK constraints preserved.
 *
 * The 4 better-auth core tables (user/session/account/verification) are created
 * by Paperclip's own onboard/migration path, so the FK targets (`"user"`,
 * `"session"`) already exist when this runs. We only create the 5 IdP-only
 * tables, ordered so FK targets exist first: jwks → oauthClient →
 * oauthRefreshToken → oauthAccessToken → oauthConsent.
 *
 * Idempotent: every statement is `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF
 * NOT EXISTS`, safe to call on every boot.
 */

import { sql } from "drizzle-orm";
import { pgTable, text, timestamp, boolean, jsonb } from "drizzle-orm/pg-core";

/** A `db.execute`-capable handle (drizzle). Loose to avoid coupling to the fork's exact type. */
type DbExecutor = {
  execute: (query: unknown) => Promise<unknown>;
};

const MANAGED_JSONB_COLUMNS = [
  { table: "oauthClient", column: "redirectUris" },
  { table: "oauthClient", column: "postLogoutRedirectUris" },
  { table: "oauthClient", column: "grantTypes" },
  { table: "oauthClient", column: "responseTypes" },
  { table: "oauthClient", column: "contacts" },
  { table: "oauthClient", column: "scopes" },
  { table: "oauthClient", column: "metadata" },
  { table: "oauthRefreshToken", column: "scopes" },
  { table: "oauthAccessToken", column: "scopes" },
  { table: "oauthConsent", column: "scopes" },
] as const;

// ---------------------------------------------------------------------------
// Drizzle table definitions for the 5 IdP-only tables.
//
// better-auth's drizzleAdapter is configured in `better-auth.ts` with an
// EXPLICIT `schema` object. When a schema is passed explicitly, the adapter
// resolves EVERY model the plugins touch (jwt → "jwks"; oauthProvider →
// "oauthClient"/"oauthAccessToken"/"oauthRefreshToken"/"oauthConsent") from that
// object — a missing model throws `The model "<name>" was not found in the
// schema object`. So we export drizzle table objects whose JS keys match the
// better-auth field names and whose DB column names match the camelCase columns
// created by {@link ensureIdpAuthTables} above (the better-auth 1.6 default
// column casing — NOT snake_case, unlike Paperclip's own auth tables).
//
// `string[]`/`json` fields are `jsonb` (see the header note): the oauth-provider
// reads them as arrays/objects, so a plain `text` column breaks the authorize
// flow. drizzle returns a parsed JS value from a `jsonb` column.
//
// The drizzle adapter keys models by the JS property name used in the schema
// object (see `idpAuthSchema`), so the const names here are the model names.
// ---------------------------------------------------------------------------

export const jwks = pgTable("jwks", {
  id: text("id").primaryKey(),
  publicKey: text("publicKey").notNull(),
  privateKey: text("privateKey").notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  expiresAt: timestamp("expiresAt", { withTimezone: true }),
});

export const oauthClient = pgTable("oauthClient", {
  id: text("id").primaryKey(),
  clientId: text("clientId").notNull(),
  clientSecret: text("clientSecret"),
  disabled: boolean("disabled"),
  skipConsent: boolean("skipConsent"),
  enableEndSession: boolean("enableEndSession"),
  subjectType: text("subjectType"),
  scopes: jsonb("scopes"),
  userId: text("userId"),
  createdAt: timestamp("createdAt", { withTimezone: true }),
  updatedAt: timestamp("updatedAt", { withTimezone: true }),
  name: text("name"),
  uri: text("uri"),
  icon: text("icon"),
  contacts: jsonb("contacts"),
  tos: text("tos"),
  policy: text("policy"),
  softwareId: text("softwareId"),
  softwareVersion: text("softwareVersion"),
  softwareStatement: text("softwareStatement"),
  redirectUris: jsonb("redirectUris").notNull(),
  postLogoutRedirectUris: jsonb("postLogoutRedirectUris"),
  tokenEndpointAuthMethod: text("tokenEndpointAuthMethod"),
  grantTypes: jsonb("grantTypes"),
  responseTypes: jsonb("responseTypes"),
  public: boolean("public"),
  type: text("type"),
  requirePKCE: boolean("requirePKCE"),
  referenceId: text("referenceId"),
  metadata: jsonb("metadata"),
});

export const oauthRefreshToken = pgTable("oauthRefreshToken", {
  id: text("id").primaryKey(),
  token: text("token").notNull(),
  clientId: text("clientId").notNull(),
  sessionId: text("sessionId"),
  userId: text("userId").notNull(),
  referenceId: text("referenceId"),
  expiresAt: timestamp("expiresAt", { withTimezone: true }).notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  revoked: timestamp("revoked", { withTimezone: true }),
  authTime: timestamp("authTime", { withTimezone: true }),
  scopes: jsonb("scopes").notNull(),
});

export const oauthAccessToken = pgTable("oauthAccessToken", {
  id: text("id").primaryKey(),
  token: text("token").notNull(),
  clientId: text("clientId").notNull(),
  sessionId: text("sessionId"),
  userId: text("userId"),
  referenceId: text("referenceId"),
  refreshId: text("refreshId"),
  expiresAt: timestamp("expiresAt", { withTimezone: true }).notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  scopes: jsonb("scopes").notNull(),
});

export const oauthConsent = pgTable("oauthConsent", {
  id: text("id").primaryKey(),
  clientId: text("clientId").notNull(),
  userId: text("userId"),
  referenceId: text("referenceId"),
  scopes: jsonb("scopes").notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updatedAt", { withTimezone: true }).notNull(),
});

/**
 * The 5 IdP-only drizzle models, keyed by their better-auth model names. Spread
 * into the drizzleAdapter `schema` in `better-auth.ts` alongside the Paperclip
 * core auth tables so the jwt + oauthProvider plugins resolve their tables.
 */
export const idpAuthSchema = {
  jwks,
  oauthClient,
  oauthAccessToken,
  oauthRefreshToken,
  oauthConsent,
} as const;

/**
 * Create the 5 better-auth 1.6 IdP-only tables (jwks, oauthClient,
 * oauthRefreshToken, oauthAccessToken, oauthConsent) plus their indexes if they
 * do not already exist. Must run AFTER the better-auth core tables (user,
 * session) exist (Paperclip onboard) and BEFORE the auth instance serves
 * traffic. Idempotent.
 */
export async function ensureIdpAuthTables(db: DbExecutor): Promise<void> {
  // 1. jwks — no FK; must exist before signing keys are minted.
  await db.execute(sql`
    create table if not exists "jwks" (
      "id" text not null primary key,
      "publicKey" text not null,
      "privateKey" text not null,
      "createdAt" timestamptz not null,
      "expiresAt" timestamptz
    )
  `);

  // 2. oauthClient — FK to "user"; referenced by the token/consent tables.
  //    string[]/json columns are jsonb (see header note) so the oauth-provider
  //    reads them back as arrays/objects, not strings.
  await db.execute(sql`
    create table if not exists "oauthClient" (
      "id" text not null primary key,
      "clientId" text not null unique,
      "clientSecret" text,
      "disabled" boolean,
      "skipConsent" boolean,
      "enableEndSession" boolean,
      "subjectType" text,
      "scopes" jsonb,
      "userId" text references "user" ("id") on delete cascade,
      "createdAt" timestamptz,
      "updatedAt" timestamptz,
      "name" text,
      "uri" text,
      "icon" text,
      "contacts" jsonb,
      "tos" text,
      "policy" text,
      "softwareId" text,
      "softwareVersion" text,
      "softwareStatement" text,
      "redirectUris" jsonb not null,
      "postLogoutRedirectUris" jsonb,
      "tokenEndpointAuthMethod" text,
      "grantTypes" jsonb,
      "responseTypes" jsonb,
      "public" boolean,
      "type" text,
      "requirePKCE" boolean,
      "referenceId" text,
      "metadata" jsonb
    )
  `);

  // 3. oauthRefreshToken — FKs to oauthClient, session, user; referenced by
  //    oauthAccessToken.refreshId, so it must exist before oauthAccessToken.
  await db.execute(sql`
    create table if not exists "oauthRefreshToken" (
      "id" text not null primary key,
      "token" text not null unique,
      "clientId" text not null references "oauthClient" ("clientId") on delete cascade,
      "sessionId" text references "session" ("id") on delete set null,
      "userId" text not null references "user" ("id") on delete cascade,
      "referenceId" text,
      "expiresAt" timestamptz not null,
      "createdAt" timestamptz not null,
      "revoked" timestamptz,
      "authTime" timestamptz,
      "scopes" jsonb not null
    )
  `);

  // 4. oauthAccessToken — FKs to oauthClient, session, user, oauthRefreshToken.
  await db.execute(sql`
    create table if not exists "oauthAccessToken" (
      "id" text not null primary key,
      "token" text not null unique,
      "clientId" text not null references "oauthClient" ("clientId") on delete cascade,
      "sessionId" text references "session" ("id") on delete set null,
      "userId" text references "user" ("id") on delete cascade,
      "referenceId" text,
      "refreshId" text references "oauthRefreshToken" ("id") on delete cascade,
      "expiresAt" timestamptz not null,
      "createdAt" timestamptz not null,
      "scopes" jsonb not null
    )
  `);

  // 5. oauthConsent — FKs to oauthClient, user.
  await db.execute(sql`
    create table if not exists "oauthConsent" (
      "id" text not null primary key,
      "clientId" text not null references "oauthClient" ("clientId") on delete cascade,
      "userId" text references "user" ("id") on delete cascade,
      "referenceId" text,
      "scopes" jsonb not null,
      "createdAt" timestamptz not null,
      "updatedAt" timestamptz not null
    )
  `);

  // HIGH-4: IF NOT EXISTS preserves older text columns; reconcile them to jsonb.
  await reconcileManagedJsonbColumns(db);

  // Secondary indexes (match the reference schema).
  await db.execute(sql`create index if not exists "oauthClient_userId_idx" on "oauthClient" ("userId")`);
  await db.execute(sql`create index if not exists "oauthRefreshToken_clientId_idx" on "oauthRefreshToken" ("clientId")`);
  await db.execute(sql`create index if not exists "oauthRefreshToken_sessionId_idx" on "oauthRefreshToken" ("sessionId")`);
  await db.execute(sql`create index if not exists "oauthRefreshToken_userId_idx" on "oauthRefreshToken" ("userId")`);
  await db.execute(sql`create index if not exists "oauthAccessToken_clientId_idx" on "oauthAccessToken" ("clientId")`);
  await db.execute(sql`create index if not exists "oauthAccessToken_sessionId_idx" on "oauthAccessToken" ("sessionId")`);
  await db.execute(sql`create index if not exists "oauthAccessToken_userId_idx" on "oauthAccessToken" ("userId")`);
  await db.execute(sql`create index if not exists "oauthAccessToken_refreshId_idx" on "oauthAccessToken" ("refreshId")`);
  await db.execute(sql`create index if not exists "oauthConsent_clientId_idx" on "oauthConsent" ("clientId")`);
  await db.execute(sql`create index if not exists "oauthConsent_userId_idx" on "oauthConsent" ("userId")`);
}

async function reconcileManagedJsonbColumns(db: DbExecutor): Promise<void> {
  for (const { table, column } of MANAGED_JSONB_COLUMNS) {
    const result = await db.execute(sql`
      select data_type
        from information_schema.columns
       where table_schema = current_schema()
         and table_name = ${table}
         and column_name = ${column}
       limit 1
    `);
    const dataType = (extractRows(result)[0] as { data_type?: unknown } | undefined)?.data_type;
    if (dataType === "jsonb" || typeof dataType !== "string") {
      continue;
    }
    try {
      await db.execute(sql`
        alter table ${sql.raw(quotePgIdentifier(table))}
        alter column ${sql.raw(quotePgIdentifier(column))}
        type jsonb
        using ${sql.raw(quotePgIdentifier(column))}::jsonb
      `);
    } catch (error) {
      const cause = error instanceof Error ? error.message : String(error);
      throw new Error(
        `[paperclip-idp] HIGH-4: failed to convert "${table}"."${column}" from ${dataType} to jsonb. ` +
          `Repair invalid JSON values or recreate the IdP table before booting. Cause: ${cause}`,
      );
    }
  }
}

function extractRows(result: unknown): unknown[] {
  if (Array.isArray(result)) {
    return result;
  }
  const rows = (result as { rows?: unknown[] } | null)?.rows;
  return Array.isArray(rows) ? rows : [];
}

function quotePgIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}
