// ---------------------------------------------------------------------------
// Bridge JWT verification — Lumina platform → Paperclip bridge auth
// ---------------------------------------------------------------------------
// Verifies short-lived JWTs minted by the Lumina platform's
// PaperclipWorkspaceAdapter (mintBridgeJwt). These tokens authenticate
// bridge endpoint requests for user upsert, membership sync, and session
// creation during SSO handoff.
//
// Claims:
//   - company_id: Paperclip company ID the request is scoped to
//   - iss: "lumina-platform-bridge"
//   - jti: unique nonce
//   - iat/exp: issued at / expiry (60-second TTL)
//
// The shared secret is PAPERCLIP_AGENT_JWT_SECRET (same env var used by
// the agent JWT system — different issuer distinguishes the two).
// ---------------------------------------------------------------------------

import { createHmac, timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BridgeJwtClaims {
  company_id: string;
  iss: string;
  jti: string;
  iat: number;
  exp: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const JWT_ALGORITHM = "HS256";
const EXPECTED_ISSUER = "lumina-platform-bridge";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function bridgeConfig() {
  const secret = process.env.PAPERCLIP_AGENT_JWT_SECRET;
  if (!secret) return null;
  return { secret };
}

function base64UrlDecode(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

function signPayload(secret: string, signingInput: string): string {
  return createHmac("sha256", secret).update(signingInput).digest("base64url");
}

function parseJson(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function safeCompare(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify a bridge JWT from the Lumina platform.
 *
 * @returns Parsed claims if valid, null otherwise
 */
export function verifyBridgeJwt(token: string): BridgeJwtClaims | null {
  if (!token) return null;
  const config = bridgeConfig();
  if (!config) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, claimsB64, signature] = parts;

  // Verify header
  const header = parseJson(base64UrlDecode(headerB64));
  if (!header || header.alg !== JWT_ALGORITHM) return null;

  // Verify signature (timing-safe comparison)
  const signingInput = `${headerB64}.${claimsB64}`;
  const expectedSig = signPayload(config.secret, signingInput);
  if (!safeCompare(signature, expectedSig)) return null;

  // Parse and validate claims
  const claims = parseJson(base64UrlDecode(claimsB64));
  if (!claims) return null;

  const companyId =
    typeof claims.company_id === "string" ? claims.company_id : null;
  const iss = typeof claims.iss === "string" ? claims.iss : null;
  const jti = typeof claims.jti === "string" ? claims.jti : null;
  const iat = typeof claims.iat === "number" ? claims.iat : null;
  const exp = typeof claims.exp === "number" ? claims.exp : null;

  if (!companyId || !iss || !jti || !iat || !exp) return null;

  // Verify issuer
  if (iss !== EXPECTED_ISSUER) return null;

  // Verify expiry
  const now = Math.floor(Date.now() / 1000);
  if (exp < now) return null;

  return { company_id: companyId, iss, jti, iat, exp };
}
