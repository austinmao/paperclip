import type { Request, RequestHandler, Response } from "express";
import type { Socket } from "node:net";
import { sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import type { BetterAuthSessionResult } from "./better-auth.js";

type GatewayMap = Record<string, string>;

type BrandPreviewProxyOptions = {
  resolveSession?: (req: Request) => Promise<BetterAuthSessionResult | null>;
  gatewayTokenMintHandler?: RequestHandler;
};

type DbResult = unknown[] | { rows?: unknown[] };

const SAFE_RUN_ID_RE = /^[A-Za-z0-9_-]+$/;
const SAFE_PREFIX_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
const SAFE_ASSET_ROLE_RE = /^(logo|hero|palette|typography)$/;
const SAFE_ACTION_RE = /^(start|respond|peek|candidates|select|finalize|assemble)$/;

// Bound the in-process gateway-token mint. The mint handler is invoked with a
// synthetic req/res pair, so a handler that never writes a response (or returns
// a promise that resolves without responding) would leave the mint promise
// pending forever and hang the proxy request. Reject after this deadline so the
// caller fails closed (502) instead of holding the connection open.
const GATEWAY_MINT_TIMEOUT_MS = 10_000;

function extractRows(result: DbResult): unknown[] {
  if (Array.isArray(result)) return result;
  if (Array.isArray(result?.rows)) return result.rows;
  return [];
}

function parseOpenclawBrandPreviewGatewayMap(): GatewayMap {
  const defaults: GatewayMap = {
    staging: "https://gateway-lumina-staging-production.up.railway.app",
    ceremonia: "https://ceremonia.holalumina.com",
  };
  const raw = process.env.OPENCLAW_BRAND_PREVIEW_GATEWAY_MAP ?? "";
  if (!raw.trim()) return defaults;

  try {
    const parsed = JSON.parse(raw) as GatewayMap;
    return Object.fromEntries(
      Object.entries({ ...defaults, ...parsed }).map(([slug, url]) => [
        slug.toLowerCase(),
        url,
      ]),
    );
  } catch {
    const parsed: GatewayMap = {};
    for (const pair of raw.split(",")) {
      const [slug, ...urlParts] = pair.split("=");
      const url = urlParts.join("=").trim();
      if (slug?.trim() && url) {
        parsed[slug.trim().toLowerCase()] = url;
      }
    }
    return { ...defaults, ...parsed };
  }
}

function mintOpenclawGatewayToken(
  tenantSlug: string,
  req: Request,
  gatewayTokenMintHandler: RequestHandler,
): Promise<string> {
  return new Promise((resolveRaw, rejectRaw) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      rejectRaw(new Error("gateway token mint timed out"));
    }, GATEWAY_MINT_TIMEOUT_MS);
    if (typeof timer.unref === "function") timer.unref();
    const resolve = (value: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveRaw(value);
    };
    const reject = (error: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rejectRaw(error instanceof Error ? error : new Error(String(error)));
    };

    const mintKey =
      process.env.GATEWAY_MINT_S2S_SECRET ?? process.env.GATEWAY_MACHINE_MINT_SECRET ?? "";
    const mintReq = {
      get: (header: string) =>
        header.toLowerCase() === "x-machine-mint-key" ? mintKey : undefined,
      headers: req.headers ?? {},
      socket: req.socket as Socket,
      body: { tenant_slug: tenantSlug },
    } as unknown as Request;
    const mintState = {
      headersSent: false,
      statusCode: 200,
      headers: {} as Record<string, string>,
    };
    const mintRes = {
      status(code: number) {
        mintState.statusCode = code;
        return this;
      },
      set(header: string, value: string) {
        mintState.headers[header] = value;
        return this;
      },
      json(body: { jwt?: unknown }) {
        mintState.headersSent = true;
        if (mintState.statusCode >= 400) {
          reject(new Error(`gateway token mint failed: ${mintState.statusCode}`));
          return;
        }
        if (typeof body.jwt !== "string" || body.jwt.length === 0) {
          reject(new Error("gateway token mint returned no jwt"));
          return;
        }
        resolve(body.jwt);
      },
    } as unknown as Response;

    try {
      const maybePromise = gatewayTokenMintHandler(mintReq, mintRes, reject);
      void Promise.resolve(maybePromise).catch(reject);
    } catch (error) {
      reject(error);
    }
  });
}

async function resolveTenantGateway(
  db: Db,
  opts: BrandPreviewProxyOptions,
  req: Request,
  res: Response,
  companyPrefix: string,
): Promise<{ tenantSlug: string; gatewayBase: string; token: string } | null> {
  if (!opts.gatewayTokenMintHandler) {
    res.status(503).json({ error: "gateway_token_mint_unavailable" });
    return null;
  }

  const session = opts.resolveSession ? await opts.resolveSession(req) : null;
  const userId = session?.user?.id ?? session?.session?.userId;
  if (!userId) {
    res.status(401).json({ error: "unauthorized" });
    return null;
  }

  const companyResult = await db.execute(sql`
    select c.id, c.name, c.issue_prefix
    from companies c
    join company_memberships cm on cm.company_id = c.id
    where lower(c.issue_prefix) = lower(${companyPrefix})
      and c.status = 'active'
      and cm.principal_id = ${userId}
      and cm.principal_type = 'user'
      and cm.status = 'active'
    limit 1
  `);
  const company = extractRows(companyResult)[0] as
    | { name?: unknown; issue_prefix?: unknown }
    | undefined;
  // The downstream mint contract (openclaw-idp `handleGatewayTokenMint`) keys on
  // companies.name and stamps org_id = name, so the minted/wire identity MUST
  // stay the company name to preserve live tenant binding. The URL identity is
  // the immutable issue_prefix, which may intentionally differ from name (for
  // example STG -> staging), so bind the URL to issue_prefix instead of requiring
  // name and issue_prefix to be the same slug.
  const tenantSlug = typeof company?.name === "string" ? company.name : "";
  const companyIssuePrefix = typeof company?.issue_prefix === "string" ? company.issue_prefix : "";
  const gatewayBase = parseOpenclawBrandPreviewGatewayMap()[tenantSlug.toLowerCase()];
  if (!tenantSlug || !gatewayBase) {
    res.status(404).json({ error: "gateway_not_configured" });
    return null;
  }
  if (!companyIssuePrefix || companyIssuePrefix.toLowerCase() !== companyPrefix.toLowerCase()) {
    res.status(409).json({ error: "tenant_identity_mismatch" });
    return null;
  }

  const token = await mintOpenclawGatewayToken(tenantSlug, req, opts.gatewayTokenMintHandler);
  return { tenantSlug, gatewayBase, token };
}

export function createOpenclawBrandPreviewProxy(
  db: Db,
  opts: BrandPreviewProxyOptions,
): RequestHandler {
  return async (req, res) => {
    try {
      const companyPrefix = String(req.params.companyPrefix ?? "");
      const runId = String(req.params.runId ?? "");
      const assetRole = req.params.role ? String(req.params.role) : "";
      const suffix = req.path.endsWith("/state")
        ? "state"
        : assetRole
          ? `asset:${assetRole}`
          : "html";

      if (!SAFE_PREFIX_RE.test(companyPrefix) || !SAFE_RUN_ID_RE.test(runId)) {
        res.status(404).json({ error: "not_found" });
        return;
      }
      const resolved = await resolveTenantGateway(db, opts, req, res, companyPrefix);
      if (!resolved) return;

      let bridgePath = `/clawinterview/brand-preview/${encodeURIComponent(runId)}`;
      if (suffix === "state") {
        bridgePath += "/state";
      } else if (suffix.startsWith("asset:")) {
        const role = suffix.slice("asset:".length);
        if (!SAFE_ASSET_ROLE_RE.test(role)) {
          res.status(400).json({ error: "invalid_role" });
          return;
        }
        bridgePath = `/clawinterview/brand-preview-assets/${encodeURIComponent(runId)}/${role}`;
      }

      const target = new URL(bridgePath, resolved.gatewayBase.replace(/\/$/, "") + "/");
      const upstream = await fetch(target, {
        headers: {
          Authorization: `Bearer ${resolved.token}`,
          Accept: req.get("accept") ?? "*/*",
        },
      });
      const contentType = upstream.headers.get("content-type") ?? "application/octet-stream";
      const cacheControl = upstream.headers.get("cache-control") ?? "no-store";
      res.status(upstream.status);
      res.set("Content-Type", contentType);
      res.set("Cache-Control", cacheControl);
      if (contentType.includes("text/html")) {
        const html = await upstream.text();
        res.send(
          html
            .replaceAll("'/clawinterview/", `'/${companyPrefix}/clawinterview/`)
            .replaceAll("\"/clawinterview/", `"/${companyPrefix}/clawinterview/`),
        );
        return;
      }
      res.send(Buffer.from(await upstream.arrayBuffer()));
    } catch (error) {
      console.error("[paperclip-idp] brand preview proxy failed", error);
      if (!res.headersSent) {
        res.status(502).json({ error: "brand_preview_proxy_failed" });
      }
    }
  };
}

export function createOpenclawBrandInterviewActionProxy(
  db: Db,
  opts: BrandPreviewProxyOptions,
): RequestHandler {
  return async (req, res) => {
    try {
      const companyPrefix = String(req.params.companyPrefix ?? "");
      const action = String(req.params.action ?? "");

      if (!SAFE_PREFIX_RE.test(companyPrefix) || !SAFE_ACTION_RE.test(action)) {
        res.status(404).json({ error: "not_found" });
        return;
      }

      const resolved = await resolveTenantGateway(db, opts, req, res, companyPrefix);
      if (!resolved) return;

      const body = req.body && typeof req.body === "object" ? req.body : {};
      const target = new URL(
        `/clawinterview/${encodeURIComponent(action)}`,
        resolved.gatewayBase.replace(/\/$/, "") + "/",
      );
      const upstream = await fetch(target, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${resolved.token}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ...body, interview_type: "brand" }),
      });
      const contentType = upstream.headers.get("content-type") ?? "application/json";
      res.status(upstream.status);
      res.set("Content-Type", contentType);
      res.set("Cache-Control", "no-store");
      res.send(Buffer.from(await upstream.arrayBuffer()));
    } catch (error) {
      console.error("[paperclip-idp] brand interview action proxy failed", error);
      if (!res.headersSent) {
        res.status(502).json({ error: "brand_interview_action_proxy_failed" });
      }
    }
  };
}
