/**
 * Seed Lumina OS agents on first boot.
 *
 * Reads config/paperclip-agents.yaml and registers any agents not already
 * present in the first company. Idempotent: safe to run on every restart.
 * Uses the agentService directly (no HTTP, no auth needed).
 *
 * Called from index.ts after the server is listening and migrations are done.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { eq } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { agents, companies } from "@paperclipai/db";
import { parse as parseYaml } from "yaml";
import { agentService } from "./services/index.js";
import { logger } from "./middleware/logger.js";

// ── Types ───────────────────────────────────────────────────────────────────

interface RosterEntry {
	agentId: string;
	name: string;
	role: string;
	title: string;
	reportsTo: string | null;
	heartbeatEnabled: boolean;
	budgetMonthlyCents: number;
	type: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

// The YAML file is bundled into the Docker image via COPY in the Dockerfile.
// At runtime, resolve relative to the server working directory.
const ROSTER_PATHS = [
	resolve(process.cwd(), "config/paperclip-agents.yaml"),
	resolve(process.cwd(), "../config/paperclip-agents.yaml"),
	resolve(process.cwd(), "../../config/paperclip-agents.yaml"),
];

// Gateway URL: prefer env var, fall back to Railway internal DNS.
const GATEWAY_WS_URL =
	process.env.OPENCLAW_GATEWAY_URL ?? "ws://openclaw.railway.internal:18789";

// ── Main ────────────────────────────────────────────────────────────────────

export async function seedLuminaAgents(db: Db): Promise<void> {
	// Only seed when LUMINA_SEED_AGENTS env var is set (opt-in per instance)
	if (!process.env.LUMINA_SEED_AGENTS) {
		return;
	}

	const rosterPath = ROSTER_PATHS.find((p) => {
		try {
			readFileSync(p);
			return true;
		} catch {
			return false;
		}
	});

	if (!rosterPath) {
		logger.warn(
			{ paths: ROSTER_PATHS },
			"[seed] paperclip-agents.yaml not found, skipping agent seeding",
		);
		return;
	}

	let roster: RosterEntry[];
	let gatewayUrl = GATEWAY_WS_URL;
	try {
		const raw = readFileSync(rosterPath, "utf-8");
		const parsed = parseYaml(raw) as { agents?: unknown[]; gateway_url?: string };
		const rawEntries = parsed?.agents ?? [];

		// Use gateway_url from YAML if present (overrides env/default)
		if (parsed.gateway_url) {
			gatewayUrl = parsed.gateway_url;
		}

		// Validate each entry has required fields
		roster = rawEntries
			.filter((entry): entry is Record<string, unknown> =>
				typeof entry === "object" && entry !== null,
			)
			.filter((entry) => {
				if (!entry.agentId || !entry.name) {
					logger.warn({ entry }, "[seed] Skipping roster entry missing agentId or name");
					return false;
				}
				return true;
			})
			.map((entry) => ({
				agentId: String(entry.agentId),
				name: String(entry.name),
				role: String(entry.role ?? "engineer"),
				title: String(entry.title ?? entry.name),
				reportsTo: entry.reportsTo ? String(entry.reportsTo) : null,
				heartbeatEnabled: Boolean(entry.heartbeatEnabled),
				budgetMonthlyCents: Number(entry.budgetMonthlyCents) || 5000,
				type: String(entry.type ?? "proactive"),
			}));
	} catch (err) {
		logger.error({ err, path: rosterPath }, "[seed] Failed to parse agent roster YAML");
		return;
	}

	if (roster.length === 0) {
		logger.info("[seed] Agent roster is empty, nothing to seed");
		return;
	}

	// Find the first company (created by bridge upsert-user during onboarding)
	const companyRows = await db
		.select({ id: companies.id, name: companies.name })
		.from(companies)
		.limit(1);

	if (companyRows.length === 0) {
		logger.info("[seed] No company exists yet, deferring agent seeding to next restart");
		return;
	}

	const companyId = companyRows[0].id;
	const svc = agentService(db);

	// List existing agents to skip duplicates
	const existingRows = await db
		.select({ name: agents.name })
		.from(agents)
		.where(eq(agents.companyId, companyId));
	const existingNames = new Set(existingRows.map((r) => r.name));

	const pending = roster.filter((entry) => !existingNames.has(entry.name));

	if (pending.length === 0) {
		logger.info(
			{ total: roster.length, existing: existingNames.size },
			"[seed] All agents already registered, nothing to seed",
		);
		return;
	}

	logger.info(
		{ total: roster.length, existing: existingNames.size, toSeed: pending.length },
		"[seed] Seeding Lumina OS agents",
	);

	let seeded = 0;
	let failed = 0;

	for (const entry of pending) {
		try {
			await svc.create(companyId, {
				name: entry.name,
				role: entry.role,
				title: entry.title,
				adapterType: "openclaw_gateway",
				adapterConfig: {
					url: gatewayUrl,
					agentId: entry.agentId,
				},
				budgetMonthlyCents: entry.budgetMonthlyCents,
				...(entry.reportsTo ? { reportsTo: entry.reportsTo } : {}),
			});
			seeded++;
		} catch (err) {
			failed++;
			logger.error(
				{ err, agent: entry.name },
				`[seed] Failed to seed agent "${entry.name}"`,
			);
		}
	}

	logger.info(
		{ seeded, failed, total: roster.length },
		"[seed] Agent seeding complete",
	);
}
