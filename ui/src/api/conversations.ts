/**
 * @fileoverview Conversation helpers built on top of existing issue + agent APIs.
 *
 * A "conversation" is a regular Paperclip issue whose title starts with a known
 * prefix. No new backend endpoints are needed — this module provides helpers to
 * create, list, and interact with conversation-flavored issues.
 */
import type { Issue } from "@paperclipai/shared";
import { issuesApi } from "./issues";
import { agentsApi } from "./agents";

/** Title prefix used to identify conversation issues. */
export const CONVERSATION_PREFIX = "Conversation: ";

/** Returns true when the issue represents a board↔agent conversation. */
export function isConversationIssue(issue: Issue): boolean {
  return typeof issue.title === "string" && issue.title.startsWith(CONVERSATION_PREFIX);
}

/** Extract the agent display name from a conversation issue title. */
export function conversationAgentLabel(issue: Issue): string {
  if (!isConversationIssue(issue)) return "";
  return issue.title.slice(CONVERSATION_PREFIX.length);
}

/**
 * List all open conversations for a company.
 * Fetches the full issue list and filters client-side by title prefix.
 * Excludes cancelled/done conversations unless explicitly requested.
 */
export async function listConversations(
  companyId: string,
  opts?: { includeClosed?: boolean },
): Promise<Issue[]> {
  const issues = await issuesApi.list(companyId);
  return issues
    .filter((issue) => {
      if (!isConversationIssue(issue)) return false;
      if (!opts?.includeClosed) {
        const status = issue.status?.toLowerCase() ?? "";
        if (status === "done" || status === "cancelled") return false;
      }
      return true;
    })
    .sort(
      (a, b) =>
        new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(),
    );
}

/**
 * Find an existing open conversation with a specific agent, or return null.
 */
export async function findConversation(
  companyId: string,
  agentId: string,
): Promise<Issue | null> {
  const conversations = await listConversations(companyId);
  return (
    conversations.find(
      (issue) => issue.assigneeAgentId === agentId,
    ) ?? null
  );
}

/**
 * Start a new conversation with an agent. Creates a conversation-typed issue
 * assigned to the target agent with status "in_progress".
 */
export async function startConversation(
  companyId: string,
  agentId: string,
  agentName: string,
): Promise<Issue> {
  return issuesApi.create(companyId, {
    title: `${CONVERSATION_PREFIX}${agentName}`,
    description: "Board conversation with agent. Awaiting first message.",
    assigneeAgentId: agentId,
    status: "blocked",
  });
}

/** Deduplicates concurrent calls for the same agent to avoid creating duplicates. */
const ensureInFlight = new Map<string, Promise<Issue>>();

/**
 * Find or create a conversation with the given agent, then return its issue.
 * Concurrent calls for the same agent share a single in-flight Promise.
 */
export function ensureConversation(
  companyId: string,
  agentId: string,
  agentName: string,
): Promise<Issue> {
  const key = `${companyId}:${agentId}`;
  const inflight = ensureInFlight.get(key);
  if (inflight) return inflight;

  const promise = (async () => {
    const existing = await findConversation(companyId, agentId);
    if (existing) return existing;
    return startConversation(companyId, agentId, agentName);
  })();

  ensureInFlight.set(key, promise);
  promise.finally(() => ensureInFlight.delete(key));

  return promise;
}

/** Result of a sendMessage call — allows callers to detect partial failures. */
export type SendMessageResult =
  | { ok: true }
  | { ok: false; wakeupError: unknown };

/**
 * Send a message in a conversation. Posts a comment and immediately wakes the
 * assigned agent so it can respond.
 *
 * Returns a result object so callers can detect when the comment was posted
 * successfully but the agent wakeup failed (network blip, rate limit, etc.).
 */
export async function sendMessage(
  issueId: string,
  agentId: string,
  body: string,
  companyId?: string,
): Promise<SendMessageResult> {
  // Comment is the primary action — let it throw on failure.
  await issuesApi.addComment(issueId, body, true);

  // Wakeup is best-effort — capture failures so the caller can surface them.
  try {
    await agentsApi.wakeup(
      agentId,
      {
        source: "on_demand",
        triggerDetail: "manual",
        reason: "conversation_reply",
        payload: { issueId },
      },
      companyId,
    );
    return { ok: true };
  } catch (err) {
    return { ok: false, wakeupError: err };
  }
}

/**
 * Rename a conversation to a custom title. Preserves the "Conversation: " prefix
 * so the issue remains identifiable as a conversation.
 */
export async function renameConversation(
  issueId: string,
  agentName: string,
  customTopic: string,
): Promise<void> {
  const topic = customTopic.trim();
  if (!topic) return;
  await issuesApi.update(issueId, {
    title: `${CONVERSATION_PREFIX}${agentName} — ${topic}`,
  });
}
