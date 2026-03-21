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

/**
 * Find or create a conversation with the given agent, then return its issue ID.
 */
export async function ensureConversation(
  companyId: string,
  agentId: string,
  agentName: string,
): Promise<Issue> {
  const existing = await findConversation(companyId, agentId);
  if (existing) return existing;
  return startConversation(companyId, agentId, agentName);
}

/**
 * Send a message in a conversation. Posts a comment and immediately wakes the
 * assigned agent so it can respond.
 */
export async function sendMessage(
  issueId: string,
  agentId: string,
  body: string,
  companyId?: string,
): Promise<void> {
  await issuesApi.addComment(issueId, body, true);
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
}

/**
 * Update the conversation title with a topic derived from the message.
 * Only auto-titles if the current title is the default "Conversation: {name}" format.
 */
export async function autoTitleConversation(
  issueId: string,
  body: string,
  currentTitle: string,
): Promise<void> {
  // Only auto-title if still using the default title
  if (!currentTitle.startsWith(CONVERSATION_PREFIX)) return;
  const agentName = currentTitle.slice(CONVERSATION_PREFIX.length);
  const topic = body.replace(/\n/g, " ").trim().slice(0, 40);
  if (!topic) return;
  const suffix = body.trim().length > 40 ? "..." : "";
  await issuesApi.update(issueId, {
    title: `${CONVERSATION_PREFIX}${agentName} — ${topic}${suffix}`,
  });
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