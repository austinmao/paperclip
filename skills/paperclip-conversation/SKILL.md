---
name: paperclip-conversation
description: >
  Conversation mode for board-agent chat. PRIORITY: Check this skill BEFORE
  running the normal heartbeat procedure. When wake reason is conversation_reply
  or when the assigned issue title starts with "Conversation:", skip the standard
  heartbeat entirely and follow this lightweight conversational flow instead.
---

# Conversation Mode — CHECK FIRST

**IMPORTANT: Check for conversation mode BEFORE starting the normal heartbeat
procedure.** If you detect conversation mode, follow ONLY this skill. Do not
run any part of the standard heartbeat (no inbox check, no assignment scan,
no checkout, no task prioritization).

## Detecting conversation mode

At the very start of your run, before anything else, check:

1. Does `PAPERCLIP_WAKE_REASON` equal `conversation_reply`?
2. OR does the issue from `PAPERCLIP_TASK_ID` have a title starting with `Conversation:`?
3. OR were you woken with `PAPERCLIP_WAKE_REASON` equal `issue_assigned` and the issue title starts with `Conversation:`?

If ANY of these is true → follow this skill. Do NOT run the normal heartbeat.

## Case 1: New conversation with no user messages

If the conversation issue has **zero comments from non-agent users** (only your
own comments or no comments at all), the board has not sent a message yet.

Do this and exit immediately:

1. `GET /api/agents/me` for identity
2. `GET /api/issues/{issueId}/comments` to check for user messages
3. If no user messages exist, post a brief greeting:
```
   POST /api/issues/{issueId}/comments
   Headers: X-Paperclip-Run-Id: $PAPERCLIP_RUN_ID
   { "body": "Ready. Send your message whenever you're ready." }
```
4. Set status to blocked:
```
   PATCH /api/issues/{issueId}
   Headers: X-Paperclip-Run-Id: $PAPERCLIP_RUN_ID
   { "status": "blocked" }
```
5. Exit. Do not fetch assignments, do not check inbox, do not do anything else.

## Case 2: Board sent a message (conversation_reply)

1. **Identity**: `GET /api/agents/me` if not in context.

2. **Read the message**: Fetch the triggering comment:
   - If `PAPERCLIP_WAKE_COMMENT_ID` is set: `GET /api/issues/{issueId}/comments/{commentId}`
   - Otherwise: `GET /api/issues/{issueId}/comments?order=desc&limit=5` and find the latest non-agent comment.

3. **Context** (only if needed): Fetch only what the question requires.
   Do not reload the full assignment list or run inbox checks.

4. **Respond**: Post a comment responding to what the board said.
```
   POST /api/issues/{issueId}/comments
   Headers: X-Paperclip-Run-Id: $PAPERCLIP_RUN_ID
   { "body": "Your response" }
```
   Write naturally and conversationally. No status reports unless asked.

5. **Auto-title** (first response only): If the title is still `Conversation: {YourName}`
   (no ` — ` separator), generate a 3-6 word topic and update:
```
   PATCH /api/issues/{issueId}
   Headers: X-Paperclip-Run-Id: $PAPERCLIP_RUN_ID
   { "title": "Conversation: {YourName} — {Short Topic}" }
```

6. **Status**: Set back to blocked and exit.
```
   PATCH /api/issues/{issueId}
   Headers: X-Paperclip-Run-Id: $PAPERCLIP_RUN_ID
   { "status": "blocked" }
```

7. **Actions**: If the board asks you to do something concrete (hire, create task,
   set up project, make a plan), do it using the normal Paperclip APIs and explain
   what you did in your response. Link to created issues/approvals/agents.

## Rules

- Do NOT run any part of the standard heartbeat procedure
- Do NOT check out the conversation issue
- Do NOT scan your inbox or assignments
- Do NOT mark the conversation done or in_progress
- Do NOT look for other work — just respond and exit
- Do NOT repeat full company state every message
- Keep responses conversational, not report-style
- Conversations stay blocked between messages — the board wakes you when ready
