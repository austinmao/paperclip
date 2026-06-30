export {};

import type { AgentApiKeyScope } from "@paperclipai/shared";

// Extracted to a named type (b41e1d77b) so it can augment BOTH
// `express-serve-static-core`'s `Request` (some call sites import this
// directly) and the global `Express` namespace `Request` below — kept in
// sync with upstream's fuller actor shape (onBehalfOfMemberships/keyScope/
// onBehalfOfUserId, added independently upstream).
type RequestActor = {
  type: "board" | "agent" | "none";
  userId?: string;
  userName?: string | null;
  userEmail?: string | null;
  agentId?: string;
  companyId?: string;
  companyIds?: string[];
  memberships?: Array<{
    companyId: string;
    membershipRole?: string | null;
    status?: string;
  }>;
  onBehalfOfMemberships?: Array<{
    companyId: string;
    membershipRole?: string | null;
    status?: string;
  }>;
  isInstanceAdmin?: boolean;
  keyId?: string;
  keyScope?: AgentApiKeyScope;
  runId?: string;
  onBehalfOfUserId?: string | null;
  source?: "local_implicit" | "session" | "board_key" | "agent_key" | "agent_jwt" | "cloud_tenant" | "none";
};

declare module "express-serve-static-core" {
  interface Request {
    actor: RequestActor;
  }
}

declare global {
  namespace Express {
    interface Request {
      actor: RequestActor;
    }
  }
}
