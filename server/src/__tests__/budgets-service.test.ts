import { beforeEach, describe, expect, it, vi } from "vitest";
import { budgetService } from "../services/budgets.ts";

const mockLogActivity = vi.hoisted(() => vi.fn());

vi.mock("../services/activity-log.js", () => ({
  logActivity: mockLogActivity,
}));

type SelectResult = unknown[];

function createDbStub(selectResults: SelectResult[]) {
  const pendingSelects = [...selectResults];
  const runSelect = () => pendingSelects.shift() ?? [];
  const selectWhere = vi.fn(() => query);
  const selectThen = vi.fn((resolve: (value: unknown[]) => unknown) => Promise.resolve(resolve(runSelect() as unknown[])));
  const selectOrderBy = vi.fn(async () => runSelect());
  const query = {
    where: selectWhere,
    then: selectThen,
    orderBy: selectOrderBy,
  };
  const selectFrom = vi.fn(() => query);
  const select = vi.fn(() => ({
    from: selectFrom,
  }));

  const insertValues = vi.fn();
  const insertReturning = vi.fn(async () => pendingInserts.shift() ?? []);
  const insert = vi.fn(() => ({
    values: insertValues.mockImplementation(() => ({
      returning: insertReturning,
    })),
  }));

  const updateSet = vi.fn();
  const updateWhere = vi.fn(async () => pendingUpdates.shift() ?? []);
  const update = vi.fn(() => ({
    set: updateSet.mockImplementation(() => ({
      where: updateWhere,
    })),
  }));

  const pendingInserts: unknown[][] = [];
  const pendingUpdates: unknown[][] = [];

  return {
    db: {
      select,
      insert,
      update,
    },
    queueInsert: (rows: unknown[]) => {
      pendingInserts.push(rows);
    },
    queueUpdate: (rows: unknown[] = []) => {
      pendingUpdates.push(rows);
    },
    selectWhere,
    insertValues,
    updateSet,
  };
}

describe("budgetService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("creates a hard-stop incident and pauses an agent when spend exceeds a budget", async () => {
    const policy = {
      id: "policy-1",
      companyId: "company-1",
      scopeType: "agent",
      scopeId: "agent-1",
      metric: "billed_cents",
      windowKind: "calendar_month_utc",
      amount: 100,
      warnPercent: 80,
      hardStopEnabled: true,
      notifyEnabled: false,
      isActive: true,
    };

    const dbStub = createDbStub([
      [policy],
      [{ total: 150 }],
      [],
      [{
        companyId: "company-1",
        name: "Budget Agent",
        status: "running",
        pauseReason: null,
      }],
    ]);

    dbStub.queueInsert([{
      id: "approval-1",
      companyId: "company-1",
      status: "pending",
    }]);
    dbStub.queueInsert([{
      id: "incident-1",
      companyId: "company-1",
      policyId: "policy-1",
      approvalId: "approval-1",
    }]);
    dbStub.queueUpdate([]);
    const cancelWorkForScope = vi.fn().mockResolvedValue(undefined);

    const service = budgetService(dbStub.db as any, { cancelWorkForScope });
    await service.evaluateCostEvent({
      companyId: "company-1",
      agentId: "agent-1",
      projectId: null,
    } as any);

    expect(dbStub.insertValues).toHaveBeenCalledWith(
      expect.objectContaining({
        companyId: "company-1",
        type: "budget_override_required",
        status: "pending",
      }),
    );
    expect(dbStub.insertValues).toHaveBeenCalledWith(
      expect.objectContaining({
        companyId: "company-1",
        policyId: "policy-1",
        thresholdType: "hard",
        amountLimit: 100,
        amountObserved: 150,
        approvalId: "approval-1",
      }),
    );
    expect(dbStub.updateSet).toHaveBeenCalledWith(
      expect.objectContaining({
        status: "paused",
        pauseReason: "budget",
        pausedAt: expect.any(Date),
      }),
    );
    expect(mockLogActivity).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        action: "budget.hard_threshold_crossed",
        entityId: "incident-1",
      }),
    );
    expect(cancelWorkForScope).toHaveBeenCalledWith({
      companyId: "company-1",
      scopeType: "agent",
      scopeId: "agent-1",
    });
  });

  it("blocks new work when an agent hard-stop remains exceeded even if the agent is not paused yet", async () => {
    const agentPolicy = {
      id: "policy-agent-1",
      companyId: "company-1",
      scopeType: "agent",
      scopeId: "agent-1",
      metric: "billed_cents",
      windowKind: "calendar_month_utc",
      amount: 100,
      warnPercent: 80,
      hardStopEnabled: true,
      notifyEnabled: true,
      isActive: true,
    };

    const dbStub = createDbStub([
      [{
        status: "running",
        pauseReason: null,
        companyId: "company-1",
        name: "Budget Agent",
      }],
      [{
        status: "active",
        name: "Paperclip",
      }],
      [],
      [agentPolicy],
      [{ total: 120 }],
    ]);

    const service = budgetService(dbStub.db as any);
    const block = await service.getInvocationBlock("company-1", "agent-1");

    expect(block).toEqual({
      scopeType: "agent",
      scopeId: "agent-1",
      scopeName: "Budget Agent",
      reason: "Agent cannot start because its budget hard-stop is still exceeded.",
    });
  });

  it("surfaces a budget-owned company pause distinctly from a manual pause", async () => {
    const dbStub = createDbStub([
      [{
        status: "idle",
        pauseReason: null,
        companyId: "company-1",
        name: "Budget Agent",
      }],
      [{
        status: "paused",
        pauseReason: "budget",
        name: "Paperclip",
      }],
    ]);

    const service = budgetService(dbStub.db as any);
    const block = await service.getInvocationBlock("company-1", "agent-1");

    expect(block).toEqual({
      scopeType: "company",
      scopeId: "company-1",
      scopeName: "Paperclip",
      reason: "Company is paused because its budget hard-stop was reached.",
    });
  });

  it("uses live observed spend when raising a budget incident", async () => {
    const dbStub = createDbStub([
      [{
        id: "incident-1",
        companyId: "company-1",
        policyId: "policy-1",
        amountObserved: 120,
        approvalId: "approval-1",
      }],
      [{
        id: "policy-1",
        companyId: "company-1",
        scopeType: "company",
        scopeId: "company-1",
        metric: "billed_cents",
        windowKind: "calendar_month_utc",
      }],
      [{ total: 150 }],
    ]);

    const service = budgetService(dbStub.db as any);

    await expect(
      service.resolveIncident(
        "company-1",
        "incident-1",
        { action: "raise_budget_and_resume", amount: 140 },
        "board-user",
      ),
    ).rejects.toThrow("New budget must exceed current observed spend");
  });

  it("syncs company monthly budget when raising and resuming a company incident", async () => {
    const now = new Date();
    const dbStub = createDbStub([
      [{
        id: "incident-1",
        companyId: "company-1",
        policyId: "policy-1",
        scopeType: "company",
        scopeId: "company-1",
        metric: "billed_cents",
        windowKind: "calendar_month_utc",
        windowStart: now,
        windowEnd: now,
        thresholdType: "hard",
        amountLimit: 100,
        amountObserved: 120,
        status: "open",
        approvalId: "approval-1",
        resolvedAt: null,
        createdAt: now,
        updatedAt: now,
      }],
      [{
        id: "policy-1",
        companyId: "company-1",
        scopeType: "company",
        scopeId: "company-1",
        metric: "billed_cents",
        windowKind: "calendar_month_utc",
        amount: 100,
      }],
      [{ total: 120 }],
      [{ id: "approval-1", status: "approved" }],
      [{
        companyId: "company-1",
        name: "Paperclip",
        status: "paused",
        pauseReason: "budget",
        pausedAt: now,
      }],
    ]);

    const service = budgetService(dbStub.db as any);
    await service.resolveIncident(
      "company-1",
      "incident-1",
      { action: "raise_budget_and_resume", amount: 175 },
      "board-user",
    );

    expect(dbStub.updateSet).toHaveBeenCalledWith(
      expect.objectContaining({
        budgetMonthlyCents: 175,
        updatedAt: expect.any(Date),
      }),
    );
  });

  it("skips stale scoped incidents when building overview", async () => {
    const companyPolicy = {
      id: "policy-company-1",
      companyId: "company-1",
      scopeType: "company",
      scopeId: "company-1",
      metric: "billed_cents",
      windowKind: "calendar_month_utc",
      amount: 100,
      warnPercent: 80,
      hardStopEnabled: true,
      notifyEnabled: true,
      isActive: true,
      updatedAt: new Date("2026-04-01T00:00:00.000Z"),
    };
    const staleIncident = {
      id: "incident-stale",
      companyId: "company-1",
      policyId: "policy-company-1",
      scopeType: "agent",
      scopeId: "agent-missing",
      metric: "billed_cents",
      windowKind: "calendar_month_utc",
      windowStart: new Date("2026-04-01T00:00:00.000Z"),
      windowEnd: new Date("2026-05-01T00:00:00.000Z"),
      thresholdType: "hard",
      amountLimit: 50,
      amountObserved: 75,
      status: "open",
      approvalId: null,
      resolvedAt: null,
      createdAt: new Date("2026-04-01T00:00:00.000Z"),
      updatedAt: new Date("2026-04-01T00:00:00.000Z"),
    };

    const dbStub = createDbStub([
      [companyPolicy],
      [{
        companyId: "company-1",
        name: "Paperclip",
        status: "active",
        pauseReason: null,
        pausedAt: null,
      }],
      [{ total: 10 }],
      [staleIncident],
      [],
    ]);

    const service = budgetService(dbStub.db as any);
    const overview = await service.overview("company-1");

    expect(overview.policies).toHaveLength(1);
    expect(overview.policies[0]).toEqual(
      expect.objectContaining({
        policyId: "policy-company-1",
        scopeType: "company",
        scopeId: "company-1",
        scopeName: "Paperclip",
      }),
    );
    expect(overview.activeIncidents).toEqual([]);
    expect(overview.pendingApprovalCount).toBe(0);
  });
});
