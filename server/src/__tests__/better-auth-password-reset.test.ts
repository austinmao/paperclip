/**
 * Regression: the 2026.707 Track B image was built directly from the fork and
 * omitted the OpenClaw password-reset delivery callback. The hosted endpoint
 * then returned "Reset password isn't enabled" instead of sending AgentMail.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Db } from "@paperclipai/db";
import type { Config } from "../config.js";
import {
  buildBetterAuthEmailAndPasswordOptions,
  createBetterAuthInstance,
} from "../auth/better-auth.js";
import { sendResetPasswordRedacted } from "../auth/openclaw-idp.js";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("Better Auth password-reset wiring", () => {
  it("keeps reset delivery enabled in direct Track B builds", () => {
    const options = buildBetterAuthEmailAndPasswordOptions({
      authDisableSignUp: true,
    } as Config);

    expect(options).toMatchObject({
      enabled: true,
      requireEmailVerification: false,
      disableSignUp: true,
    });
    expect(options.sendResetPassword).toBe(sendResetPasswordRedacted);
  });

  it("passes reset delivery through the production Better Auth assembly", () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "test-only-secret");
    const authFactory = vi.fn(() => ({ handler: vi.fn() })) as unknown as
      NonNullable<Parameters<typeof createBetterAuthInstance>[3]>;
    const config = {
      deploymentMode: "authenticated",
      deploymentExposure: "public",
      authBaseUrlMode: "explicit",
      authPublicBaseUrl: "https://agents.example.test",
      authDisableSignUp: true,
    } as Config;

    createBetterAuthInstance({} as Db, config, ["https://app.example.test"], authFactory);

    expect(authFactory).toHaveBeenCalledOnce();
    expect(authFactory.mock.calls[0]?.[0].emailAndPassword?.sendResetPassword)
      .toBe(sendResetPasswordRedacted);
  });
});
