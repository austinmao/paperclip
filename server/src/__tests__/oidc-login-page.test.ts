import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { renderOidcLoginPage } from "../auth/oidc-login-page.js";

describe("hosted OIDC login page", () => {
  afterEach(() => {
    delete process.env.OPENCLAW_OIDC_APP_NAME;
    delete process.env.OPENCLAW_OIDC_SUBTITLE;
  });

  it("renders the teal token contract and OAuth resume form", () => {
    const html = renderOidcLoginPage();

    expect(html).toContain("--oc-accent:172 76% 42%");
    expect(html).toContain("--primary:172 76% 42%");
    expect(html).toContain("--ring:172 76% 42%");
    expect(html).not.toContain("--primary:228 92% 63%");
    expect(html).toContain('id="login-form"');
    expect(html).toContain('type="email"');
    expect(html).toContain('type="password"');
    expect(html).toContain("/api/auth/sign-in/email");
    expect(html).toContain("/api/auth/oauth2/authorize");
  });

  it("brands the heading + title with the platform name and surfaces no IdP name", () => {
    const html = renderOidcLoginPage();

    expect(html).toContain("<title>Sign in to Glance</title>");
    expect(html).toContain("<h1>Sign in to Glance</h1>");
    // The internal IdP name must not leak to end users.
    expect(html).not.toContain("OpenClaw");
    expect(html).not.toContain("Paperclip");
    // No subtitle by default.
    expect(html).not.toContain("account to continue");
  });

  it("honors OPENCLAW_OIDC_APP_NAME + OPENCLAW_OIDC_SUBTITLE overrides (escaped)", () => {
    process.env.OPENCLAW_OIDC_APP_NAME = "Acme <Co>";
    process.env.OPENCLAW_OIDC_SUBTITLE = "Welcome back";
    const html = renderOidcLoginPage();

    expect(html).toContain("<title>Sign in to Acme &lt;Co&gt;</title>");
    expect(html).toContain("<h1>Sign in to Acme &lt;Co&gt;</h1>");
    expect(html).toContain("<p>Welcome back</p>");
    expect(html).not.toContain("Acme <Co>");
  });

  it("is served as no-cache HTML from /oidc-login", async () => {
    const app = express();
    app.get("/oidc-login", (_req, res) => {
      res
        .status(200)
        .type("html")
        .set("Cache-Control", "no-cache")
        .send(renderOidcLoginPage());
    });

    const res = await request(app).get("/oidc-login").expect(200);

    expect(res.headers["content-type"]).toContain("text/html");
    expect(res.headers["cache-control"]).toBe("no-cache");
    expect(res.text).toContain("--oc-accent:172 76% 42%");
  });
});
