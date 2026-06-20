import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { renderOidcLoginPage } from "../auth/oidc-login-page.js";

describe("hosted OIDC login page", () => {
  it("renders the OpenClaw teal token contract and OAuth resume form", () => {
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
