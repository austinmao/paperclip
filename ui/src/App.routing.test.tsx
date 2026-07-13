// @vitest-environment jsdom

import type { ReactNode } from "react";
import { flushSync } from "react-dom";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockLocation = vi.hoisted(() => ({
  pathname: "/dashboard",
  search: "",
  hash: "",
}));

const mockCompany = vi.hoisted(() => ({
  loading: false,
  selectedCompany: { id: "company-stg", issuePrefix: "STG" } as {
    id: string;
    issuePrefix: string;
  } | null,
  companies: [{ id: "company-stg", issuePrefix: "STG" }],
}));

vi.mock("@/lib/router", () => ({
  Link: ({ to, children }: { to: string; children?: ReactNode }) => <a href={to}>{children}</a>,
  Navigate: ({ to, replace }: { to: string; replace?: boolean }) => (
    <div>{`Navigate:${to}:${replace ? "replace" : "push"}`}</div>
  ),
  Outlet: () => null,
  Route: ({ children }: { children?: ReactNode }) => <>{children}</>,
  Routes: ({ children }: { children?: ReactNode }) => <>{children}</>,
  useLocation: () => mockLocation,
  useParams: () => ({}),
}));

vi.mock("./context/CompanyContext", () => ({
  useCompany: () => mockCompany,
}));

import { UnprefixedBoardRedirect } from "./components/UnprefixedBoardRedirect";

describe("UnprefixedBoardRedirect", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    mockLocation.pathname = "/dashboard";
    mockLocation.search = "";
    mockLocation.hash = "";
    mockCompany.loading = false;
    mockCompany.selectedCompany = { id: "company-stg", issuePrefix: "STG" };
    mockCompany.companies = [{ id: "company-stg", issuePrefix: "STG" }];
  });

  afterEach(() => {
    flushSync(() => root.unmount());
    container.remove();
  });

  function renderRedirect() {
    flushSync(() => root.render(<UnprefixedBoardRedirect />));
  }

  it("redirects the bare dashboard to the selected company and preserves query and hash", () => {
    mockLocation.search = "?filter=open";
    mockLocation.hash = "#card-1";

    renderRedirect();

    expect(container.textContent).toBe("Navigate:/STG/dashboard?filter=open#card-1:replace");
  });

  it("redirects an unprefixed dashboard subpage into the selected company", () => {
    mockLocation.pathname = "/dashboard/live";

    renderRedirect();

    expect(container.textContent).toBe("Navigate:/STG/dashboard/live:replace");
  });

  it("falls back to the first company when no company is selected", () => {
    mockCompany.selectedCompany = null;
    mockCompany.companies = [{ id: "company-alt", issuePrefix: "ALT" }];

    renderRedirect();

    expect(container.textContent).toBe("Navigate:/ALT/dashboard:replace");
  });

  it("waits for company loading to finish", () => {
    mockCompany.loading = true;

    renderRedirect();

    expect(container.textContent).toBe("Loading...");
  });

  it("sends a companyless dashboard visit to onboarding", () => {
    mockCompany.selectedCompany = null;
    mockCompany.companies = [];

    renderRedirect();

    expect(container.textContent).toBe("Navigate:/onboarding:replace");
  });
});
