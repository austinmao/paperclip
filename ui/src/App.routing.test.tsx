// @vitest-environment jsdom

import { flushSync } from "react-dom";
import { createRoot } from "react-dom/client";
import {
  MemoryRouter,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockCompany = vi.hoisted(() => ({
  loading: false,
  selectedCompany: { id: "company-stg", issuePrefix: "STG" } as {
    id: string;
    issuePrefix: string;
  } | null,
  companies: [{ id: "company-stg", issuePrefix: "STG" }],
}));

vi.mock("./context/CompanyContext", () => ({
  useCompany: () => mockCompany,
}));

import {
  UNPREFIXED_DASHBOARD_ROUTE,
  UnprefixedBoardRedirect,
} from "./components/UnprefixedBoardRedirect";

function LocationProbe() {
  const location = useLocation();
  return <div>{`${location.pathname}${location.search}${location.hash}`}</div>;
}

describe("unprefixed dashboard routing", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    mockCompany.loading = false;
    mockCompany.selectedCompany = { id: "company-stg", issuePrefix: "STG" };
    mockCompany.companies = [{ id: "company-stg", issuePrefix: "STG" }];
  });

  afterEach(() => {
    flushSync(() => root.unmount());
    container.remove();
  });

  async function renderAt(path: string) {
    flushSync(() => {
      root.render(
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route
              path={UNPREFIXED_DASHBOARD_ROUTE}
              element={<UnprefixedBoardRedirect />}
            />
            <Route path="onboarding" element={<LocationProbe />} />
            <Route path=":companyPrefix/dashboard/*" element={<LocationProbe />} />
            <Route path=":companyPrefix" element={<div>wrong-prefix-route</div>} />
          </Routes>
        </MemoryRouter>,
      );
    });
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await Promise.resolve();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      if (!container.textContent?.includes("Loading...")) break;
    }
  }

  it.each([
    ["/dashboard", "/STG/dashboard"],
    ["/dashboard/live", "/STG/dashboard/live"],
    ["/dashboard/live?filter=open#card-1", "/STG/dashboard/live?filter=open#card-1"],
    ["/dashboard/a/b", "/STG/dashboard/a/b"],
  ])("canonicalizes %s through the real router", async (entry, expected) => {
    await renderAt(entry);

    expect(container.textContent).toBe(expected);
    expect(container.textContent).not.toContain("wrong-prefix-route");
  });

  it("falls back to the first company when no company is selected", async () => {
    mockCompany.selectedCompany = null;
    mockCompany.companies = [{ id: "company-alt", issuePrefix: "ALT" }];

    await renderAt("/dashboard");

    expect(container.textContent).toBe("/ALT/dashboard");
  });

  it("does not double-prefix a company whose prefix is also a board route root", async () => {
    mockCompany.selectedCompany = { id: "company-org", issuePrefix: "ORG" };
    mockCompany.companies = [{ id: "company-org", issuePrefix: "ORG" }];

    await renderAt("/dashboard");

    expect(container.textContent).toBe("/ORG/dashboard");
  });

  it("waits for company loading to finish", async () => {
    mockCompany.loading = true;

    await renderAt("/dashboard");

    expect(container.textContent).toBe("Loading...");
  });

  it("sends a companyless dashboard visit to onboarding", async () => {
    mockCompany.selectedCompany = null;
    mockCompany.companies = [];

    await renderAt("/dashboard");

    expect(container.textContent).toBe("/onboarding");
  });
});
