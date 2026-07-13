import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

describe("App route ordering", () => {
  it("routes the legacy unprefixed dashboard before the company-prefix matcher", () => {
    const source = readFileSync(fileURLToPath(new URL("./App.tsx", import.meta.url)), "utf8");
    const dashboardRoute = '<Route path="dashboard" element={<UnprefixedBoardRedirect />} />';
    const companyPrefixRoute = '<Route path=":companyPrefix" element={<Layout />}>';

    expect(source).toContain(dashboardRoute);
    expect(source.indexOf(dashboardRoute)).toBeLessThan(source.indexOf(companyPrefixRoute));
  });
});
