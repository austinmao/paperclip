import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

describe("App route registration", () => {
  it("registers the legacy unprefixed dashboard redirect", () => {
    const source = readFileSync(fileURLToPath(new URL("./App.tsx", import.meta.url)), "utf8");
    const dashboardRoute = '<Route path="dashboard/*" element={<UnprefixedBoardRedirect />} />';

    expect(source).toContain(dashboardRoute);
  });
});
