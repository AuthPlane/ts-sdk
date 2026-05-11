import { describe, expect, it } from "vitest";

import { buildPrm } from "../../src/core/index.js";

describe("buildPrm", () => {
  it(
    "rfc9728-prm-must-contain-required-fields",
    "builds RFC9728-like metadata shape",
    () => {
    const prm = buildPrm(
      "https://auth.example.com",
      "https://api.example.com/mcp",
      ["tools/query", "tools/write"]
    );

    expect(prm.resource).toBe("https://api.example.com/mcp");
    expect(prm.authorization_servers).toEqual(["https://auth.example.com"]);
    expect(prm.bearer_methods_supported).toEqual(["header"]);
    expect(prm.resource_signing_alg_values_supported).toEqual(["RS256", "ES256"]);
    expect(prm.scopes_supported).toEqual(["tools/query", "tools/write"]);
  });
});
