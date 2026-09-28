import { describe, expect, it, vi } from "vitest";

// Simulates what Node's ESM loader hands the guard when the ipaddr.js import
// resolves to a shape without `parse` (the namespace-import regression): the
// call site raises a TypeError before any address is parsed. That must
// surface, not be translated into "blocked" — the malformed-address path
// (`ipaddr.parse` throwing a plain Error) is the only failure that may
// return false, and tests/core/ssrf.test.ts covers it.
vi.mock("ipaddr.js", () => ({
  default: {
    parse: () => {
      throw new TypeError("ipaddr.parse is not a function");
    },
    IPv6: class {},
  },
}));

describe("isIpAllowed with a broken ipaddr.js import", () => {
  it("propagates the TypeError instead of rejecting every address", async () => {
    const { isIpAllowed } = await import("../../src/core/fetching/ssrf.js");
    expect(() => isIpAllowed("8.8.8.8")).toThrow(TypeError);
  });
});
