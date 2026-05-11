import { describe, expect, it } from "vitest";
import {
  AuthplaneTokenVerifier,
  IntrospectionRevocation,
  TokenRevoked,
  authplaneMcpAuth,
  requireScope,
  toUrlElicitationRequiredError,
} from "../src/index.js";

describe("mcp index exports", () => {
  it("exports public symbols", () => {
    expect(typeof authplaneMcpAuth).toBe("function");
    expect(typeof requireScope).toBe("function");
    expect(typeof AuthplaneTokenVerifier).toBe("function");
    expect(typeof IntrospectionRevocation.get).toBe("function");
    expect(typeof TokenRevoked).toBe("function");
    expect(typeof toUrlElicitationRequiredError).toBe("function");
  });
});
