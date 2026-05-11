import { describe, expect, it } from "vitest";
import {
  AuthplaneTokenVerifier,
  IntrospectionRevocation,
  TokenRevoked,
  authplaneFastMcpAuth,
  toUrlElicitationRequiredError,
} from "../src/index.js";

describe("fastmcp index exports", () => {
  it("exports public symbols", () => {
    expect(typeof authplaneFastMcpAuth).toBe("function");
    expect(typeof AuthplaneTokenVerifier).toBe("function");
    expect(typeof IntrospectionRevocation.get).toBe("function");
    expect(typeof TokenRevoked).toBe("function");
    expect(typeof toUrlElicitationRequiredError).toBe("function");
  });
});
