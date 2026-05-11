import { describe, expect, it } from "vitest";

import { InsufficientScope, VerifiedClaims } from "../../src/core/index.js";

function makeClaims(): VerifiedClaims {
  return new VerifiedClaims({
    sub: "user_123",
    clientId: "client_123",
    scopes: ["tools/query", "tools/write"],
    issuer: "https://auth.example.com",
    audience: ["https://api.example.com"],
    expiresAt: 1_800_000_000,
    issuedAt: 1_700_000_000,
    jti: "jti_123",
    kid: "kid_123",
    agentId: "",
    agentChain: [],
    notBefore: 0,
    raw: {
      sub: "user_123",
      client_id: "client_123",
      tenant_id: "tenant_123",
    },
  });
}

describe("VerifiedClaims", () => {
  it("checks granted scopes", () => {
    const claims = makeClaims();
    expect(claims.hasScope("tools/query")).toBe(true);
    expect(claims.hasScope("tools/admin")).toBe(false);
  });

  it("enforces required scopes", () => {
    const claims = makeClaims();
    expect(() => claims.requireScope("tools/query")).not.toThrow();
    expect(() => claims.requireScope("tools/admin")).toThrow(InsufficientScope);
  });

  it("checks raw claims", () => {
    const claims = makeClaims();
    expect(claims.hasClaim("tenant_id")).toBe(true);
    expect(claims.hasClaim("tenant_id", "tenant_123")).toBe(true);
    expect(claims.hasClaim("tenant_id", "tenant_999")).toBe(false);
  });

  it("act returns the RFC 8693 actor object when present", () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_123",
      scopes: [],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com"],
      expiresAt: 1_800_000_000,
      issuedAt: 1_700_000_000,
      jti: "jti_1",
      kid: "kid_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: {
        act: { sub: "actor_1", iss: "https://auth.example.com" },
      },
    });
    expect(claims.act).toEqual({
      sub: "actor_1",
      iss: "https://auth.example.com",
    });
  });

  it("act is undefined when the claim is absent or not an object", () => {
    const claims = makeClaims();
    expect(claims.act).toBeUndefined();
  });

  it("mayAct returns the RFC 8693 may_act object when present", () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_123",
      scopes: [],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com"],
      expiresAt: 1_800_000_000,
      issuedAt: 1_700_000_000,
      jti: "jti_1",
      kid: "kid_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { may_act: { sub: "svc_delegate" } },
    });
    expect(claims.mayAct).toEqual({ sub: "svc_delegate" });
  });

  it("mayAct is undefined when absent", () => {
    const claims = makeClaims();
    expect(claims.mayAct).toBeUndefined();
  });
});
