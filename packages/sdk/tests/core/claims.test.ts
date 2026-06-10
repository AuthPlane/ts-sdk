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

  describe("requireScopes (AND)", () => {
    it("is a no-op when the required list is empty", () => {
      const claims = makeClaims();
      expect(() => claims.requireScopes([])).not.toThrow();
    });

    it("passes when every required scope is present", () => {
      const claims = makeClaims();
      expect(() =>
        claims.requireScopes(["tools/query", "tools/write"]),
      ).not.toThrow();
    });

    it("throws InsufficientScope naming the missing scope and present scopes", () => {
      const claims = makeClaims();
      expect(() =>
        claims.requireScopes(["tools/query", "tools/admin"]),
      ).toThrow(InsufficientScope);
      expect(() =>
        claims.requireScopes(["tools/query", "tools/admin"]),
      ).toThrow(
        "Token missing required scope 'tools/admin'. Token has scopes: tools/query, tools/write",
      );
    });

    it("pluralises the message and lists every missing scope", () => {
      const claims = makeClaims();
      expect(() =>
        claims.requireScopes(["tools/admin", "tools/superuser"]),
      ).toThrow(
        "Token missing required scopes 'tools/admin', 'tools/superuser'. Token has scopes: tools/query, tools/write",
      );
    });

    it("throws InsufficientScope when the token has no scopes at all", () => {
      const claims = new VerifiedClaims({
        sub: "u",
        clientId: "c",
        scopes: [],
        issuer: "https://auth.example.com",
        audience: ["https://api.example.com"],
        expiresAt: 1_800_000_000,
        issuedAt: 1_700_000_000,
        jti: "j",
        kid: "k",
        agentId: "",
        agentChain: [],
        notBefore: 0,
        raw: {},
      });
      expect(() => claims.requireScopes(["tools/query"])).toThrow(
        InsufficientScope,
      );
      // Empty scope list surfaces as "(none)" so the message stays grammatical.
      expect(() => claims.requireScopes(["tools/query"])).toThrow(
        "Token has scopes: (none)",
      );
    });
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
