import { describe, expect, it, vi } from "vitest";
import { AuthplaneError, VerifiedClaims, type AuthplaneResource } from "@authplane/sdk/core";

import { AuthplaneTokenVerifier } from "../src/verifier.js";

describe("AuthplaneTokenVerifier", () => {
  it("maps verified claims into FastMCP session shape", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add", "tools/admin"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: {
        sub: "user_123",
        tenant_id: "tenant_789",
      },
    });
    const verifier = {
      verify: vi.fn(async () => claims),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    const result = await adapter.verifyAccessToken("valid_jwt");

    expect(result).toEqual({
      token: "valid_jwt",
      clientId: "client_456",
      scopes: ["tools/add", "tools/admin"],
      expiresAt: 1700000000,
      claims: {
        sub: "user_123",
        tenant_id: "tenant_789",
      },
    });
  });

  it("propagates AuthplaneError so the adapter can map it to a typed WWW-Authenticate challenge", async () => {
    const verifier = {
      verify: vi.fn(async () => {
        throw new AuthplaneError("Invalid token");
      }),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    await expect(adapter.verifyAccessToken("bad_token")).rejects.toBeInstanceOf(
      AuthplaneError,
    );
  });

  it("rethrows non-authplane errors", async () => {
    const verifier = {
      verify: vi.fn(async () => {
        throw new Error("unexpected");
      }),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    await expect(adapter.verifyAccessToken("bad_token")).rejects.toThrow(
      "unexpected",
    );
  });
});
