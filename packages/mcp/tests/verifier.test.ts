import { describe, expect, it, vi } from "vitest";
import {
  InvalidClaims,
  InvalidSignature,
  VerifiedClaims,
  type AuthplaneResource,
} from "@authplane/sdk/core";

import { AuthplaneTokenVerifier } from "../src/verifier.js";

describe("AuthplaneTokenVerifier", () => {
  it("maps verified claims into MCP AuthInfo", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add_numbers", "tools/echo_message"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verifier = {
      verify: vi.fn(async () => claims),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    const result = await adapter.verifyAccessToken("valid_jwt");

    expect(result.token).toBe("valid_jwt");
    expect(result.clientId).toBe("client_456");
    expect(result.scopes).toEqual(["tools/add_numbers", "tools/echo_message"]);
    expect(result.expiresAt).toBe(1700000000);
    expect(result.resource?.toString()).toBe("https://api.example.com/");
    expect(result.extra).toEqual({
      sub: "user_123",
      iss: "https://auth.example.com",
      jti: "token_123",
      kid: "key_1",
    });
  });

  it("propagates AuthplaneError unchanged (the calling adapter classifies it via httpStatus + wwwAuthenticate)", async () => {
    const verifier = {
      verify: vi.fn(async () => {
        throw new InvalidSignature("signature verification failed");
      }),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    await expect(adapter.verifyAccessToken("bad_token")).rejects.toBeInstanceOf(
      InvalidSignature,
    );
  });

  it("throws InvalidClaims when audience array is empty", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: [],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verifier = {
      verify: vi.fn(async () => claims),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    await expect(adapter.verifyAccessToken("token")).rejects.toBeInstanceOf(
      InvalidClaims,
    );
  });

  it("rethrows non-authplane verifier errors", async () => {
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
