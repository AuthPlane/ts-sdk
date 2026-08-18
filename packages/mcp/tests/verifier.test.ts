import { describe, expect, it, vi } from "vitest";
import {
  AuthplaneError,
  type AuthplaneResource,
  CircuitOpenError,
  DPoPBindingMismatch,
  DPoPNotSupported,
  InsufficientScope,
  InvalidClaims,
  InvalidGrant,
  InvalidSignature,
  JWKSFetchError,
  MetadataFetchError,
  MissingMetadataEndpoint,
  MultipleDPoPProofs,
  TokenExpired,
  TokenMissing,
  TokenRevoked,
  VerifiedClaims,
  VerifierRuntimeError,
} from "@authplane/sdk/core";
import {
  InsufficientScopeError,
  InvalidTokenError,
  ServerError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";

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

  it("propagates AuthplaneError unchanged from verifyAccessTokenWithDpop (our own adapter classifies it via httpStatus + wwwAuthenticate)", async () => {
    const verifier = {
      verify: vi.fn(async () => {
        throw new InvalidSignature("signature verification failed");
      }),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    await expect(
      adapter.verifyAccessTokenWithDpop("bad_token"),
    ).rejects.toBeInstanceOf(InvalidSignature);
  });

  it("throws InvalidClaims from verifyAccessTokenWithDpop when audience array is empty", async () => {
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

    await expect(
      adapter.verifyAccessTokenWithDpop("token"),
    ).rejects.toBeInstanceOf(InvalidClaims);
  });

  it("throws InvalidClaims from verifyAccessTokenWithDpop when audience is not a valid URL", async () => {
    // The OAuth `aud` claim is just a string — non-URL values are spec-legal
    // even though RFC 8707 resource indicators are URIs in practice. A
    // malformed audience must surface as 401 (token-validity), not 500.
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: ["not a url"],
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

    await expect(adapter.verifyAccessTokenWithDpop("token")).rejects.toThrow(
      new InvalidClaims("Token audience is not a valid URL"),
    );
  });

  it("rethrows non-authplane verifier errors unchanged from both entry points", async () => {
    const verifier = {
      verify: vi.fn(async () => {
        throw new Error("unexpected");
      }),
    } as unknown as AuthplaneResource;
    const adapter = new AuthplaneTokenVerifier(verifier);

    await expect(adapter.verifyAccessToken("bad_token")).rejects.toThrow(
      "unexpected",
    );
    await expect(
      adapter.verifyAccessTokenWithDpop("bad_token"),
    ).rejects.toThrow("unexpected");
  });
});

describe("AuthplaneTokenVerifier.verifyAccessToken error taxonomy", () => {
  function adapterThrowing(error: unknown): AuthplaneTokenVerifier {
    return new AuthplaneTokenVerifier({
      verify: vi.fn(async () => {
        throw error;
      }),
    } as unknown as AuthplaneResource);
  }

  it.each([
    ["TokenMissing", new TokenMissing()],
    ["TokenExpired", new TokenExpired()],
    ["InvalidSignature", new InvalidSignature()],
    ["InvalidClaims", new InvalidClaims()],
    ["TokenRevoked", new TokenRevoked()],
    ["InvalidGrant", new InvalidGrant()],
    ["DPoPBindingMismatch", new DPoPBindingMismatch()],
    ["MultipleDPoPProofs", new MultipleDPoPProofs()],
  ])("maps %s to InvalidTokenError", async (_label, error) => {
    const rejection = await adapterThrowing(error)
      .verifyAccessToken("t")
      .catch((e: unknown) => e);

    expect(rejection).toBeInstanceOf(InvalidTokenError);
    expect((rejection as InvalidTokenError).errorCode).toBe("invalid_token");
  });

  it("maps InsufficientScope to InsufficientScopeError", async () => {
    const rejection = await adapterThrowing(new InsufficientScope())
      .verifyAccessToken("t")
      .catch((e: unknown) => e);

    expect(rejection).toBeInstanceOf(InsufficientScopeError);
    expect((rejection as InsufficientScopeError).errorCode).toBe(
      "insufficient_scope",
    );
  });

  it.each([
    ["JWKSFetchError", new JWKSFetchError()],
    ["MetadataFetchError", new MetadataFetchError()],
    ["MissingMetadataEndpoint", new MissingMetadataEndpoint()],
    ["CircuitOpenError", new CircuitOpenError()],
    ["VerifierRuntimeError", new VerifierRuntimeError()],
    ["bare AuthplaneError", new AuthplaneError("something odd")],
  ])("maps %s to ServerError", async (_label, error) => {
    const rejection = await adapterThrowing(error)
      .verifyAccessToken("t")
      .catch((e: unknown) => e);

    expect(rejection).toBeInstanceOf(ServerError);
    expect((rejection as ServerError).errorCode).toBe("server_error");
    expect((rejection as ServerError).message).toBe(
      "Authorization server temporarily unavailable",
    );
  });

  it("keeps internal infrastructure detail off the 500 wire message", async () => {
    // The SDK renders `ServerError.message` verbatim in the unauthenticated
    // response body, and core's fetch errors embed the underlying failure
    // (hostnames included). Only `.cause` may carry the detail.
    const original = new MetadataFetchError(
      "Failed to fetch document: getaddrinfo ENOTFOUND internal-as.corp.local",
    );
    const rejection = await adapterThrowing(original)
      .verifyAccessToken("t")
      .catch((e: unknown) => e);

    expect((rejection as Error).message).not.toContain("internal-as.corp");
    expect((rejection as Error).cause).toBe(original);
  });

  it("maps DPoPNotSupported to InvalidTokenError", async () => {
    // Bearer-scheme carve-out in core's `wwwAuthenticate`; through this seam
    // it is still a 401 token-validity failure.
    const rejection = await adapterThrowing(new DPoPNotSupported())
      .verifyAccessToken("t")
      .catch((e: unknown) => e);

    expect(rejection).toBeInstanceOf(InvalidTokenError);
  });

  it("maps a malformed audience to InvalidTokenError, not a 500", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: ["not a url"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const adapter = new AuthplaneTokenVerifier({
      verify: vi.fn(async () => claims),
    } as unknown as AuthplaneResource);

    await expect(adapter.verifyAccessToken("t")).rejects.toBeInstanceOf(
      InvalidTokenError,
    );
  });

  it("preserves the core error as `cause` for host-side logging", async () => {
    const original = new TokenExpired();
    const rejection = await adapterThrowing(original)
      .verifyAccessToken("t")
      .catch((e: unknown) => e);

    expect((rejection as Error).cause).toBe(original);
  });

  it("carries core's sanitised message through, stripping header-breaking characters", async () => {
    const rejection = await adapterThrowing(
      new TokenExpired('Token has expired: "exp" claim check\r\nInjected: yes'),
    )
      .verifyAccessToken("t")
      .catch((e: unknown) => e);

    const message = (rejection as Error).message;
    expect(message).not.toMatch(/["\\\r\n]/);
    expect(message).toContain("Token has expired");
    expect(message).toContain("exp");
  });
});
