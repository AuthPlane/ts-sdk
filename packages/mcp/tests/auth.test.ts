import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { UrlElicitationRequiredError } from "@modelcontextprotocol/sdk/types.js";
import {
  AuthplaneClient,
  type AuthplaneResource,
  ConsentRequiredError,
} from "@authplane/sdk/core";

import { AuthplaneTokenVerifier } from "../src/verifier.js";
import { authplaneMcpAuth, requireScope } from "../src/auth.js";

describe("authplaneMcpAuth", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("builds verifier, bearer middleware, and PRM route wiring (without client)", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add_numbers"],
        bearer_methods_supported: ["header"],
      })),
      prmDocumentUrl: vi.fn(
        () => "https://api.example.com/.well-known/oauth-protected-resource/mcp",
      ),
    } as unknown as AuthplaneResource;

    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(),
    } as unknown as AuthplaneClient;

    const clientCreateSpy = vi
      .spyOn(AuthplaneClient, "create")
      .mockResolvedValue(mockClient);

    const options = {
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add_numbers"],
      requiredScopes: ["tools/add_numbers"],
    };

    const result = await authplaneMcpAuth(options);

    expect(clientCreateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        issuer: "https://auth.example.com",
      }),
    );
    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        scopes: ["tools/add_numbers"],
      }),
    );
    expect(result.tokenVerifier).toBeInstanceOf(AuthplaneTokenVerifier);
    expect(typeof result.bearerAuth).toBe("function");
    expect(result.protectedResourceMetadataPath).toBe(
      "/.well-known/oauth-protected-resource/mcp"
    );
    expect(result.protectedResourceMetadata.resource).toBe(
      "https://api.example.com/mcp"
    );
  });

  it("forwards revocationChecker to AuthplaneClient.resource()", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: [],
        bearer_methods_supported: ["header"],
      })),
      prmDocumentUrl: vi.fn(
        () => "https://api.example.com/.well-known/oauth-protected-resource/mcp",
      ),
    } as unknown as AuthplaneResource;

    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(),
    } as unknown as AuthplaneClient;

    const clientCreateSpy = vi
      .spyOn(AuthplaneClient, "create")
      .mockResolvedValue(mockClient);

    const result = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      revocationChecker: { clientId: "my-rs", clientSecret: "s3cret" },
    });

    expect(clientCreateSpy).toHaveBeenCalled();
    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        revocationChecker: { clientId: "my-rs", clientSecret: "s3cret" },
      }),
    );
    expect(result.client).toBe(mockClient);
  });

  it("creates AuthplaneClient when asCredentials are provided", async () => {
    const mockClient = {
      resource: vi.fn(() => ({
        verify: vi.fn(),
        prmResponse: vi.fn(() => ({
          resource: "https://api.example.com/mcp",
          authorization_servers: ["https://auth.example.com"],
          scopes_supported: ["tools/add_numbers"],
          bearer_methods_supported: ["header"],
        })),
        prmDocumentUrl: vi.fn(
          () =>
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
        ),
      })) as unknown,
      exchange: vi.fn(),
    } as unknown as AuthplaneClient;

    const clientCreateSpy = vi
      .spyOn(AuthplaneClient, "create")
      .mockResolvedValue(mockClient);

    const result = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add_numbers"],
      asCredentials: { clientId: "id", clientSecret: "secret" },
    });

    expect(clientCreateSpy).toHaveBeenCalledWith({
      issuer: "https://auth.example.com",
      auth: { clientId: "id", clientSecret: "secret" },
    });
    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        scopes: ["tools/add_numbers"],
      }),
    );
    expect(result.client).toBe(mockClient);
  });

  it("forwards cache tunables (cacheTtlBufferSeconds, defaultTtlSeconds, cacheMaxEntries) to AuthplaneClient.create()", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: [],
        bearer_methods_supported: ["header"],
      })),
      prmDocumentUrl: vi.fn(
        () => "https://api.example.com/.well-known/oauth-protected-resource/mcp",
      ),
    } as unknown as AuthplaneResource;

    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(),
    } as unknown as AuthplaneClient;

    const createSpy = vi
      .spyOn(AuthplaneClient, "create")
      .mockResolvedValue(mockClient);

    await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      cacheTtlBufferSeconds: 45,
      defaultTtlSeconds: 1800,
      cacheMaxEntries: 256,
    });

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        cacheTtlBufferSeconds: 45,
        defaultTtlSeconds: 1800,
        cacheMaxEntries: 256,
      }),
    );
  });

  it("forwards all optional verifier config to AuthplaneClient.resource()", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: [],
        bearer_methods_supported: ["header"],
      })),
      prmDocumentUrl: vi.fn(
        () => "https://api.example.com/.well-known/oauth-protected-resource/mcp",
      ),
    } as unknown as AuthplaneResource;

    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(),
    } as unknown as AuthplaneClient;

    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      allowedAlgorithms: ["RS256", "ES256"],
      clockSkewSeconds: 30,
      inboundDPoP: { maxProofAgeSeconds: 60 },
      devMode: true,
    });

    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        allowedAlgorithms: ["RS256", "ES256"],
        clockSkewSeconds: 30,
        inboundDPoP: { maxProofAgeSeconds: 60 },
        devMode: true,
      }),
    );
  });

  it("wraps client.exchange so ConsentRequiredError maps to -32042", async () => {
    const consentError = new ConsentRequiredError("Consent needed", {
      serviceId: "calendar",
      causeDetail: "approval_pending",
      consentUrl: "https://example.com/consent",
      statusCode: 400,
    });
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: [],
        bearer_methods_supported: ["header"],
      })),
      prmDocumentUrl: vi.fn(
        () => "https://api.example.com/.well-known/oauth-protected-resource/mcp",
      ),
    } as unknown as AuthplaneResource;
    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(async () => {
        throw consentError;
      }),
    } as unknown as AuthplaneClient;
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    const result = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    const thrown = await result.client
      .exchange({} as never)
      .catch((e: unknown) => e);
    expect(thrown).toBeInstanceOf(UrlElicitationRequiredError);
    expect((thrown as Error).cause).toBe(consentError);
  });

  it("wrapped client.exchange passes through non-consent errors", async () => {
    const otherError = new Error("network failure");
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: [],
        bearer_methods_supported: ["header"],
      })),
      prmDocumentUrl: vi.fn(
        () => "https://api.example.com/.well-known/oauth-protected-resource/mcp",
      ),
    } as unknown as AuthplaneResource;
    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(async () => {
        throw otherError;
      }),
    } as unknown as AuthplaneClient;
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    const result = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await expect(result.client.exchange({} as never)).rejects.toThrow(
      "network failure",
    );
  });

  it("wrapped client.exchange passes through ConsentRequiredError without consentUrl", async () => {
    const consentError = new ConsentRequiredError("Consent needed", {
      serviceId: "calendar",
      causeDetail: "approval_pending",
      consentUrl: null,
      statusCode: 400,
    });
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: [],
        bearer_methods_supported: ["header"],
      })),
      prmDocumentUrl: vi.fn(
        () => "https://api.example.com/.well-known/oauth-protected-resource/mcp",
      ),
    } as unknown as AuthplaneResource;
    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(async () => {
        throw consentError;
      }),
    } as unknown as AuthplaneClient;
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    const result = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await expect(result.client.exchange({} as never)).rejects.toBeInstanceOf(
      ConsentRequiredError,
    );
  });
});

describe("requireScope", () => {
  it("passes when scope is present", () => {
    const authInfo = {
      token: "t",
      clientId: "c",
      scopes: ["tools/add", "tools/multiply"],
      expiresAt: 0,
    } as AuthInfo;

    expect(() => requireScope("tools/add", authInfo)).not.toThrow();
  });

  it("throws when scope is missing", () => {
    const authInfo = {
      token: "t",
      clientId: "c",
      scopes: ["tools/add"],
      expiresAt: 0,
    } as AuthInfo;

    expect(() => requireScope("tools/multiply", authInfo)).toThrow(
      /Missing required scope: tools\/multiply/
    );
  });

  it("throws when authInfo is undefined", () => {
    expect(() => requireScope("tools/add", undefined)).toThrow(
      /Missing required scope/
    );
  });
});
