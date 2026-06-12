import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AuthplaneClient,
  type AuthplaneResource,
  ConsentRequiredError,
  type DPoPReplayStore,
  DPoPReplayDetected,
  InsufficientScope,
  TokenExpired,
  VerifiedClaims,
} from "@authplane/sdk/core";
import { UrlElicitationRequiredError } from "@modelcontextprotocol/sdk/types.js";

import { AuthplaneTokenVerifier } from "../src/verifier.js";
import {
  _authenticateRequestContext,
  authplaneFastMcpAuth,
} from "../src/auth.js";

function createRequest(authorization?: string) {
  return {
    headers: authorization ? { authorization } : {},
  };
}

function createDpopRequest(args: {
  authorization?: string;
  dpop?: string;
  host?: string | string[];
  forwardedProto?: string | string[];
  url?: string;
  method?: string;
}) {
  const headers: Record<string, string | string[] | undefined> = {};
  if (args.authorization !== undefined) headers.authorization = args.authorization;
  if (args.dpop !== undefined) headers.dpop = args.dpop;
  if (args.host !== undefined) headers.host = args.host;
  if (args.forwardedProto !== undefined)
    headers["x-forwarded-proto"] = args.forwardedProto;
  return {
    headers,
    url: args.url,
    method: args.method,
  };
}

describe("authplaneFastMcpAuth", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    // Reset the per-request async-local store between tests. In production
    // Node's http.Server provides a fresh async context per HTTP request;
    // vitest shares one async context across the whole test file, so
    // `enterWith` from one test would leak its store into the next and the
    // production `if (store === undefined)` branch would never re-enter,
    // serving stale cached promises across tests.
    _authenticateRequestContext.disable();
  });

  it("builds verifier, token verifier, authenticate and oauth config", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });

    const mockResource = {
      verify: vi.fn(async () => claims),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
        bearer_methods_supported: ["header"],
        resource_signing_alg_values_supported: ["RS256", "ES256"],
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
      scopes: ["tools/add"],
    };

    const result = await authplaneFastMcpAuth(options);
    const session = await result.authenticate(
      createRequest("Bearer valid_jwt") as never,
    );

    expect(clientCreateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        issuer: "https://auth.example.com",
      }),
    );
    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        scopes: ["tools/add"],
      }),
    );

    expect(result.tokenVerifier).toBeInstanceOf(AuthplaneTokenVerifier);
    expect(session.clientId).toBe("client_456");
    expect(session.scopes).toEqual(["tools/add"]);
    expect(result.oauth.enabled).toBe(true);
    expect(result.oauth.protectedResource).toEqual({
      resource: "https://api.example.com/mcp",
      authorizationServers: ["https://auth.example.com"],
      scopesSupported: ["tools/add"],
      bearerMethodsSupported: ["header"],
    });
    expect(result.protectedResourceMetadataUrl).toBe(
      "https://api.example.com/.well-known/oauth-protected-resource/mcp",
    );
  });

  it("derives resource from baseUrl + mcpPath when resource is not set", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
        bearer_methods_supported: ["header"],
        resource_signing_alg_values_supported: ["RS256", "ES256"],
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

    await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      baseUrl: "https://api.example.com",
      mcpPath: "/mcp",
      scopes: ["tools/add"],
    });

    expect(clientCreateSpy).toHaveBeenCalled();
    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        scopes: ["tools/add"],
      }),
    );
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

    await authplaneFastMcpAuth({
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

  it("throws when neither resource nor baseUrl is provided", async () => {
    await expect(
      authplaneFastMcpAuth({
        issuer: "https://auth.example.com",
        scopes: ["tools/add"],
      } as never),
    ).rejects.toThrow(/provide either 'resource' or 'baseUrl'/);
  });

  it("throws 401 response when authorization header is missing", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
        bearer_methods_supported: ["header"],
        resource_signing_alg_values_supported: ["RS256", "ES256"],
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add"],
    });

    try {
      await result.authenticate(createRequest() as never);
      throw new Error("expected authenticate to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(Response);
      const response = error as Response;
      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toContain(
        'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
      );
    }
  });

  it("throws 403 response when token lacks requiredScopes", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });

    const mockResource = {
      verify: vi.fn(async () => claims),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add", "tools/admin"],
        bearer_methods_supported: ["header"],
        resource_signing_alg_values_supported: ["RS256", "ES256"],
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add", "tools/admin"],
      requiredScopes: ["tools/admin"],
    });

    try {
      await result.authenticate(createRequest("Bearer valid_jwt") as never);
      throw new Error("expected authenticate to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(Response);
      const response = error as Response;
      expect(response.status).toBe(403);
      const wwwAuth = response.headers.get("WWW-Authenticate") ?? "";
      expect(wwwAuth).toContain('error="insufficient_scope"');
      expect(wwwAuth).toContain('scope="tools/admin"');
      expect(wwwAuth).toContain(
        'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
      );
    }
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

    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      revocationChecker: { clientId: "my-rs", clientSecret: "s3cret" },
    });

    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        revocationChecker: { clientId: "my-rs", clientSecret: "s3cret" },
      }),
    );
  });

  it("creates AuthplaneClient when asCredentials are provided", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
        bearer_methods_supported: ["header"],
        resource_signing_alg_values_supported: ["RS256", "ES256"],
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add"],
      asCredentials: { clientId: "id", clientSecret: "secret" },
    });

    expect(clientCreateSpy).toHaveBeenCalledWith({
      issuer: "https://auth.example.com",
      auth: { clientId: "id", clientSecret: "secret" },
      devMode: undefined,
      fetchSettings: undefined,
      jwksRefreshSeconds: undefined,
      metadataRefreshSeconds: undefined,
    });
    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        scopes: ["tools/add"],
      }),
    );
    expect(result.client).toBe(mockClient);
  });

  it("forwards all optional verifier config to AuthplaneClient.resource()", async () => {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
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

    await authplaneFastMcpAuth({
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

  it("DPoP: builds full request context from DPoP header, using the configured resource origin (ignoring Host and X-Forwarded-Proto)", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await result.authenticate(
      createDpopRequest({
        authorization: "DPoP access_token",
        dpop: "dpop_proof_jwt",
        // Spoofed headers — the adapter must not derive origin from these.
        host: "attacker.example.com",
        forwardedProto: "http",
        url: "/mcp",
        method: "post",
      }) as never,
    );

    expect(verify).toHaveBeenCalledWith(
      "access_token",
      expect.objectContaining({
        dpopRequest: expect.objectContaining({
          method: "POST",
          url: "https://api.example.com/mcp",
          proofs: ["dpop_proof_jwt"],
        }),
      }),
    );
  });

  it("DPoP: still verifies when Host and X-Forwarded-Proto are absent — origin comes from resource, never the literal 'localhost'", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: [],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await result.authenticate(
      createDpopRequest({
        authorization: "DPoP token",
        dpop: "proof",
        url: "/mcp",
      }) as never,
    );

    const passedDpop = (verify.mock.calls[0]?.[1] as
      | { dpopRequest?: { url: string } }
      | undefined)?.dpopRequest;
    expect(passedDpop?.url).toBe("https://api.example.com/mcp");
    expect(passedDpop?.url).not.toContain("localhost");
  });

  it("DPoP: array-valued Host and X-Forwarded-Proto headers do not corrupt the htu", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: [],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await result.authenticate(
      createDpopRequest({
        authorization: "DPoP token",
        dpop: "proof",
        host: ["a.example.com", "b.example.com"],
        forwardedProto: ["https", "http"],
        url: "/mcp/path",
      }) as never,
    );

    expect(verify).toHaveBeenCalledWith(
      "token",
      expect.objectContaining({
        dpopRequest: expect.objectContaining({
          url: "https://api.example.com/mcp/path",
        }),
      }),
    );
  });

  it("DPoP: dispatched path drives the htu — proof for /endpoint-a replayed against /endpoint-b is handed to the SDK with the actual path", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: [],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await result.authenticate(
      createDpopRequest({
        authorization: "DPoP token",
        // Proof originally minted for `/endpoint-a` replayed against
        // `/endpoint-b`; the verifier sees the actual dispatched path so
        // the SDK's `htu` comparison can reject the replay.
        dpop: "proof-originally-for-endpoint-a",
        url: "/endpoint-b",
      }) as never,
    );

    expect(verify).toHaveBeenCalledWith(
      "token",
      expect.objectContaining({
        dpopRequest: expect.objectContaining({
          url: "https://api.example.com/endpoint-b",
        }),
      }),
    );
  });

  it("DPoP: default-port normalization — explicit :443 in resource is elided in the comparison URL", async () => {
    // Configuring `resource` with the explicit default HTTPS port must not
    // leak ":443" into the comparison URL, otherwise the adapter would
    // require its own port-normalizer in addition to the SDK's
    // `normalizeHtu`. We rely on `URL.host` to elide default ports.
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: [],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com:443/mcp",
    });

    await result.authenticate(
      createDpopRequest({
        authorization: "DPoP token",
        dpop: "proof",
        url: "/mcp",
      }) as never,
    );

    const passedDpop = (verify.mock.calls[0]?.[1] as
      | { dpopRequest?: { url: string } }
      | undefined)?.dpopRequest;
    expect(passedDpop?.url).toBe("https://api.example.com/mcp");
    expect(passedDpop?.url).not.toContain(":443");
  });

  it("accepts 'DPoP <token>' authorization header (RFC 9449)", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: [],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await result.authenticate(createRequest("DPoP my_token") as never);

    expect(verify).toHaveBeenCalledWith("my_token", expect.anything());
  });

  it("rejects authorization header that is an array (multiple Authorization headers)", async () => {
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    try {
      await result.authenticate({
        headers: { authorization: ["Bearer a", "Bearer b"] },
      } as never);
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(Response);
      expect((error as Response).status).toBe(401);
    }
  });

  it("rejects authorization header with unknown scheme", async () => {
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    try {
      await result.authenticate(createRequest("Basic abc123") as never);
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(Response);
      expect((error as Response).status).toBe(401);
    }
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
      exchange: vi.fn(async () => { throw consentError; }),
    } as unknown as AuthplaneClient;
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    const result = await authplaneFastMcpAuth({
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
      exchange: vi.fn(async () => { throw otherError; }),
    } as unknown as AuthplaneClient;
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await expect(result.client.exchange({} as never)).rejects.toThrow("network failure");
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
      exchange: vi.fn(async () => { throw consentError; }),
    } as unknown as AuthplaneClient;
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    await expect(result.client.exchange({} as never)).rejects.toBeInstanceOf(
      ConsentRequiredError,
    );
  });

  it("caches verify() per request so a second authenticate call does not double-verify the same DPoP proof", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      inboundDPoP: { required: true },
    });

    // Two authenticate calls within the same async context — simulates
    // FastMCP 3.35.x's double-invocation, where both calls happen as
    // descendants of the same HTTP request handler. The test body itself
    // is one async chain, which matches the per-request boundary Node
    // provides in production. Underlying verify() must run exactly once
    // so the inbound replay store only sees the proof's jti the first
    // time.
    const request = createDpopRequest({
      authorization: "Bearer access_token",
      dpop: "dpop_proof_jwt",
      url: "/mcp",
      method: "post",
    });
    const s1 = await result.authenticate(request as never);
    const s2 = await result.authenticate(request as never);

    expect(verify).toHaveBeenCalledTimes(1);
    expect(s1).toBe(s2);
  });

  it("does not share verify() across distinct request contexts even when the IncomingMessage is the same object", async () => {
    // Locks in the property that distinguishes ALS-based scoping from the
    // prior IncomingMessage-keyed cache: if the *same* request object is
    // re-presented in a *different* async context, the cache does not
    // serve. Models a (hypothetical) middleware/server that recycles
    // request objects across requests — would have produced a session
    // leak with the WeakMap design.
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
      expiresAt: 1700000000,
      issuedAt: 1699999000,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const verify = vi.fn(async () => claims);
    const mockResource = {
      verify,
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    const request = createRequest("Bearer access_token");
    await _authenticateRequestContext.run({}, async () => {
      await result.authenticate(request as never);
    });
    await _authenticateRequestContext.run({}, async () => {
      await result.authenticate(request as never);
    });

    expect(verify).toHaveBeenCalledTimes(2);
  });

  it("caches a failing verify() so the second call surfaces the same 401, not a different one", async () => {
    const verify = vi.fn(async () => {
      throw new Error("synthetic verify failure");
    });
    const mockResource = {
      verify,
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
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

    const result = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    });

    const request = createRequest("Bearer access_token");
    await expect(result.authenticate(request as never)).rejects.toThrow(
      "synthetic verify failure",
    );
    await expect(result.authenticate(request as never)).rejects.toThrow(
      "synthetic verify failure",
    );
    // verify() must still only have been called once; the rejection itself
    // is what the cache serves on the second pass.
    expect(verify).toHaveBeenCalledTimes(1);
  });

  // The per-class scheme/status/sanitisation table lives in
  // packages/sdk/tests/core/errors.test.ts against `wwwAuthenticate` and
  // `httpStatus` directly. The adapter-level smoke tests below only assert
  // that those helpers are wired in: typed errors round-trip out of the
  // catch into a `Response`, the resource-metadata URL is injected, and
  // the 401-vs-403 distinction is visible end-to-end.
  describe("error → Response wiring (smoke)", () => {
    function setupAdapter(verifyImpl: () => Promise<never>) {
      const mockResource = {
        verify: vi.fn(verifyImpl),
        prmResponse: vi.fn(() => ({
          resource: "https://api.example.com/mcp",
          authorization_servers: ["https://auth.example.com"],
          scopes_supported: ["tools/add"],
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
      return authplaneFastMcpAuth({
        issuer: "https://auth.example.com",
        resource: "https://api.example.com/mcp",
        scopes: ["tools/add"],
      });
    }

    it("Bearer-class error from verify → 401 Response with Bearer challenge and resource_metadata", async () => {
      const result = await setupAdapter(async () => {
        throw new TokenExpired("token past exp");
      });
      try {
        await result.authenticate(createRequest("Bearer access_token") as never);
        throw new Error("expected authenticate to throw");
      } catch (error) {
        expect(error).toBeInstanceOf(Response);
        const response = error as Response;
        expect(response.status).toBe(401);
        const challenge = response.headers.get("WWW-Authenticate") ?? "";
        expect(challenge).toMatch(/^Bearer /);
        expect(challenge).toContain(
          'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
        );
      }
    });

    it("DPoP-class error from verify → 401 Response with DPoP challenge", async () => {
      const result = await setupAdapter(async () => {
        throw new DPoPReplayDetected("DPoP proof jti already seen");
      });
      try {
        await result.authenticate(createRequest("Bearer access_token") as never);
        throw new Error("expected authenticate to throw");
      } catch (error) {
        const response = error as Response;
        expect(response.status).toBe(401);
        expect(response.headers.get("WWW-Authenticate") ?? "").toMatch(/^DPoP /);
      }
    });

    it("InsufficientScope from verify → 403 Response with insufficient_scope", async () => {
      const result = await setupAdapter(async () => {
        throw new InsufficientScope("requires tools/admin");
      });
      try {
        await result.authenticate(createRequest("Bearer access_token") as never);
        throw new Error("expected authenticate to throw");
      } catch (error) {
        const response = error as Response;
        expect(response.status).toBe(403);
        expect(response.headers.get("WWW-Authenticate") ?? "").toContain(
          'error="insufficient_scope"',
        );
      }
    });
  });
});

