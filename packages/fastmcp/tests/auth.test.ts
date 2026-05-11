import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AuthplaneClient,
  type AuthplaneResource,
  ConsentRequiredError,
  type DPoPReplayStore,
  VerifiedClaims,
} from "@authplane/sdk/core";
import { UrlElicitationRequiredError } from "@modelcontextprotocol/sdk/types.js";

import { AuthplaneTokenVerifier } from "../src/verifier.js";
import { authplaneFastMcpAuth } from "../src/auth.js";

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

  it("derives resource from baseUrl + mcpPath when resource is not set (Python alignment)", async () => {
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
        dpopRequest: {
          method: "POST",
          url: "https://api.example.com/mcp",
          proof: "dpop_proof_jwt",
        },
      }),
    );
  });

  it("DPoP (AP-412): still verifies when Host and X-Forwarded-Proto are absent — origin comes from resource, never the literal 'localhost'", async () => {
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

  it("DPoP (AP-412): array-valued Host and X-Forwarded-Proto headers do not corrupt the htu", async () => {
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

  it("DPoP (AP-412): dispatched path drives the htu — proof for /endpoint-a replayed against /endpoint-b is handed to the SDK with the actual path", async () => {
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

  it("DPoP (AP-412): default-port normalization — explicit :443 in resource is elided in the comparison URL", async () => {
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
});

