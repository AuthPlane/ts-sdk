import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { UrlElicitationRequiredError } from "@modelcontextprotocol/sdk/types.js";
import {
  AuthplaneClient,
  AuthplaneResource,
  type AuthplaneResourceOptions,
  ConsentRequiredError,
  httpStatus,
  InsufficientScope,
  wwwAuthenticate,
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
      resourceMetadataUrl: vi.fn(
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
      resourceMetadataUrl: vi.fn(
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
        resourceMetadataUrl: vi.fn(
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
      resourceMetadataUrl: vi.fn(
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
      resourceMetadataUrl: vi.fn(
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
      resourceMetadataUrl: vi.fn(
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
      resourceMetadataUrl: vi.fn(
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
      resourceMetadataUrl: vi.fn(
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

  // A plain Error reached neither `httpStatus` nor `wwwAuthenticate` — only
  // AuthplaneError instances are mapped — so an insufficient scope surfaced as
  // a JSON-RPC internal error or the generic 500 fallback, and the client
  // never saw the challenge it would step up from.
  it("throws core InsufficientScope so a host can answer 403 + challenge", () => {
    const error = (() => {
      try {
        requireScope("tools/delete_thing", undefined);
      } catch (caught) {
        return caught;
      }
      return undefined;
    })();

    expect(error).toBeInstanceOf(InsufficientScope);
    expect(httpStatus(error)).toBe(403);
    expect(wwwAuthenticate(error as InsufficientScope)).toContain(
      'error="insufficient_scope"'
    );
  });

  it("carries the missing scope into the challenge so the client knows what to ask for", () => {
    const authInfo = {
      token: "t",
      clientId: "c",
      scopes: ["tools/add"],
      expiresAt: 0,
    } as AuthInfo;

    try {
      requireScope("tools/delete_thing", authInfo);
      expect.unreachable("requireScope should have thrown");
    } catch (error) {
      expect((error as InsufficientScope).requiredScopes).toEqual([
        "tools/delete_thing",
      ]);
      expect(wwwAuthenticate(error as InsufficientScope)).toContain(
        'scope="tools/delete_thing"'
      );
    }
  });
});

/**
 * A mock client whose `resource()` calls through to the real core constructor.
 *
 * The stub clients elsewhere in this file cannot reject anything, so a test
 * built on one would pass whether or not the RFC 8707 §2 gate exists. The
 * client-owned collaborators are stubbed because the indicator gate runs first
 * in the constructor and nothing here dereferences them.
 */
function realResourceClient(): AuthplaneClient {
  return {
    resource: (options: AuthplaneResourceOptions) =>
      new AuthplaneResource({
        ...options,
        issuer: "https://auth.example.com",
        metadataCache: {},
        fetchSettings: {},
        getJwksCache: () => ({}),
      } as unknown as ConstructorParameters<typeof AuthplaneResource>[0]),
    exchange: vi.fn(),
    close: vi.fn(async () => undefined),
  } as unknown as AuthplaneClient;
}

describe("authplaneMcpAuth resource indicator (RFC 8707 §2)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects a fragment-bearing resource at setup, not per request", async () => {
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(realResourceClient());

    await expect(
      authplaneMcpAuth({
        issuer: "https://auth.example.com",
        resource: "https://api.example.com/mcp#frag",
        scopes: ["tools/add_numbers"],
      }),
    ).rejects.toThrow(/RFC 8707 §2/u);
  });

  it("rejects a relative resource at setup through the same gate", async () => {
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(realResourceClient());

    await expect(
      authplaneMcpAuth({
        issuer: "https://auth.example.com",
        resource: "/mcp",
        scopes: ["tools/add_numbers"],
      }),
    ).rejects.toThrow(/absolute URL with a scheme and a host/u);
  });

  it("builds normally for the same identifier without a fragment", async () => {
    // Guards the test above against passing vacuously on a broken harness.
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(realResourceClient());

    const auth = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add_numbers"],
    });

    expect(auth.protectedResourceMetadataPath).toBe(
      "/.well-known/oauth-protected-resource/mcp",
    );
  });
});

describe("authplaneMcpAuth query-bearing resource (RFC 9728 §3)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("registers the query-less PRM path and advertises the query-bearing document URL on the 401", async () => {
    // End-to-end through the real core derivation (`realResourceClient`):
    // route registration is path-keyed, so the mount path must shed the
    // query, while the challenge's `resource_metadata` value must carry it
    // verbatim — that URL is the one a client round-trips against the served
    // document's `resource` member (RFC 9728 §3.3).
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(realResourceClient());

    const auth = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp?tenant=a",
      scopes: ["tools/add_numbers"],
    });

    expect(auth.protectedResourceMetadataPath).toBe(
      "/.well-known/oauth-protected-resource/mcp",
    );
    expect(auth.protectedResourceMetadata.resource).toBe(
      "https://api.example.com/mcp?tenant=a",
    );

    const res = {
      statusCode: 200,
      headers: {} as Record<string, string>,
      body: undefined as unknown,
      set(name: string, value: string) {
        this.headers[name] = value;
        return this;
      },
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json(payload: unknown) {
        this.body = payload;
        return this;
      },
    };
    const next = vi.fn();
    await auth.bearerAuth({ headers: {} } as never, res as never, next);

    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toContain(
      'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a"',
    );
    expect(next).not.toHaveBeenCalled();
  });
});

describe("authplaneMcpAuth resource_metadata override (RFC 9728 §3)", () => {
  const AS_HOSTED =
    "https://auth.example.com/.well-known/oauth-protected-resource/mcp";

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function createRes() {
    return {
      statusCode: 200,
      headers: {} as Record<string, string>,
      set(name: string, value: string) {
        this.headers[name] = value;
        return this;
      },
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json() {
        return this;
      },
    };
  }

  async function buildOverridden() {
    // Real core resource, so the option travels the path it travels in
    // production: adapter option → `client.resource()` → the constructor's
    // gate → the accessor the challenge reads.
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(realResourceClient());
    return authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add_numbers"],
      requiredScopes: ["tools/add_numbers"],
      resourceMetadataUrl: AS_HOSTED,
    });
  }

  it("advertises the configured URL on the 401 while the PRM route stays derived", async () => {
    const auth = await buildOverridden();

    // The document the AS hosts is what clients are sent to; the route this
    // adapter mounts is still the local, derived one.
    expect(auth.protectedResourceMetadataUrl).toBe(AS_HOSTED);
    expect(auth.protectedResourceMetadataPath).toBe(
      "/.well-known/oauth-protected-resource/mcp",
    );

    const res = createRes();
    const next = vi.fn();
    await auth.bearerAuth({ headers: {} } as never, res as never, next);

    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toContain(
      `resource_metadata="${AS_HOSTED}"`,
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("advertises it on the 403 insufficient_scope challenge too", async () => {
    const auth = await buildOverridden();
    vi.spyOn(
      AuthplaneTokenVerifier.prototype,
      "verifyAccessTokenWithDpop",
    ).mockResolvedValue({
      token: "jwt",
      clientId: "client_1",
      scopes: [],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    });

    const res = createRes();
    const next = vi.fn();
    await auth.bearerAuth(
      {
        headers: { authorization: "Bearer token-1" },
        method: "POST",
        originalUrl: "/mcp",
      } as never,
      res as never,
      next,
    );

    expect(res.statusCode).toBe(403);
    const challenge = res.headers["WWW-Authenticate"] ?? "";
    expect(challenge).toContain('error="insufficient_scope"');
    expect(challenge).toContain(`resource_metadata="${AS_HOSTED}"`);
  });

  it("falls back to the derived URL when no override is configured", async () => {
    // Guards the tests above against passing vacuously: the same wiring with
    // the option omitted must advertise the resource-hosted document.
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(realResourceClient());

    const auth = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add_numbers"],
    });

    expect(auth.protectedResourceMetadataUrl).toBe(
      "https://api.example.com/.well-known/oauth-protected-resource/mcp",
    );
  });

  it("rejects an invalid override at setup, not per request", async () => {
    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(realResourceClient());

    await expect(
      authplaneMcpAuth({
        issuer: "https://auth.example.com",
        resource: "https://api.example.com/mcp",
        scopes: ["tools/add_numbers"],
        resourceMetadataUrl: "/.well-known/oauth-protected-resource/mcp",
      }),
    ).rejects.toThrow(/absolute URL with a scheme and a host/u);
  });
});
