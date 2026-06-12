import { describe, expect, it, vi, afterEach } from "vitest";
import {
  AuthplaneClient,
  type AuthplaneResource,
  TokenExpired,
} from "@authplane/sdk/core";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { AuthplaneTokenVerifier } from "../src/verifier.js";
import { authplaneMcpAuth } from "../src/auth.js";

type MockReq = {
  headers: Record<string, string | string[] | undefined>;
  method?: string;
  protocol?: string;
  originalUrl?: string;
  url?: string;
  auth?: AuthInfo;
};

type MockRes = {
  statusCode: number;
  headers: Record<string, string>;
  body: unknown;
  set: (name: string, value: string) => MockRes;
  status: (code: number) => MockRes;
  json: (payload: unknown) => MockRes;
};

function createRes(): MockRes {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,
    set(name, value) {
      this.headers[name] = value;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

describe("authplaneMcpAuth bearerAuth middleware", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function buildAuth(
    overrides: Partial<Parameters<typeof authplaneMcpAuth>[0]> = {},
  ) {
    const mockResource = {
      verify: vi.fn(),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add", "tools/multiply"],
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

    return authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add", "tools/multiply"],
      requiredScopes: ["tools/add", "tools/multiply"],
      ...overrides,
    });
  }

  it("returns 401 when Authorization header is missing", async () => {
    const auth = await buildAuth();
    const req: MockReq = { headers: {} };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(401);
    const challenge = res.headers["WWW-Authenticate"];
    expect(challenge).toContain('error="invalid_token"');
    expect(challenge).toContain('scope="tools/add tools/multiply"');
    expect(challenge).toContain("resource_metadata=");
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 when token misses configured requiredScopes", async () => {
    const auth = await buildAuth();
    vi.spyOn(
      AuthplaneTokenVerifier.prototype,
      "verifyAccessTokenWithDpop",
    ).mockResolvedValue({
      token: "jwt",
      clientId: "client_1",
      scopes: ["tools/add"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
      },
      method: "POST",
      protocol: "https",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(403);
    const challenge = res.headers["WWW-Authenticate"];
    expect(challenge).toContain('error="insufficient_scope"');
    expect(challenge).toContain('scope="tools/add tools/multiply"');
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 500 on unexpected verifier error", async () => {
    const auth = await buildAuth();
    vi.spyOn(
      AuthplaneTokenVerifier.prototype,
      "verifyAccessTokenWithDpop",
    ).mockRejectedValue(new Error("unexpected verifier failure"));

    const req: MockReq = {
      headers: { authorization: "Bearer token-1" },
      method: "POST",
      protocol: "https",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual(
      expect.objectContaining({
        error: "server_error",
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("accepts a DPoP-scheme Authorization header (RFC 9449 §7.1 — parity with hono/nestjs/fastmcp)", async () => {
    // Before this PR the middleware split the Authorization header
    // inline and required `scheme === "bearer"`, so a client that
    // (correctly per RFC 9449 §7.1) presented its DPoP-bound token
    // under the `DPoP` scheme got a 401 here while
    // `@authplane/hono` / `@authplane/nestjs` / `@authplane/fastmcp`
    // accepted it. Routing through core's `extractBearerToken` —
    // which accepts both `Bearer` and `DPoP` — closes that latent
    // interop divergence.
    const auth = await buildAuth();
    vi.spyOn(
      AuthplaneTokenVerifier.prototype,
      "verifyAccessTokenWithDpop",
    ).mockResolvedValue({
      token: "jwt",
      clientId: "client_1",
      scopes: ["tools/add", "tools/multiply"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    });

    const req: MockReq = {
      headers: { authorization: "DPoP token-1" },
      method: "POST",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(200);
  });

  it("passes request, attaches auth info, and forwards DPoP context built from the configured resource origin", async () => {
    const auth = await buildAuth();
    const verifySpy = vi
      .spyOn(AuthplaneTokenVerifier.prototype, "verifyAccessTokenWithDpop")
      .mockResolvedValue({
        token: "jwt",
        clientId: "client_1",
        scopes: ["tools/add", "tools/multiply"],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "proof-abc",
        host: "api.example.com",
        "x-forwarded-proto": "https",
      },
      method: "POST",
      protocol: "http",
      originalUrl: "/mcp?x=1",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.auth).toEqual(
      expect.objectContaining({
        clientId: "client_1",
      }),
    );
    expect(verifySpy).toHaveBeenCalledWith(
      "token-1",
      expect.objectContaining({
        method: "POST",
        url: "https://api.example.com/mcp?x=1",
        proofs: ["proof-abc"],
      }),
    );
  });

  it("returns 401 with 'Bearer TOKEN' message on unknown scheme", async () => {
    const auth = await buildAuth();
    const req: MockReq = { headers: { authorization: "Basic abc" } };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(401);
    expect((res.body as { error_description: string }).error_description).toMatch(
      /expected 'Bearer TOKEN'/,
    );
  });

  it("returns 401 when authorization header is an array (multiple values)", async () => {
    const auth = await buildAuth();
    const req: MockReq = {
      headers: { authorization: ["Bearer a", "Bearer b"] },
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(401);
  });

  it("returns 401 when the core verifier surfaces TokenExpired", async () => {
    // Expiry enforcement lives in core `AuthplaneResource.verify()` — it
    // honors the configured `clockSkewSeconds` tolerance and throws
    // `TokenExpired` for stale tokens. The middleware used to re-check
    // `authInfo.expiresAt < Date.now()/1000` *without* skew tolerance,
    // which could reject tokens core deemed valid. This test
    // pins the new behavior: the middleware passes the error through
    // the standard catch → `wwwAuthenticate` + `httpStatus(401)` path
    // and emits an RFC 6750 challenge instead of doing its own
    // duplicate timing check.
    const auth = await buildAuth();
    vi.spyOn(
      AuthplaneTokenVerifier.prototype,
      "verifyAccessTokenWithDpop",
    ).mockRejectedValue(new TokenExpired("Token has expired"));

    const req: MockReq = {
      headers: { authorization: "Bearer token-1" },
      method: "POST",
      protocol: "https",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(401);
    const challenge = res.headers["WWW-Authenticate"] ?? "";
    expect(challenge).toMatch(/^Bearer /);
    expect(challenge).toContain('error="invalid_token"');
    expect((res.body as { error_description: string }).error_description).toMatch(
      /expired/,
    );
  });

  it("rejects requests carrying two DPoP headers delivered as a string[] (raw-headers shape)", async () => {
    // The `string[]` shape lands in `req.headers` when callers reach for
    // `req.rawHeaders` or hand-build the bag — it's NOT what Node's
    // default `http.IncomingMessage.headers` produces (see the
    // comma-folded test below). `extractDpopHeaderValues` still has to
    // handle both because adapters in the wild surface either; the core
    // factory raises `MultipleDPoPProofs` for §4.3 violations. The
    // middleware must surface 401 with a `DPoP`-scheme challenge and
    // never invoke the token verifier — no JWKS lookup should occur for
    // a request the boundary already rejected.
    const auth = await buildAuth();
    const verifySpy = vi.spyOn(
      AuthplaneTokenVerifier.prototype,
      "verifyAccessTokenWithDpop",
    );

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: ["eyJ.first", "eyJ.second"],
      },
      method: "POST",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(401);
    const challenge = res.headers["WWW-Authenticate"] ?? "";
    expect(challenge).toMatch(/^DPoP /);
    // RFC 9449 §7.1: §4.3 rejections carry invalid_dpop_proof, not the
    // SDK's historical invalid_token used by the other DPoPError shapes.
    expect(challenge).toContain('error="invalid_dpop_proof"');
    expect(verifySpy).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects requests carrying two DPoP headers delivered as a comma-folded string (real Node shape)", async () => {
    // `http.IncomingMessage.headers` only arrays a fixed allow-list
    // (`set-cookie`, etc.); everything else is comma-folded — so two
    // `DPoP` headers on the wire actually arrive in `req.headers.dpop`
    // as the single string `"proofA, proofB"`. This is the path real
    // Node traffic hits; the array case above exercises a hand-built
    // / raw-headers fixture. The core factory's comma-split catches
    // the folded shape because JWS compact serialisation is
    // base64url + `.` and never contains a literal `,`, so any comma
    // must be a merged duplicate.
    const auth = await buildAuth();
    const verifySpy = vi.spyOn(
      AuthplaneTokenVerifier.prototype,
      "verifyAccessTokenWithDpop",
    );

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "eyJ.first, eyJ.second",
      },
      method: "POST",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(res.statusCode).toBe(401);
    const challenge = res.headers["WWW-Authenticate"] ?? "";
    expect(challenge).toMatch(/^DPoP /);
    expect(challenge).toContain('error="invalid_dpop_proof"');
    expect(verifySpy).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("ignores spoofed Host and X-Forwarded-Proto headers, uses configured resource origin", async () => {
    const auth = await buildAuth();
    const verifySpy = vi
      .spyOn(AuthplaneTokenVerifier.prototype, "verifyAccessTokenWithDpop")
      .mockResolvedValue({
        token: "jwt",
        clientId: "client_1",
        scopes: ["tools/add", "tools/multiply"],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "proof",
        host: "attacker.example.com",
        "x-forwarded-proto": "http",
      },
      method: "POST",
      protocol: "http",
      url: "/mcp/sub",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(verifySpy).toHaveBeenCalledWith(
      "token-1",
      expect.objectContaining({ url: "https://api.example.com/mcp/sub" }),
    );
  });

  it("still verifies when Host header is absent — origin comes from resource", async () => {
    const auth = await buildAuth();
    const verifySpy = vi
      .spyOn(AuthplaneTokenVerifier.prototype, "verifyAccessTokenWithDpop")
      .mockResolvedValue({
        token: "jwt",
        clientId: "client_1",
        scopes: ["tools/add", "tools/multiply"],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "proof",
        // no host, no x-forwarded-proto, no req.protocol — before the htu-origin fix this
        // collapsed to `http://localhost/mcp`.
      },
      method: "POST",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(verifySpy).toHaveBeenCalledWith(
      "token-1",
      expect.objectContaining({ url: "https://api.example.com/mcp" }),
    );
  });

  it("never produces the 'localhost' literal even when Host header is an array", async () => {
    const auth = await buildAuth();
    const verifySpy = vi
      .spyOn(AuthplaneTokenVerifier.prototype, "verifyAccessTokenWithDpop")
      .mockResolvedValue({
        token: "jwt",
        clientId: "client_1",
        scopes: ["tools/add", "tools/multiply"],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "proof",
        host: ["a.example.com", "b.example.com"],
      },
      method: "POST",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    const passedUrl = (
      verifySpy.mock.calls[0]?.[1] as { url: string } | undefined
    )?.url;
    expect(passedUrl).toBe("https://api.example.com/mcp");
    expect(passedUrl).not.toContain("localhost");
  });

  it("falls back to the resource pathname when both originalUrl and url are absent", async () => {
    const auth = await buildAuth();
    const verifySpy = vi
      .spyOn(AuthplaneTokenVerifier.prototype, "verifyAccessTokenWithDpop")
      .mockResolvedValue({
        token: "jwt",
        clientId: "client_1",
        scopes: ["tools/add", "tools/multiply"],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "proof",
      },
      method: "POST",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(verifySpy).toHaveBeenCalledWith(
      "token-1",
      expect.objectContaining({ url: "https://api.example.com/mcp" }),
    );
  });

  it("dispatched path drives the htu — a proof minted for /endpoint-a hits the SDK with /endpoint-b on a cross-endpoint replay", async () => {
    const auth = await buildAuth();
    const verifySpy = vi
      .spyOn(AuthplaneTokenVerifier.prototype, "verifyAccessTokenWithDpop")
      .mockResolvedValue({
        token: "jwt",
        clientId: "client_1",
        scopes: ["tools/add", "tools/multiply"],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "proof-originally-for-endpoint-a",
      },
      method: "POST",
      originalUrl: "/endpoint-b",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    expect(verifySpy).toHaveBeenCalledWith(
      "token-1",
      expect.objectContaining({
        url: "https://api.example.com/endpoint-b",
      }),
    );
  });

  it("default-port normalization — explicit :443 in resource is elided in the comparison URL", async () => {
    // Configuring `resource` with the explicit default HTTPS port must not
    // leak ":443" into the comparison URL, otherwise the adapter would
    // require its own port-normalizer in addition to the SDK's
    // `normalizeHtu`. We rely on `URL.host` to elide default ports.
    const auth = await buildAuth({
      resource: "https://api.example.com:443/mcp",
    });
    const verifySpy = vi
      .spyOn(AuthplaneTokenVerifier.prototype, "verifyAccessTokenWithDpop")
      .mockResolvedValue({
        token: "jwt",
        clientId: "client_1",
        scopes: ["tools/add", "tools/multiply"],
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

    const req: MockReq = {
      headers: {
        authorization: "Bearer token-1",
        dpop: "proof",
      },
      method: "POST",
      originalUrl: "/mcp",
    };
    const res = createRes();
    const next = vi.fn();

    await auth.bearerAuth(req as never, res as never, next);

    const passedUrl = (
      verifySpy.mock.calls[0]?.[1] as { url: string } | undefined
    )?.url;
    expect(passedUrl).toBe("https://api.example.com/mcp");
    expect(passedUrl).not.toContain(":443");
  });

});
