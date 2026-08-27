import {
  type AuthplaneResource,
  CircuitOpenError,
  InsufficientScope,
  InvalidClaims,
  JWKSFetchError,
  MetadataFetchError,
  TokenExpired,
  VerifiedClaims,
  VerifierRuntimeError,
} from "@authplane/sdk/core";
import {
  InsufficientScopeError,
  InvalidTokenError,
  ServerError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { describe, expect, it, vi } from "vitest";

import { AuthplaneTokenVerifier } from "../src/verifier.js";

const RESOURCE_METADATA_URL =
  "https://api.example.com/.well-known/oauth-protected-resource/mcp";

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

function claimsWith(
  overrides: { scopes?: string[]; audience?: string[] } = {},
) {
  return new VerifiedClaims({
    sub: "user_123",
    clientId: "client_456",
    scopes: overrides.scopes ?? ["tools/add"],
    issuer: "https://auth.example.com",
    audience: overrides.audience ?? ["https://api.example.com/mcp"],
    // Far future so the SDK middleware's own expiry re-check passes.
    expiresAt: 4_102_444_800,
    issuedAt: 1_699_999_000,
    jti: "token_123",
    kid: "key_1",
    agentId: "",
    agentChain: [],
    notBefore: 0,
    raw: { sub: "user_123" },
  });
}

function resourceThatThrows(error: unknown): AuthplaneResource {
  return {
    verify: vi.fn(async () => {
      throw error;
    }),
  } as unknown as AuthplaneResource;
}

/**
 * Runs the stock MCP SDK `requireBearerAuth` middleware with our
 * `AuthplaneTokenVerifier` plugged in as the `OAuthTokenVerifier` — the
 * exact wiring `authplaneMcpAuth().tokenVerifier` is documented for.
 */
async function runStockMiddleware(
  verifier: AuthplaneResource,
  options: { requiredScopes?: string[] } = {},
) {
  const middleware = requireBearerAuth({
    verifier: new AuthplaneTokenVerifier(verifier),
    requiredScopes: options.requiredScopes ?? [],
    resourceMetadataUrl: RESOURCE_METADATA_URL,
  });
  const req = { headers: { authorization: "Bearer some_token" } };
  const res = createRes();
  const next = vi.fn();
  // biome-ignore lint/suspicious/noExplicitAny: express req/res mocks
  await middleware(req as any, res as any, next);
  return { res, next };
}

describe("AuthplaneTokenVerifier inside the stock requireBearerAuth", () => {
  it("turns an expired token into 401 with a resource_metadata challenge", async () => {
    const { res, next } = await runStockMiddleware(
      resourceThatThrows(new TokenExpired()),
    );

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toContain(
      `resource_metadata="${RESOURCE_METADATA_URL}"`,
    );
    expect(res.headers["WWW-Authenticate"]).toContain('error="invalid_token"');
    expect(res.body).toMatchObject({ error: "invalid_token" });
  });

  it("turns an audience mismatch into 401", async () => {
    const { res } = await runStockMiddleware(
      resourceThatThrows(new InvalidClaims("Token audience is not allowed.")),
    );

    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toContain('error="invalid_token"');
  });

  it("turns a missing scope into 403 insufficient_scope", async () => {
    const { res } = await runStockMiddleware(
      resourceThatThrows(new InsufficientScope()),
    );

    expect(res.statusCode).toBe(403);
    expect(res.headers["WWW-Authenticate"]).toContain(
      'error="insufficient_scope"',
    );
    expect(res.body).toMatchObject({ error: "insufficient_scope" });
  });

  it("still lets the middleware's own scope check produce 403", async () => {
    const verifier = {
      verify: vi.fn(async () => claimsWith({ scopes: ["tools/add"] })),
    } as unknown as AuthplaneResource;

    const { res } = await runStockMiddleware(verifier, {
      requiredScopes: ["tools/delete"],
    });

    expect(res.statusCode).toBe(403);
  });

  it.each([
    ["JWKS unreachable", new JWKSFetchError()],
    ["AS metadata unreachable", new MetadataFetchError()],
    ["circuit breaker open", new CircuitOpenError()],
    ["verifier runtime failure", new VerifierRuntimeError()],
  ])("turns %s into 500 without a challenge", async (_label, error) => {
    const { res } = await runStockMiddleware(resourceThatThrows(error));

    expect(res.statusCode).toBe(500);
    expect(res.headers["WWW-Authenticate"]).toBeUndefined();
    expect(res.body).toMatchObject({
      error: "server_error",
      // Generic by design: the SDK copies the message into the body of an
      // unauthenticated response, so core's detailed 5xx text must not leak.
      error_description: "Authorization server temporarily unavailable",
    });
  });

  it("passes a valid token through to next()", async () => {
    const verifier = {
      verify: vi.fn(async () => claimsWith()),
    } as unknown as AuthplaneResource;

    const { res, next } = await runStockMiddleware(verifier, {
      requiredScopes: ["tools/add"],
    });

    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(200);
  });

  it("emits a parseable WWW-Authenticate even when the core message contains quotes", async () => {
    // `resource.verify()` embeds jose's message on expiry, and jose quotes
    // claim names (`"exp" claim timestamp check failed`). The SDK's header
    // builder splices `error_description` in unsanitised, so an unescaped
    // quote would terminate the parameter early and break the challenge
    // clients rely on for discovery.
    const { res } = await runStockMiddleware(
      resourceThatThrows(
        new TokenExpired('Token has expired: "exp" claim timestamp check\r\n'),
      ),
    );

    const header = res.headers["WWW-Authenticate"] as string;
    expect(res.statusCode).toBe(401);
    expect(header).not.toContain('"exp"');
    expect(header).not.toMatch(/[\r\n]/);
    // The trailing parameters must survive the splice.
    expect(header).toContain(`resource_metadata="${RESOURCE_METADATA_URL}"`);
    // Exactly three quoted params — error, error_description,
    // resource_metadata — so no quote leaked out of the message.
    expect(header.match(/"/g)?.length).toBe(6);
  });

  it("throws errors that are instanceof the host's SDK classes (dual-package guard)", async () => {
    const cases: Array<[unknown, unknown]> = [
      [new TokenExpired(), InvalidTokenError],
      [new InsufficientScope(), InsufficientScopeError],
      [new JWKSFetchError(), ServerError],
    ];

    for (const [thrown, expected] of cases) {
      const adapter = new AuthplaneTokenVerifier(resourceThatThrows(thrown));
      await expect(adapter.verifyAccessToken("t")).rejects.toBeInstanceOf(
        expected as never,
      );
    }
  });
});
