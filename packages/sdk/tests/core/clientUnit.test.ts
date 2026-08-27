import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK } from "jose";

import { AuthplaneClient } from "../../src/core/client.js";
import type { TokenExchangeOptions, TokenResponse } from "../../src/auth/oauth/types.js";

function readRequestBody(req: import("node:http").IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function urlSearchParamsBody(body: string): URLSearchParams {
  return new URLSearchParams(body);
}

function okTokenResponse(overrides: Partial<TokenResponse> = {}): Record<string, unknown> {
  return {
    access_token: overrides.accessToken ?? "at_ok",
    token_type: overrides.tokenType ?? "Bearer",
    expires_in: overrides.expiresIn ?? 3600,
    scope: overrides.scope ?? (overrides.scope === "" ? "" : "tools/echo"),
    refresh_token: overrides.refreshToken ?? "",
    issued_token_type:
      overrides.issuedTokenType ?? "urn:ietf:params:oauth:token-type:access_token",
  };
}

describe("AuthplaneClient unit (metadata, basic auth, cache hit)", () => {
  it("covers clientCredentials, exchange, introspect, revoke and cache", async () => {
    const { publicKey } = await generateKeyPair("RS256");
    const jwk: Record<string, unknown> = {
      ...(await exportJWK(publicKey)),
      kid: "kid_1",
      alg: "RS256",
      use: "sig",
    };

    const asServer = createServer();
    let tokenRequests = 0;

    asServer.on("request", async (req, res) => {
      try {
        if (!req.url) {
          res.statusCode = 404;
          res.end();
          return;
        }

        if (req.method === "GET" && req.url === "/.well-known/oauth-authorization-server") {
          res.setHeader("content-type", "application/json");
          res.setHeader("cache-control", "public, max-age=60");
          res.end(
            JSON.stringify({
              issuer: `http://127.0.0.1:${(asServer.address() as AddressInfo).port}`,
              jwks_uri: `http://127.0.0.1:${(asServer.address() as AddressInfo).port}/.well-known/jwks.json`,
              token_endpoint: `http://127.0.0.1:${(asServer.address() as AddressInfo).port}/oauth/token`,
              introspection_endpoint: `http://127.0.0.1:${(asServer.address() as AddressInfo).port}/oauth/introspect`,
              revocation_endpoint: `http://127.0.0.1:${(asServer.address() as AddressInfo).port}/oauth/revoke`,
            }),
          );
          return;
        }

        if (req.method === "GET" && req.url === "/.well-known/jwks.json") {
          res.setHeader("content-type", "application/json");
          res.setHeader("cache-control", "public, max-age=60");
          res.end(JSON.stringify({ keys: [jwk] }));
          return;
        }

        if (req.method === "POST" && req.url === "/oauth/token") {
          tokenRequests += 1;

          const body = await readRequestBody(req);
          const params = urlSearchParamsBody(body);

          const grantType = params.get("grant_type") ?? "";
          const scope = params.get("scope") ?? "";

          const tokenResp = (() => {
            if (grantType === "client_credentials") {
              return okTokenResponse({
                accessToken: `at_client_${tokenRequests}`,
                scope: scope || "tools/echo",
              });
            }

            if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
              const exchangeScope = params.get("scope") ?? (scope || "tools/echo");
              return okTokenResponse({
                accessToken: `at_exchange_${tokenRequests}`,
                scope: exchangeScope || "tools/echo",
              });
            }

            return okTokenResponse({ accessToken: `at_unknown_${tokenRequests}` });
          })();

          // Basic auth is set via AuthplaneClient.basicAuthHeader; validate it exists.
          const authHeader = req.headers.authorization;
          expect(typeof authHeader).toBe("string");
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify(tokenResp));
          return;
        }

        if (req.method === "POST" && req.url === "/oauth/introspect") {
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              active: true,
              scope: "tools/echo",
              client_id: "client_1",
              sub: "sub_1",
              token_type: "Bearer",
              iss: "issuer_1",
              exp: 1700000000,
              iat: 1700000000,
              jti: "jti_1",
              agent_id: "",
              agent_chain: [],
            }),
          );
          return;
        }

        if (req.method === "POST" && req.url === "/oauth/revoke") {
          // revokeToken expects non-error status.
          res.statusCode = 200;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({}));
          return;
        }

        res.statusCode = 404;
        res.end();
      } catch (e) {
        res.statusCode = 500;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: String(e) }));
      }
    });

    await new Promise<void>((resolve) => asServer.listen(0, "127.0.0.1", resolve));
    const addr = asServer.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
        auth: {
          clientId: "client_1",
          clientSecret: "secret_1",
        },
        // Make tests deterministic; we don't need refresh behavior here.
        jwksRefreshSeconds: 60,
        metadataRefreshSeconds: 60,
      });

      // Cache hit check: second call should not increase tokenRequests.
      const t1 = await client.clientCredentials(["tools/echo"]);
      const t2 = await client.clientCredentials(["tools/echo"]);
      expect(t1.accessToken).toBe(`at_client_1`);
      expect(t2.accessToken).toBe(`at_client_1`);
      expect(tokenRequests).toBe(1);

      const exchange: TokenExchangeOptions = {
        subjectToken: "st_1",
        scope: "tools/echo",
        audiences: ["aud_1"],
      };
      const exchanged = await client.exchange(exchange);
      expect(exchanged.accessToken).toMatch(/^at_exchange_/);

      const introspected = await client.introspect("some_token");
      expect(introspected.active).toBe(true);
      expect(introspected.scope).toBe("tools/echo");

      await expect(client.revoke("some_token")).resolves.toBeUndefined();
    } finally {
      await new Promise<void>((resolve) => asServer.close(() => resolve()));
    }
  });

  it("AuthplaneClient.create({ cacheMaxEntries }) honors the cap end-to-end", async () => {
    // End-to-end plumbing test: assert that the `cacheMaxEntries` option
    // actually reaches the `TokenCache` constructor (not just the
    // adapter-level forwarding the four adapter test suites already
    // pin). We mock an AS that returns distinct tokens per scope and
    // count token-endpoint hits; with `cacheMaxEntries: 2`, three
    // distinct-scope `clientCredentials` calls populate three entries —
    // the LRU (first call) must be evicted, so re-requesting it issues
    // a fresh token-endpoint hit. The most-recently-touched entry stays
    // cached (no extra hit).
    const asServer = createServer();
    let tokenRequests = 0;

    asServer.on("request", async (req, res) => {
      if (!req.url) {
        res.statusCode = 404;
        res.end();
        return;
      }
      const port = (asServer.address() as AddressInfo).port;
      if (
        req.method === "GET" &&
        req.url === "/.well-known/oauth-authorization-server"
      ) {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            issuer: `http://127.0.0.1:${port}`,
            jwks_uri: `http://127.0.0.1:${port}/.well-known/jwks.json`,
            token_endpoint: `http://127.0.0.1:${port}/oauth/token`,
          }),
        );
        return;
      }
      if (req.method === "GET" && req.url === "/.well-known/jwks.json") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ keys: [] }));
        return;
      }
      if (req.method === "POST" && req.url === "/oauth/token") {
        tokenRequests += 1;
        const body = await readRequestBody(req);
        const scope = urlSearchParamsBody(body).get("scope") ?? "";
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify(
            okTokenResponse({
              accessToken: `at_${tokenRequests}_${scope}`,
              scope,
            }),
          ),
        );
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => asServer.listen(0, "127.0.0.1", resolve));
    const addr = asServer.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
        auth: { clientId: "client_1", clientSecret: "secret_1" },
        jwksRefreshSeconds: 60,
        metadataRefreshSeconds: 60,
        cacheMaxEntries: 2,
      });

      // Populate three distinct cache entries against a cap of 2.
      await client.clientCredentials(["a"]);
      await client.clientCredentials(["b"]);
      await client.clientCredentials(["c"]);
      expect(tokenRequests).toBe(3);

      // "a" was the first inserted and has not been touched since — it
      // should be the LRU victim evicted when "c" landed. Re-requesting
      // it must hit the AS again.
      await client.clientCredentials(["a"]);
      expect(tokenRequests).toBe(4);

      // "c" is the most-recently-set entry; still in cache, no extra hit.
      await client.clientCredentials(["c"]);
      expect(tokenRequests).toBe(4);
    } finally {
      await new Promise<void>((resolve) => asServer.close(() => resolve()));
    }
  });
});

