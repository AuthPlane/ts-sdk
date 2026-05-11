import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { generateKeyPair, exportJWK } from "jose";

import { describe, expect, it } from "vitest";

import {
  AuthplaneClient,
  CircuitOpenError,
  InvalidGrantError,
  ServerError,
} from "../../src/core/index.js";

async function startDiscoveryAndJwksServer(
  params: {
    tokenHandler: (req: import("node:http").IncomingMessage) => Promise<{
      statusCode: number;
      json: Record<string, unknown>;
    }>;
  },
): Promise<{ server: Server; base: string }> {
  const { publicKey } = await generateKeyPair("RS256");
  const jwk = (await exportJWK(publicKey)) as Record<string, unknown>;
  jwk.kid = "kid_1";
  jwk.alg = "RS256";
  jwk.use = "sig";

  const server = createServer(async (req, res) => {
    try {
      if (!req.url) {
        res.statusCode = 404;
        res.end();
        return;
      }

      if (req.method === "GET" && req.url === "/.well-known/oauth-authorization-server") {
        res.setHeader("content-type", "application/json");
        const addr = server.address() as AddressInfo;
        const base = `http://127.0.0.1:${addr.port}`;
        res.end(
          JSON.stringify({
            issuer: base,
            jwks_uri: `${base}/.well-known/jwks.json`,
            token_endpoint: `${base}/oauth/token`,
            introspection_endpoint: `${base}/oauth/introspect`,
            revocation_endpoint: `${base}/oauth/revoke`,
          }),
        );
        return;
      }

      if (req.method === "GET" && req.url === "/.well-known/jwks.json") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ keys: [jwk] }));
        return;
      }

      if (req.method === "POST" && req.url === "/oauth/token") {
        const tokenResp = await params.tokenHandler(req);
        res.statusCode = tokenResp.statusCode;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(tokenResp.json));
        return;
      }

      // Not used in these tests
      res.statusCode = 404;
      res.end();
    } catch (e) {
      res.statusCode = 500;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: String(e) }));
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;
  return { server, base };
}

describe("AuthplaneClient branches", () => {
  it("does not send Authorization header when auth is undefined", async () => {
    let sawAuthHeader: string | undefined;

    const serverAndBase = await startDiscoveryAndJwksServer({
      tokenHandler: async (req) => {
        sawAuthHeader = req.headers.authorization as string | undefined;
        return {
          statusCode: 200,
          json: {
            access_token: "at_no_auth",
            token_type: "Bearer",
            expires_in: 60,
            scope: "",
            // Ensure tokenResponseParsing doesn't reject optional fields
            issued_token_type: "",
          },
        };
      },
    });

    const { server, base } = serverAndBase;
    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
      });

      const token = await client.clientCredentials(["tools/echo"]);
      expect(token.accessToken).toBe("at_no_auth");
      expect(sawAuthHeader).toBeUndefined();
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("records failures and opens circuit on repeated clientCredentials errors", async () => {
    const serverAndBase = await startDiscoveryAndJwksServer({
      tokenHandler: async () => {
        return {
          statusCode: 503,
          json: {
            error: "server_error",
            error_description: "unavailable",
          },
        };
      },
    });

    const { server, base } = serverAndBase;
    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
        auth: {
          clientId: "client_1",
          clientSecret: "secret_1",
        },
        circuitBreakerThreshold: 1,
        circuitBreakerCooldownSeconds: 30,
        jwksRefreshSeconds: 60,
        metadataRefreshSeconds: 60,
      });

      await expect(client.clientCredentials(["tools/echo"])).rejects.toBeInstanceOf(
        ServerError,
      );

      await expect(client.clientCredentials(["tools/echo"])).rejects.toBeInstanceOf(
        CircuitOpenError,
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("does not open circuit on repeated invalid_grant from clientCredentials", async () => {
    const serverAndBase = await startDiscoveryAndJwksServer({
      tokenHandler: async () => {
        return {
          statusCode: 400,
          json: {
            error: "invalid_grant",
            error_description: "expired",
          },
        };
      },
    });

    const { server, base } = serverAndBase;
    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
        auth: {
          clientId: "client_1",
          clientSecret: "secret_1",
        },
        circuitBreakerThreshold: 1,
        circuitBreakerCooldownSeconds: 30,
        jwksRefreshSeconds: 60,
        metadataRefreshSeconds: 60,
      });

      await expect(client.clientCredentials(["tools/echo"])).rejects.toBeInstanceOf(
        InvalidGrantError,
      );
      await expect(client.clientCredentials(["tools/echo"])).rejects.toBeInstanceOf(
        InvalidGrantError,
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

