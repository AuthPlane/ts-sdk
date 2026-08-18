import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPair, exportJWK } from "jose";

import { describe, expect, it } from "vitest";

import {
  AuthplaneClient,
  CircuitOpenError,
  ServerError,
} from "../../src/core/index.js";

type TokenHandler = (req: import("node:http").IncomingMessage) => Promise<{
  statusCode: number;
  json: Record<string, unknown>;
}>;

async function startFullServer(
  params: {
    tokenHandler: TokenHandler;
    introspectActive?: boolean;
    revokeStatusCode?: number;
  },
): Promise<{ server: Server; base: string }> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk: Record<string, unknown> = {
    ...(await exportJWK(publicKey)),
    kid: "kid_1",
    alg: "RS256",
    use: "sig",
  };

  const server = createServer(async (req, res) => {
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

    if (req.method === "POST" && req.url === "/oauth/introspect") {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          active: params.introspectActive ?? true,
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
      res.statusCode = params.revokeStatusCode ?? 200;
      res.setHeader("content-type", "application/json");
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.end(
          JSON.stringify({
            error: "invalid_request",
            error_description: "bad",
          }),
        );
        return;
      }
      res.end(JSON.stringify({}));
      return;
    }

    res.statusCode = 404;
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;

  void privateKey; // private key is used only to validate server JWKS expectations
  return { server, base };
}

describe("AuthplaneClient more branches", () => {
  it("covers resource(), prmResponse(), and prmDocumentUrl() via returned AuthplaneResource", async () => {
    const serverData = await startFullServer({
      tokenHandler: async () => ({
        statusCode: 200,
        json: { access_token: "at", token_type: "Bearer", expires_in: 10, scope: "" },
      }),
    });

    const { server, base } = serverData;
    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
        auth: { clientId: "client_1", clientSecret: "secret_1" },
        metadataRefreshSeconds: 60,
        jwksRefreshSeconds: 60,
      });

      const resource = client.resource({
        resource: `${base}/mcp`,
        scopes: ["tools/echo"],
      });

      expect(resource.prmResponse().scopes_supported).toEqual(["tools/echo"]);
      expect(resource.prmDocumentUrl()).toBe(
        `${base}/.well-known/oauth-protected-resource/mcp`,
      );
      await resource.close();
      await client.close();
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("throws 'client not initialized' when metadataCache is missing (all entrypoints)", async () => {
    const serverData = await startFullServer({
      tokenHandler: async () => ({
        statusCode: 200,
        json: { access_token: "at", token_type: "Bearer", expires_in: 10, scope: "" },
      }),
    });

    const { server, base } = serverData;
    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
        auth: { clientId: "client_1", clientSecret: "secret_1" },
        metadataRefreshSeconds: 60,
        jwksRefreshSeconds: 60,
      });

      // No public API invalidates the cached AS metadata; reach the private
      // field through the narrowest shape that names it.
      (client as unknown as { metadataCache: unknown }).metadataCache = undefined;

      await expect(client.clientCredentials(["tools/echo"])).rejects.toThrow(
        /authplane: client not initialized/,
      );
      await expect(
        client.exchange({ subjectToken: "st_1" }),
      ).rejects.toThrow(/authplane: client not initialized/);
      await expect(client.revoke("some_token")).rejects.toThrow(
        /authplane: client not initialized/,
      );
      await expect(client.introspect("some_token")).rejects.toThrow(
        /authplane: client not initialized/,
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("covers exchange() and revoke() error catch blocks", async () => {
    const serverData = await startFullServer({
      tokenHandler: async () => {
        return {
          statusCode: 503,
          json: { error: "server_error", error_description: "unavailable" },
        };
      },
      revokeStatusCode: 503,
    });

    const { server, base } = serverData;
    try {
      const client = await AuthplaneClient.create({
        issuer: base,
        devMode: true,
        auth: { clientId: "client_1", clientSecret: "secret_1" },
        circuitBreakerThreshold: 2,
        circuitBreakerCooldownSeconds: 60,
        metadataRefreshSeconds: 60,
        jwksRefreshSeconds: 60,
      });

      await expect(
        client.exchange({ subjectToken: "st_1" }),
      ).rejects.toBeInstanceOf(ServerError);

      await expect(client.revoke("some_token")).rejects.toBeInstanceOf(
        ServerError,
      );

      // Two infra failures (threshold=2) open the circuit before clientCredentials runs.
      await expect(
        client.clientCredentials(["tools/echo"]),
      ).rejects.toBeInstanceOf(
        CircuitOpenError,
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

