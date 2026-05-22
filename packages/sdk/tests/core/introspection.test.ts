import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";

import { describe, expect, it } from "vitest";

import { FetchSettings, InvalidClientError, introspectToken } from "../../src/core/index.js";

describe("introspectToken (RFC 7662)", () => {
  it("parses a rich introspection response", async () => {
    const server = createServer((req, res) => {
      if (req.url === "/oauth/introspect" && req.method === "POST") {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            active: true,
            scope: "read write",
            client_id: "client_1",
            sub: "user_1",
            token_type: "access_token",
            iss: "https://auth.example.com",
            exp: 123,
            iat: 45,
            jti: "jti_1",
            agent_id: "agent_1",
            agent_chain: ["a", "b"],
          }),
        );
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      const response = await introspectToken({
        introspectionEndpoint: `${base}/oauth/introspect`,
        token: "tok_1",
        authHeader: { Authorization: "Basic abc" },
        fetchSettings: FetchSettings.fromDevMode(true),
      });

      expect(response.active).toBe(true);
      expect(response.scope).toBe("read write");
      expect(response.clientId).toBe("client_1");
      expect(response.sub).toBe("user_1");
      expect(response.tokenType).toBe("access_token");
      expect(response.iss).toBe("https://auth.example.com");
      expect(response.exp).toBe(123);
      expect(response.iat).toBe(45);
      expect(response.jti).toBe("jti_1");
      expect(response.agentId).toBe("agent_1");
      expect(response.agentChain).toEqual(["a", "b"]);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("throws on non-2xx HTTP responses", async () => {
    const server = createServer((req, res) => {
      if (req.url === "/oauth/introspect" && req.method === "POST") {
        res.statusCode = 401;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "invalid_client" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      await expect(
        introspectToken({
          introspectionEndpoint: `${base}/oauth/introspect`,
          token: "tok_1",
          fetchSettings: FetchSettings.fromDevMode(true),
        }),
      ).rejects.toBeInstanceOf(InvalidClientError);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

