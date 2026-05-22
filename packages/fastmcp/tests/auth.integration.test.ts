import net from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FastMCP, type FastMCPSessionAuth } from "fastmcp";
import {
  AuthplaneClient,
  InvalidSignature,
  VerifiedClaims,
  type AuthplaneResource,
} from "@authplane/sdk/core";

import { authplaneFastMcpAuth } from "../src/auth.js";

async function getFreePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not acquire free port"));
        return;
      }
      const port = address.port;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
    server.on("error", reject);
  });
}

async function waitForServer(baseUrl: string): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        return;
      }
    } catch {
      // Retry until server is ready.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Timed out waiting for FastMCP HTTP server");
}

describe("authplaneFastMcpAuth integration", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serves PRM metadata and enforces auth on private routes", async () => {
    const port = await getFreePort();
    const baseUrl = `http://localhost:${port}`;
    const resource = `${baseUrl}/mcp`;

    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add"],
      issuer: "https://auth.example.com",
      audience: [resource],
      expiresAt: Math.floor(Date.now() / 1000) + 60,
      issuedAt: Math.floor(Date.now() / 1000) - 10,
      jti: "token_123",
      kid: "key_1",
      agentId: "",
      agentChain: [],
      notBefore: 0,
      raw: { sub: "user_123" },
    });
    const mockResource = {
      verify: vi.fn(async (token: string) => {
        if (token === "valid_jwt") {
          return claims;
        }
        // SDK `verify()` always throws a specific subclass; the base
        // `AuthplaneError` is abstract in practice. `InvalidSignature`
        // is the realistic class for a malformed-or-tampered token.
        throw new InvalidSignature("invalid token signature");
      }),
      prmResponse: vi.fn(() => ({
        resource,
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add"],
        bearer_methods_supported: ["header"],
        resource_signing_alg_values_supported: ["RS256", "ES256"],
      })),
      prmDocumentUrl: vi.fn(
        () => `${baseUrl}/.well-known/oauth-protected-resource/mcp`,
      ),
      close: vi.fn(async () => undefined),
    } as unknown as AuthplaneResource;

    const mockClient = {
      resource: vi.fn(() => mockResource),
      exchange: vi.fn(),
    } as unknown as AuthplaneClient;

    vi.spyOn(AuthplaneClient, "create").mockResolvedValue(mockClient);

    const auth = await authplaneFastMcpAuth({
      issuer: "https://auth.example.com",
      resource,
      scopes: ["tools/add"],
    });

    const server = new FastMCP<FastMCPSessionAuth>({
      name: "integration-server",
      version: "1.0.0",
      authenticate: auth.authenticate,
      oauth: auth.oauth,
    });
    await server.start({
      transportType: "httpStream",
      httpStream: {
        port,
        endpoint: "/mcp",
      },
    });

    try {
      await waitForServer(baseUrl);

      const prmRes = await fetch(
        `${baseUrl}/.well-known/oauth-protected-resource/mcp`
      );
      const prmBody = (await prmRes.json()) as {
        resource: string;
        authorization_servers: string[];
      };
      expect(prmRes.status).toBe(200);
      expect(prmBody.resource).toBe(resource);
      expect(prmBody.authorization_servers).toEqual(["https://auth.example.com"]);

      const unauthorized = await fetch(`${baseUrl}/private`);
      expect(unauthorized.status).toBe(404);

      const unauthenticatedMcp = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      });
      expect(unauthenticatedMcp.status).toBe(401);
      expect(unauthenticatedMcp.headers.get("www-authenticate")).toContain(
        "resource_metadata="
      );

      const authenticatedMcp = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer valid_jwt",
        },
        body: JSON.stringify({}),
      });
      expect(authenticatedMcp.status).not.toBe(401);
      expect(authenticatedMcp.status).toBeGreaterThanOrEqual(400);

      const unknownToken = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer invalid_jwt",
        },
        body: JSON.stringify({}),
      });
      expect(unknownToken.status).toBe(401);
      expect(unknownToken.headers.get("www-authenticate")).toContain(
        "resource_metadata="
      );
    } finally {
      await server.stop();
      await auth.verifier.close();
    }
  });
});
