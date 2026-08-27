import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthplaneClient, VerifiedClaims, type AuthplaneResource } from "@authplane/sdk/core";

import { authplaneMcpAuth } from "../src/auth.js";

describe("authplaneMcpAuth integration", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serves PRM and enforces bearer auth middleware", async () => {
    const claims = new VerifiedClaims({
      sub: "user_123",
      clientId: "client_456",
      scopes: ["tools/add_numbers"],
      issuer: "https://auth.example.com",
      audience: ["https://api.example.com/mcp"],
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
      verify: vi.fn(async () => claims),
      prmResponse: vi.fn(() => ({
        resource: "https://api.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools/add_numbers"],
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

    const auth = await authplaneMcpAuth({
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
      scopes: ["tools/add_numbers"],
      requiredScopes: ["tools/add_numbers"],
    });

    const app = express();
    app.use(express.json());
    app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);
    app.post("/mcp", auth.bearerAuth, (req, res) => {
      res.json({
        ok: true,
        clientId: req.auth?.clientId,
        scopes: req.auth?.scopes ?? [],
      });
    });

    const prmRes = await request(app).get(auth.protectedResourceMetadataPath);
    expect(prmRes.status).toBe(200);
    expect(prmRes.body.resource).toBe("https://api.example.com/mcp");

    const unauthorized = await request(app).post("/mcp").send({ ping: true });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers["www-authenticate"]).toContain("Bearer");
    expect(unauthorized.headers["www-authenticate"]).toContain(
      'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"'
    );

    const ok = await request(app)
      .post("/mcp")
      .set("Authorization", "Bearer valid_jwt")
      .send({ ping: true });

    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({
      ok: true,
      clientId: "client_456",
      scopes: ["tools/add_numbers"],
    });
  });

  it("defaults scopes and requiredScopes to empty arrays", async () => {
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

    const options = {
      issuer: "https://auth.example.com",
      resource: "https://api.example.com/mcp",
    };

    await authplaneMcpAuth(options);

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        issuer: "https://auth.example.com",
      }),
    );
    expect(mockClient.resource).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: "https://api.example.com/mcp",
        scopes: [],
      }),
    );
  });
});
