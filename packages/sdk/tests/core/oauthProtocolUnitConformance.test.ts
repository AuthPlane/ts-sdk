import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair } from "jose";

import {
  AuthplaneClient,
  FetchSettings,
  revokeToken,
  introspectToken,
} from "../../src/core/index.js";
import { InvalidClientError, ServerError } from "../../src/core/errors.js";
import { ProtocolError } from "../../src/auth/errors.js";
import { parseTokenResponse } from "../../src/auth/oauth/parsing.js";

function urlSearchParamsBody(body: string): URLSearchParams {
  return new URLSearchParams(body);
}

describe("OAuth protocol unit conformance (subset)", () => {
  it("RFC6749: token_response must contain access_token", () => {
    expect(() =>
      parseTokenResponse({
        token_type: "Bearer",
        expires_in: 10,
      }),
    ).toThrow(ProtocolError);
  });

  it("RFC6749: basic auth credentials percent-encoded before base64", async () => {
    let receivedAuthHeader: string | undefined;
    let receivedBody = "";

    const server = await startAs({
      onTokenRequest: (req) => {
        receivedAuthHeader = req.headers.authorization;
        receivedBody = req.body;
        return { statusCode: 200, json: okTokenResponse() };
      },
    });

    try {
      const as = await AuthplaneClient.create({
        issuer: server.issuer,
        devMode: true,
        auth: {
          // Use a URL-like client_id to validate percent-encoding.
          clientId: "http://localhost:8080/mcp",
          clientSecret: "s3cret",
        },
      });

      await as.clientCredentials(["read"]);

      expect(receivedAuthHeader).toMatch(/^Basic\s+/);
      const b64 = receivedAuthHeader!.slice("Basic ".length);
      const decoded = Buffer.from(b64, "base64").toString("utf-8");

      // Authplane TS uses encodeURIComponent on both clientId and secret.
      expect(decoded).toBe(
        `${encodeURIComponent("http://localhost:8080/mcp")}:${encodeURIComponent("s3cret")}`,
      );

      // grant_type is always present for client_credentials.
      const params = urlSearchParamsBody(receivedBody);
      expect(params.get("grant_type")).toBe("client_credentials");
      expect(params.get("scope")).toBe("read");
    } finally {
      await server.close();
    }
  });

  it("RFC6749: invalid_client maps to InvalidClientError", async () => {
    const server = await startAs({
      onTokenRequest: () => ({
        statusCode: 401,
        json: { error: "invalid_client", error_description: "bad creds" },
      }),
    });

    try {
      const as = await AuthplaneClient.create({
        issuer: server.issuer,
        devMode: true,
        auth: { clientId: "c", clientSecret: "s" },
      });

      await expect(as.clientCredentials(["read"])).rejects.toBeInstanceOf(
        InvalidClientError,
      );
    } finally {
      await server.close();
    }
  });

  it("RFC7009: revocation request posts token and token_type_hint=access_token", async () => {
    let receivedBody = "";
    let receivedAuthHeader: string | undefined;

    const server = await startRevokeEndpoint({
      onRevoke: (req) => {
        receivedBody = req.body;
        receivedAuthHeader = req.headers.authorization;
        return { statusCode: 200, json: {} };
      },
    });

    try {
      await revokeToken({
        revocationEndpoint: `${server.base}/oauth/revoke`,
        token: "token_to_revoke",
        authHeader: {},
        fetchSettings: FetchSettings.fromDevMode(true),
      });

      const params = urlSearchParamsBody(receivedBody);
      expect(params.get("token")).toBe("token_to_revoke");
      expect(params.get("token_type_hint")).toBe("access_token");
      expect(receivedAuthHeader).toBeUndefined();
    } finally {
      await server.close();
    }
  });

  it("RFC7009: revocation server errors surface as ServerError", async () => {
    const server = await startRevokeEndpoint({
      onRevoke: () => ({
        statusCode: 500,
        json: { error: "server_error", error_description: "boom" },
      }),
    });

    try {
      await expect(
        revokeToken({
          revocationEndpoint: `${server.base}/oauth/revoke`,
          token: "token_to_revoke",
          authHeader: {},
          fetchSettings: FetchSettings.fromDevMode(true),
        }),
      ).rejects.toBeInstanceOf(ServerError);
    } finally {
      await server.close();
    }
  });

  it("RFC7009: revocation 200 is success even if already invalid", async () => {
    const server = await startRevokeEndpoint({
      onRevoke: () => ({ statusCode: 200, json: {} }),
    });

    try {
      await expect(
        revokeToken({
          revocationEndpoint: `${server.base}/oauth/revoke`,
          token: "already-invalid-token",
          authHeader: {},
          fetchSettings: FetchSettings.fromDevMode(true),
        }),
      ).resolves.toBeUndefined();
    } finally {
      await server.close();
    }
  });

  it("RFC7662: introspection without credentials must not send Authorization header", async () => {
    let receivedAuthHeader: string | undefined;
    let receivedBody = "";

    const server = await startIntrospectionEndpoint({
      onIntrospect: (req) => {
        receivedAuthHeader = req.headers.authorization;
        receivedBody = req.body;
        return {
          statusCode: 200,
          json: { active: false, scope: "", client_id: "c", sub: "s", token_type: "access_token", iss: "iss", exp: 1, iat: 1, jti: "j" },
        };
      },
    });

    try {
      const res = await introspectToken({
        introspectionEndpoint: `${server.base}/oauth/introspect`,
        token: "raw-token",
        fetchSettings: FetchSettings.fromDevMode(true),
      });

      expect(res.active).toBe(false);
      const params = urlSearchParamsBody(receivedBody);
      expect(params.get("token")).toBe("raw-token");
      expect(params.get("token_type_hint")).toBe("access_token");
      expect(receivedAuthHeader).toBeUndefined();
    } finally {
      await server.close();
    }
  });

  it("RFC7662: introspection active=false parses as inactive; missing active defaults to inactive", async () => {
    const server = await startIntrospectionEndpoint({
      onIntrospect: (req) => {
        if (req.body.includes("raw-token-2")) {
          return { statusCode: 200, json: { error: "invalid_token" } };
        }
        return { statusCode: 200, json: { active: false } };
      },
    });

    try {
      const r1 = await introspectToken({
        introspectionEndpoint: `${server.base}/oauth/introspect`,
        token: "raw-token-1",
        fetchSettings: FetchSettings.fromDevMode(true),
      });
      expect(r1.active).toBe(false);

      const r2 = await introspectToken({
        introspectionEndpoint: `${server.base}/oauth/introspect`,
        token: "raw-token-2",
        fetchSettings: FetchSettings.fromDevMode(true),
      });
      expect(r2.active).toBe(false);
    } finally {
      await server.close();
    }
  });
});

type TokenRequest = { headers: { authorization?: string; [k: string]: string | undefined }; body: string };

async function startAs(options: {
  onTokenRequest: (req: TokenRequest) => { statusCode: number; json: Record<string, unknown> };
}): Promise<{ issuer: string; close: () => Promise<void> }> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = (await exportJWK(publicKey)) as Record<string, unknown> & { kid?: string };
  jwk.kid = "kid_1";
  jwk.use = "sig";

  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;

  server.on("request", (req, res) => {
    const url = req.url ?? "";
    if (req.method === "GET" && url === "/.well-known/oauth-authorization-server") {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          issuer: base,
          jwks_uri: `${base}/.well-known/jwks.json`,
          token_endpoint: `${base}/oauth/token`,
        }),
      );
      return;
    }
    if (req.method === "GET" && url === "/.well-known/jwks.json") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }

    if (req.method === "POST" && url === "/oauth/token") {
      let body = "";
      req.on("data", (chunk) => (body += chunk.toString("utf-8")));
      req.on("end", () => {
        const authorization = typeof req.headers.authorization === "string" ? req.headers.authorization : undefined;
        const out = options.onTokenRequest({
          headers: { authorization },
          body,
        });
        res.statusCode = out.statusCode;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(out.json));
      });
      return;
    }

    res.statusCode = 404;
    res.end();
  });

  return {
    issuer: base,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

type CaptureReq = { headers: { authorization?: string }; body: string };

async function startRevokeEndpoint(options: {
  onRevoke: (req: CaptureReq) => { statusCode: number; json: Record<string, unknown> };
}): Promise<{ base: string; close: () => Promise<void> }> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;

  server.on("request", (req, res) => {
    const url = req.url ?? "";
    if (req.method === "POST" && url === "/oauth/revoke") {
      let body = "";
      req.on("data", (chunk) => (body += chunk.toString("utf-8")));
      req.on("end", () => {
        const authorization = typeof req.headers.authorization === "string" ? req.headers.authorization : undefined;
        const out = options.onRevoke({ headers: { authorization }, body });
        res.statusCode = out.statusCode;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(out.json));
      });
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  return {
    base,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

async function startIntrospectionEndpoint(options: {
  onIntrospect: (req: CaptureReq) => { statusCode: number; json: Record<string, unknown> };
}): Promise<{ base: string; close: () => Promise<void> }> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;

  server.on("request", (req, res) => {
    const url = req.url ?? "";
    if (req.method === "POST" && url === "/oauth/introspect") {
      let body = "";
      req.on("data", (chunk) => (body += chunk.toString("utf-8")));
      req.on("end", () => {
        const authorization = typeof req.headers.authorization === "string" ? req.headers.authorization : undefined;
        const out = options.onIntrospect({ headers: { authorization }, body });
        res.statusCode = out.statusCode;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(out.json));
      });
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  return {
    base,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

function okTokenResponse(): Record<string, unknown> {
  return { access_token: "new_token", token_type: "Bearer", expires_in: 3600, scope: "read" };
}

