import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type KeyLike,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AuthplaneClient, MetadataFetchError } from "../../src/core/index.js";

interface IssuerIdentityServer {
  server: Server;
  /** Base origin without trailing slash, e.g. `http://127.0.0.1:PORT`. */
  base: string;
  /**
   * The value the AS advertises in the metadata `issuer` field. Controlled
   * independently of `base` so tests can force a trailing-slash difference.
   */
  metadataIssuer: string;
  resource: string;
  privateKey: KeyLike;
}

/**
 * Start a minimal RFC 8414 authorization server whose advertised metadata
 * `issuer` is `metadataIssuer` (which may differ from the origin by a trailing
 * slash). The `.well-known` document is served at the RFC-derived location
 * regardless of the trailing slash on the issuer identity.
 */
async function startServer(options: {
  metadataIssuer?: (base: string) => string;
}): Promise<IssuerIdentityServer> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = "kid_1";
  jwk.alg = "RS256";
  jwk.use = "sig";

  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;
  const metadataIssuer = (options.metadataIssuer ?? ((b) => b))(base);

  server.on("request", (req, res) => {
    if (req.url === "/.well-known/oauth-authorization-server") {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          issuer: metadataIssuer,
          jwks_uri: `${base}/.well-known/jwks.json`,
        }),
      );
      return;
    }
    if (req.url === "/.well-known/jwks.json") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  return { server, base, metadataIssuer, resource: `${base}/mcp`, privateKey };
}

async function mintToken(options: {
  privateKey: KeyLike;
  issuer: string;
  audience: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({
    client_id: "client_1",
    scope: "tools/query",
    jti: "jti_1",
  })
    .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "kid_1" })
    .setSubject("user_1")
    .setIssuer(options.issuer)
    .setAudience(options.audience)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(options.privateKey);
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
}

describe("issuer identity (RFC 8414 §3.3) is preserved byte-for-byte", () => {
  // Scenario (a): the AS identity legitimately carries a trailing slash. The
  // configured issuer, the metadata `issuer`, and the token `iss` all carry it.
  // Regression for the outage: the SDK used to strip the configured issuer's
  // trailing slash and hand the stripped value to the verifier as the expected
  // `iss`, so every token whose `iss` carried the slash was rejected.
  describe("token whose iss carries the configured trailing slash", () => {
    let s: IssuerIdentityServer;
    let trailingSlashIssuer: string;

    beforeAll(async () => {
      s = await startServer({ metadataIssuer: (base) => `${base}/` });
      trailingSlashIssuer = `${s.base}/`;
    });

    afterAll(async () => {
      await closeServer(s.server);
    });

    it("verifies successfully", async () => {
      const client = await AuthplaneClient.create({
        issuer: trailingSlashIssuer,
        devMode: true,
      });
      try {
        const resource = client.resource({
          resource: s.resource,
          scopes: ["tools/query"],
        });
        const token = await mintToken({
          privateKey: s.privateKey,
          issuer: trailingSlashIssuer,
          audience: s.resource,
        });

        const claims = await resource.verify(token);
        expect(claims.sub).toBe("user_1");
        expect(claims.issuer).toBe(trailingSlashIssuer);
      } finally {
        await client.close();
      }
    });
  });

  // Scenario (b): the configured issuer has no trailing slash but the metadata
  // document advertises one (or vice-versa). RFC 8414 §3.3 requires an exact
  // identity match — the SDK must reject the document rather than reconcile the
  // difference.
  describe("metadata document whose issuer differs by a trailing slash", () => {
    it("is rejected with MetadataFetchError", async () => {
      const s = await startServer({ metadataIssuer: (base) => `${base}/` });
      try {
        // Configured issuer has NO trailing slash; metadata advertises one.
        await expect(
          AuthplaneClient.create({ issuer: s.base, devMode: true }),
        ).rejects.toBeInstanceOf(MetadataFetchError);
      } finally {
        await closeServer(s.server);
      }
    });
  });
});
