import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";

import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type KeyLike,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  AuthplaneClient,
  AuthplaneResource,
  type ASCredentials,
  IntrospectionRevocation,
  DPoPReplayDetected,
  DPoPBindingMismatch,
  InvalidClaims,
  InvalidSignature,
  TokenExpired,
  TokenRevoked,
  DPoPKeyMaterial,
  DPoPProvider,
  InMemoryDPoPReplayStore,
} from "../../src/core/index.js";

interface TestAuthServer {
  server: Server;
  issuer: string;
  resource: string;
  privateKey: KeyLike;
}

interface StartOptions {
  introspectionActive?: boolean;
}

async function startAuthServer(options: StartOptions = {}): Promise<TestAuthServer> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = "kid_1";
  jwk.alg = "RS256";
  jwk.use = "sig";

  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;

  const hasIntrospection = options.introspectionActive !== undefined;

  server.on("request", (req, res) => {
    if (!req.url) {
      res.statusCode = 404;
      res.end();
      return;
    }

    if (req.url === "/.well-known/oauth-authorization-server") {
      res.setHeader("content-type", "application/json");
      const metadata: Record<string, unknown> = {
        issuer: base,
        jwks_uri: `${base}/.well-known/jwks.json`,
      };
      if (hasIntrospection) {
        metadata.introspection_endpoint = `${base}/oauth/introspect`;
      }
      res.end(JSON.stringify(metadata));
      return;
    }

    if (req.url === "/.well-known/jwks.json") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }

    if (req.url === "/oauth/introspect" && req.method === "POST") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ active: options.introspectionActive ?? true }));
      return;
    }

    res.statusCode = 404;
    res.end();
  });

  return { server, issuer: base, resource: `${base}/mcp`, privateKey };
}

async function mintToken(options: {
  privateKey: KeyLike;
  issuer: string;
  audience: string | string[];
  typ?: string;
  kid?: string;
  issuedAtOffsetSeconds?: number;
  expiresAtOffsetSeconds?: number;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const iat = now + (options.issuedAtOffsetSeconds ?? 0);
  const exp = now + (options.expiresAtOffsetSeconds ?? 300);

  let builder = new SignJWT({
    client_id: "client_1",
    scope: "tools/query tools/write",
    jti: "jti_1",
  })
    .setProtectedHeader({
      alg: "RS256",
      typ: options.typ ?? "at+jwt",
      kid: options.kid ?? "kid_1",
    })
    .setSubject("user_1")
    .setIssuer(options.issuer)
    .setIssuedAt(iat)
    .setExpirationTime(exp);

  builder = Array.isArray(options.audience)
    ? builder.setAudience(options.audience)
    : builder.setAudience(options.audience);

  return await builder.sign(options.privateKey);
}

describe("AuthplaneResource", () => {
  let testServer: TestAuthServer;

  beforeAll(async () => {
    testServer = await startAuthServer();
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      testServer.server.close((err) => (err ? reject(err) : resolve())),
    );
  });

  it("validates a correct token", async () => {
    const client = await AuthplaneClient.create({
      issuer: testServer.issuer,
      devMode: true,
    });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: ["tools/query", "tools/write"],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
      });

      const claims = await resource.verify(token);
      expect(claims.sub).toBe("user_1");
      expect(claims.clientId).toBe("client_1");
      expect(claims.scopes).toEqual(["tools/query", "tools/write"]);

      // New typed Authplane extension defaults
      expect(claims.agentId).toBe("");
      expect(claims.agentChain).toEqual([]);
      expect(claims.notBefore).toBe(0);
    } finally {
      await client.close();
    }
  });

  it("rejects expired token", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
        expiresAtOffsetSeconds: -120,
      });

      await expect(resource.verify(token)).rejects.toBeInstanceOf(TokenExpired);
    } finally {
      await client.close();
    }
  });

  it("rejects wrong typ header", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
        typ: "JWT",
      });

      await expect(resource.verify(token)).rejects.toBeInstanceOf(InvalidClaims);
    } finally {
      await client.close();
    }
  });

  it("rejects unknown kid", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
        kid: "unknown_kid",
      });

      await expect(resource.verify(token)).rejects.toBeInstanceOf(InvalidSignature);
    } finally {
      await client.close();
    }
  });

  it("accepts multi-audience tokens when resource is present", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: [testServer.resource, "https://other.example.com"],
      });

      const claims = await resource.verify(token);
      expect(claims.audience).toEqual([
        testServer.resource,
        "https://other.example.com",
      ]);
    } finally {
      await client.close();
    }
  });

  it("accepts single-element audience arrays", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: [testServer.resource],
      });

      const claims = await resource.verify(token);
      expect(claims.audience).toEqual([testServer.resource]);
    } finally {
      await client.close();
    }
  });

  it("returns audience as array for string aud claim", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
      });

      const claims = await resource.verify(token);
      expect(claims.audience).toEqual([testServer.resource]);
    } finally {
      await client.close();
    }
  });

  it("rejects iat too far in the future", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        clockSkewSeconds: 30,
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
        issuedAtOffsetSeconds: 120,
        expiresAtOffsetSeconds: 300,
      });

      await expect(resource.verify(token)).rejects.toBeInstanceOf(InvalidClaims);
    } finally {
      await client.close();
    }
  });

  it("rejects when aud array contains only empty strings", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: [""],
      });

      await expect(resource.verify(token)).rejects.toBeInstanceOf(InvalidClaims);
    } finally {
      await client.close();
    }
  });

  it("rejects when exp claim is missing", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
      });

      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({
        client_id: "client_1",
        scope: "tools/query tools/write",
        jti: "jti_missing_exp",
      })
        .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "kid_1" })
        .setSubject("user_1")
        .setIssuer(testServer.issuer)
        .setAudience(testServer.resource)
        .setIssuedAt(now)
        // Intentionally omit exp
        .sign(testServer.privateKey);

      await expect(resource.verify(token)).rejects.toBeInstanceOf(InvalidClaims);
    } finally {
      await client.close();
    }
  });

  it("exposes config and PRM metadata", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: ["tools/query"],
      });

      expect(resource.config.allowedAlgorithms.length).toBeGreaterThan(0);
      const prm = resource.prmResponse();
      expect(prm.resource).toBe(testServer.resource);
      expect(prm.scopes_supported).toEqual(["tools/query"]);
    } finally {
      await client.close();
    }
  });

  it("rejects dangerous algorithms in constructor", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      expect(() =>
        client.resource({
          resource: testServer.resource,
          scopes: [],
          allowedAlgorithms: ["HS256"],
        }),
      ).toThrowError(/Dangerous algorithms/);
    } finally {
      await client.close();
    }
  });

  it("rejects token when custom revocationChecker returns true", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        revocationChecker: async () => true,
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
      });

      await expect(resource.verify(token)).rejects.toBeInstanceOf(TokenRevoked);
    } finally {
      await client.close();
    }
  });

  it("accepts token when custom revocationChecker returns false", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        revocationChecker: async () => false,
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
      });

      const claims = await resource.verify(token);
      expect(claims.sub).toBe("user_1");
    } finally {
      await client.close();
    }
  });

  it("fail-open (default): accepts token when custom revocationChecker throws", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        revocationChecker: async () => {
          throw new Error("introspection transport failure");
        },
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
      });

      const claims = await resource.verify(token);
      expect(claims.sub).toBe("user_1");
    } finally {
      await client.close();
    }
  });

  it("failClosed: true rejects token when custom revocationChecker throws", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        failClosed: true,
        revocationChecker: async () => {
          throw new Error("introspection transport failure");
        },
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
      });

      await expect(resource.verify(token)).rejects.toBeInstanceOf(TokenRevoked);
    } finally {
      await client.close();
    }
  });

  it("custom revocationChecker receives claims and raw token", async () => {
    const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
    try {
      let receivedJti: string | undefined;
      let receivedToken: string | undefined;

      const resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        revocationChecker: async (claims, rawToken) => {
          receivedJti = claims.jti;
          receivedToken = rawToken;
          return false;
        },
      });

      const token = await mintToken({
        privateKey: testServer.privateKey,
        issuer: testServer.issuer,
        audience: testServer.resource,
      });

      await resource.verify(token);
      expect(receivedJti).toBe("jti_1");
      expect(receivedToken).toBe(token);
    } finally {
      await client.close();
    }
  });
});

describe("AuthplaneResource with introspection", () => {
  it("rejects token when introspection returns active=false", async () => {
    const revokedServer = await startAuthServer({ introspectionActive: false });
    try {
      const client = await AuthplaneClient.create({
        issuer: revokedServer.issuer,
        devMode: true,
      });
      try {
        const resource = client.resource({
          resource: revokedServer.resource,
          scopes: [],
          revocationChecker: {},
        });

        const token = await mintToken({
          privateKey: revokedServer.privateKey,
          issuer: revokedServer.issuer,
          audience: revokedServer.resource,
        });

        await expect(resource.verify(token)).rejects.toBeInstanceOf(TokenRevoked);
      } finally {
        await client.close();
      }
    } finally {
      await new Promise<void>((resolve, reject) =>
        revokedServer.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("accepts token when introspection returns active=true", async () => {
    const activeServer = await startAuthServer({ introspectionActive: true });
    try {
      const client = await AuthplaneClient.create({
        issuer: activeServer.issuer,
        devMode: true,
      });
      try {
        const resource = client.resource({
          resource: activeServer.resource,
          scopes: [],
          revocationChecker: {},
        });

        const token = await mintToken({
          privateKey: activeServer.privateKey,
          issuer: activeServer.issuer,
          audience: activeServer.resource,
        });

        const claims = await resource.verify(token);
        expect(claims.sub).toBe("user_1");
      } finally {
        await client.close();
      }
    } finally {
      await new Promise<void>((resolve, reject) =>
        activeServer.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("initializes legacy IntrospectionConfig (object revocationChecker)", async () => {
    const server = await startAuthServer({ introspectionActive: false });
    try {
      const client = await AuthplaneClient.create({ issuer: server.issuer, devMode: true });
      try {
        const resource = client.resource({
          resource: server.resource,
          scopes: [],
          // Legacy IntrospectionConfig (missing clientId/clientSecret is ok for this mock).
          revocationChecker: {},
        });

        const token = await mintToken({
          privateKey: server.privateKey,
          issuer: server.issuer,
          audience: server.resource,
        });

        await expect(resource.verify(token)).rejects.toBeInstanceOf(TokenRevoked);
      } finally {
        await client.close();
      }
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("accepts token with IntrospectionRevocation + asCredentials", async () => {
    const activeServer = await startAuthServer({ introspectionActive: true });
    try {
      const asCredentials: ASCredentials = {
        clientId: "my-rs",
        clientSecret: "s3cret",
      };

      const client = await AuthplaneClient.create({
        issuer: activeServer.issuer,
        devMode: true,
        asCredentials,
      });
      try {
        const resource = client.resource({
          resource: activeServer.resource,
          scopes: [],
          revocationChecker: IntrospectionRevocation.get(),
        });

        const token = await mintToken({
          privateKey: activeServer.privateKey,
          issuer: activeServer.issuer,
          audience: activeServer.resource,
        });

        const claims = await resource.verify(token);
        expect(claims.sub).toBe("user_1");
      } finally {
        await client.close();
      }
    } finally {
      await new Promise<void>((resolve, reject) =>
        activeServer.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

describe("AuthplaneResource with DPoP-bound tokens", () => {
  it("rejects when token has cnf.jkt but no dpopRequest is provided", async () => {
    const testServer = await startAuthServer();
    try {
      const client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
      try {
        const resource = client.resource({
          resource: testServer.resource,
          scopes: [],
          inboundDPoP: {},
        });

        const now = Math.floor(Date.now() / 1000);
        const token = await new SignJWT({
          client_id: "client_1",
          scope: "tools/query",
          jti: "jti_1",
          cnf: { jkt: "some-jkt" },
        })
          .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "kid_1" })
          .setSubject("user_1")
          .setIssuer(testServer.issuer)
          .setAudience(testServer.resource)
          .setIssuedAt(now)
          .setExpirationTime(now + 300)
          .sign(testServer.privateKey);

        await expect(resource.verify(token)).rejects.toBeInstanceOf(DPoPBindingMismatch);
      } finally {
        await client.close();
      }
    } finally {
      await new Promise<void>((resolve, reject) =>
        testServer.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("accepts DPoP-bound token when proof is provided and rejects replayed proof", async () => {
    const testServer = await startAuthServer();
    let resource: AuthplaneResource | undefined;
    let client: AuthplaneClient | undefined;

    try {
      client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
      const replayStore = new InMemoryDPoPReplayStore();
      resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        inboundDPoP: { replayStore },
      });

      const { privateKey, publicKey } = await generateKeyPair("ES256");
      const publicJwk = (await exportJWK(publicKey)) as JWK;
      const expectedJkt = await calculateJwkThumbprint(publicJwk);

      const provider = new DPoPProvider({
        keyMaterial: new DPoPKeyMaterial({
        	privateKey,
        	publicJwk,
        	algorithm: "ES256",
        }),
        nonceStore: undefined,
        proofTtlSeconds: 300,
      });

      const dpopMethod = "POST";
      const dpopUrl = "https://api.example.com/tools/call";

      // Mint a DPoP-bound access token.
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({
        client_id: "client_1",
        scope: "tools/query",
        jti: "jti_dpop_happy_1",
        cnf: { jkt: String(expectedJkt) },
      })
        .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "kid_1" })
        .setSubject("user_1")
        .setIssuer(testServer.issuer)
        .setAudience(testServer.resource)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(testServer.privateKey);

      const headers = await provider.buildHeadersAsync(dpopMethod, dpopUrl, {
        accessToken: token,
      });

      const dpopRequest = {
        method: dpopMethod,
        url: dpopUrl,
        proof: headers.DPoP,
      };

      const claims = await resource.verify(token, { dpopRequest });
      expect(claims.sub).toBe("user_1");

      // Reusing the same proof should be detected as replay.
      await expect(resource.verify(token, { dpopRequest })).rejects.toBeInstanceOf(
        DPoPReplayDetected,
      );
    } finally {
      await client?.close();
      resource = undefined;
      await new Promise<void>((resolve, reject) =>
        testServer.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("rejects DPoP binding mismatch when proof key doesn't match cnf.jkt", async () => {
    const testServer = await startAuthServer();
    let resource: AuthplaneResource | undefined;
    let client: AuthplaneClient | undefined;

    try {
      client = await AuthplaneClient.create({ issuer: testServer.issuer, devMode: true });
      resource = client.resource({
        resource: testServer.resource,
        scopes: [],
        inboundDPoP: {},
      });

      const { privateKey: keyA, publicKey: pubA } = await generateKeyPair("ES256");
      void keyA; // keyA is used as the "token binding" key below.
      const jwkA = (await exportJWK(pubA)) as JWK;
      const expectedJkt = await calculateJwkThumbprint(jwkA);

      const { privateKey: keyB, publicKey: pubB } = await generateKeyPair("ES256");
      const jwkB = (await exportJWK(pubB)) as JWK;

      const providerB = new DPoPProvider({
        keyMaterial: new DPoPKeyMaterial({
        	privateKey: keyB,
        	publicJwk: jwkB,
        	algorithm: "ES256",
        }),
      });

      const dpopMethod = "POST";
      const dpopUrl = "https://api.example.com/tools/call";

      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({
        client_id: "client_1",
        scope: "tools/query",
        jti: "jti_dpop_bind_mismatch_1",
        cnf: { jkt: String(expectedJkt) },
      })
        .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "kid_1" })
        .setSubject("user_1")
        .setIssuer(testServer.issuer)
        .setAudience(testServer.resource)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(testServer.privateKey);

      const headers = await providerB.buildHeadersAsync(dpopMethod, dpopUrl, {
        accessToken: token,
      });

      await expect(
        resource!.verify(token, {
          dpopRequest: {
            method: dpopMethod,
            url: dpopUrl,
            proof: headers.DPoP,
          },
        }),
      ).rejects.toBeInstanceOf(DPoPBindingMismatch);
    } finally {
      await client?.close();
      resource = undefined;
      await new Promise<void>((resolve, reject) =>
        testServer.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

describe("AuthplaneResource with IntrospectionRevocation without asCredentials", () => {
  it("warns and still validates token when AS introspection returns active=true", async () => {
    const server = await startAuthServer({ introspectionActive: true });
    try {
      const client = await AuthplaneClient.create({ issuer: server.issuer, devMode: true });
      try {
        const resource = client.resource({
          resource: server.resource,
          scopes: [],
          revocationChecker: IntrospectionRevocation.get(),
          // Intentionally omit asCredentials => triggers warning branch.
        });

        const token = await mintToken({
          privateKey: server.privateKey,
          issuer: server.issuer,
          audience: server.resource,
        });

        const claims = await resource.verify(token);
        expect(claims.sub).toBe("user_1");
      } finally {
        await client.close();
      }
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

