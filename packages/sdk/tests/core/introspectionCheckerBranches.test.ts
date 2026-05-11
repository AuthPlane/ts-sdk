import { createServer } from "node:http";
import { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";

import { VerifiedClaims } from "../../src/core/claims.js";
import {
  FetchSettings,
  MetadataFetchError,
  MissingMetadataEndpoint,
} from "../../src/core/index.js";
import { IntrospectionChecker } from "../../src/core/introspectionChecker.js";

function dummyClaims(): VerifiedClaims {
  return new VerifiedClaims({
    sub: "user_1",
    clientId: "client_1",
    scopes: [],
    issuer: "https://issuer.example",
    audience: ["https://rs.example"],
    expiresAt: 1700000000,
    issuedAt: 1700000000,
    jti: "jti_1",
    kid: "kid_1",
    agentId: "",
    agentChain: [],
    notBefore: 0,
    raw: {},
  });
}

describe("IntrospectionChecker.check error propagation", () => {
  it("throws when getMetadata is undefined", async () => {
    const checker = new IntrospectionChecker(undefined, {
      fetchSettings: FetchSettings.fromDevMode(true),
    });

    await expect(
      checker.check(dummyClaims(), "raw_token"),
    ).rejects.toBeInstanceOf(MetadataFetchError);
  });

  it("propagates getMetadata errors", async () => {
    const checker = new IntrospectionChecker(
      async () => {
        throw new Error("metadata fetch failed");
      },
      { fetchSettings: FetchSettings.fromDevMode(true) },
    );

    await expect(
      checker.check(dummyClaims(), "raw_token"),
    ).rejects.toThrow(/metadata fetch failed/);
  });

  it("throws MissingMetadataEndpoint when introspection_endpoint is absent", async () => {
    const checker = new IntrospectionChecker(
      async () => {
        return {};
      },
      { fetchSettings: FetchSettings.fromDevMode(true) },
    );

    await expect(
      checker.check(dummyClaims(), "raw_token"),
    ).rejects.toBeInstanceOf(MissingMetadataEndpoint);
  });

  it("propagates introspectToken errors (non-2xx)", async () => {
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
      const checker = new IntrospectionChecker(
        async () => {
          return { introspection_endpoint: `${base}/oauth/introspect` };
        },
        { fetchSettings: FetchSettings.fromDevMode(true) },
      );

      await expect(
        checker.check(dummyClaims(), "raw_token"),
      ).rejects.toThrow();
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});
