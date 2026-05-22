import { createServer } from "node:http";
import { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";

import {
  DPoPKeyMaterial,
  DPoPProvider,
  FetchSettings,
  clientCredentialsGrant,
} from "../../src/core/index.js";

describe("DPoP nonce retry", () => {
  it("retries once when AS returns use_dpop_nonce + dpop-nonce header", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = await exportJWK(publicKey);

    const provider = new DPoPProvider({
      keyMaterial: new DPoPKeyMaterial({
      	privateKey,
      	publicJwk,
      	algorithm: "ES256",
      }),
    });

    let attempt = 0;
    const server = createServer(async (req, res) => {
      if (req.url !== "/token" || req.method !== "POST") {
        res.statusCode = 404;
        res.end();
        return;
      }

      const dpop = req.headers["dpop"];
      attempt += 1;

      if (attempt === 1) {
        // Challenge with nonce; no need to validate proof.
        res.statusCode = 400;
        res.setHeader("content-type", "application/json");
        res.setHeader("dpop-nonce", "nonce_1");
        res.end(JSON.stringify({ error: "use_dpop_nonce" }));
        return;
      }

      expect(typeof dpop).toBe("string");
      const proof = String(dpop);

      // Verify signature + presence of nonce claim.
      const verified = await jwtVerify(proof, publicKey, {
        typ: "dpop+jwt",
      });
      expect(verified.payload.nonce).toBe("nonce_1");

      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          access_token: "at_1",
          token_type: "DPoP",
          expires_in: 300,
          scope: "",
        }),
      );
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      const token = await clientCredentialsGrant({
        tokenEndpoint: `${base}/token`,
        authHeader: {},
        fetchSettings: FetchSettings.fromDevMode(true),
        dpopProvider: provider,
      });
      expect(token.accessToken).toBe("at_1");
      expect(attempt).toBe(2);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

