import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type KeyLike,
} from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { AuthplaneClient } from "../../src/core/index.js";

/**
 * A verify-only resource server never calls an AS-facing operation, so the
 * verification path is the only thing that can keep AS metadata current. These
 * tests drive nothing but `verify()`: no forced refresh, no private state, no
 * test-only hook. If metadata is only ever read once at construction, the
 * rotation test below cannot pass — the token is signed by a key that is
 * published at the new `jwks_uri` and nowhere else.
 */

interface Keypair {
  kid: string;
  privateKey: KeyLike;
  jwks: { keys: JWK[] };
}

async function generateKeypair(kid: string): Promise<Keypair> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { kid, privateKey, jwks: { keys: [jwk] } };
}

const METADATA_PATH = "/.well-known/oauth-authorization-server";
const JWKS_V1_PATH = "/jwks-v1.json";
const JWKS_V2_PATH = "/jwks-v2.json";

interface RotatingAuthServer {
  server: Server;
  origin: string;
  v1: Keypair;
  v2: Keypair;
  /** Every path the SDK requested, in order. */
  requests: string[];
  count(path: string): number;
  /** Publish `jwks_uri` as v2 and withdraw the v1 document. */
  rotateJwksUri(): void;
}

/**
 * Delay applied to the v2 JWKS response. Widening that round trip is what makes
 * the stale-while-revalidate race observable: the background metadata refresh
 * commits the rotated document while whatever depends on it is still in flight.
 */
async function startRotatingAuthServer(
  jwksV2DelayMs = 0,
  metadataDelayMs = 0,
): Promise<RotatingAuthServer> {
  const v1 = await generateKeypair("key-v1");
  const v2 = await generateKeypair("key-v2");

  let publishedJwksPath = JWKS_V1_PATH;
  let v1Withdrawn = false;
  const requests: string[] = [];

  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  server.on("request", (req, res) => {
    const url = req.url ?? "";
    requests.push(url);
    res.setHeader("content-type", "application/json");

    if (url === METADATA_PATH) {
      const body = JSON.stringify({
        issuer: origin,
        jwks_uri: `${origin}${publishedJwksPath}`,
      });
      if (metadataDelayMs > 0) {
        setTimeout(() => res.end(body), metadataDelayMs);
        return;
      }
      res.end(body);
      return;
    }
    if (url === JWKS_V1_PATH && !v1Withdrawn) {
      res.end(JSON.stringify(v1.jwks));
      return;
    }
    if (url === JWKS_V2_PATH) {
      if (jwksV2DelayMs > 0) {
        setTimeout(() => res.end(JSON.stringify(v2.jwks)), jwksV2DelayMs);
        return;
      }
      res.end(JSON.stringify(v2.jwks));
      return;
    }

    // A withdrawn JWKS URI is gone, not merely stale. Answering it would let a
    // failure to follow the rotation pass unnoticed.
    res.statusCode = url === JWKS_V1_PATH ? 410 : 404;
    res.end();
  });

  return {
    server,
    origin,
    v1,
    v2,
    requests,
    count: (path) => requests.filter((r) => r === path).length,
    rotateJwksUri: () => {
      publishedJwksPath = JWKS_V2_PATH;
      v1Withdrawn = true;
    },
  };
}

async function mintToken(options: {
  keypair: Keypair;
  issuer: string;
  audience: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({
    client_id: "client_1",
    scope: "read:data",
    jti: `jti_${Math.random().toString(36).slice(2)}`,
  })
    .setProtectedHeader({
      alg: "RS256",
      typ: "at+jwt",
      kid: options.keypair.kid,
    })
    .setSubject("user_1")
    .setIssuer(options.issuer)
    .setAudience(options.audience)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(options.keypair.privateKey);
}

/** The configured metadata refresh interval, and a wait that outlasts it. */
const METADATA_REFRESH_SECONDS = 2;
/**
 * The SWR test needs a TTL at which the window it is named after exists.
 * `cacheTimeSeconds` and `now` are whole seconds, and the predicate trips at
 * `ttl * 0.8`, so at a TTL of 2 the age is 0 or 1 while the threshold is 1.6 —
 * the branch is unreachable and the test lands on the expired path instead.
 * At 10 the window is 8 s to 10 s, comfortably resolvable at second granularity.
 */
const SWR_METADATA_REFRESH_SECONDS = 10;
const sleepPastRefreshInterval = (): Promise<void> =>
  new Promise((resolve) =>
    setTimeout(resolve, METADATA_REFRESH_SECONDS * 1000 + 100),
  );

describe("AS metadata refresh on the verification path", () => {
  let as: RotatingAuthServer;

  beforeAll(async () => {
    as = await startRotatingAuthServer();
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      as.server.close((err) => (err ? reject(err) : resolve())),
    );
  });

  it("follows a rotated jwks_uri driven only by verify() traffic", async () => {
    const client = await AuthplaneClient.create({
      issuer: as.origin,
      devMode: true,
      metadataRefreshSeconds: METADATA_REFRESH_SECONDS,
      jwksRefreshSeconds: 300,
    });
    const resource = client.resource({
      resource: `${as.origin}/api`,
      scopes: ["read:data"],
    });

    try {
      // Baseline: the resource verifies against the originally published URI.
      const beforeRotation = await resource.verify(
        await mintToken({
          keypair: as.v1,
          issuer: as.origin,
          audience: `${as.origin}/api`,
        }),
      );
      expect(beforeRotation.sub).toBe("user_1");

      // Inside the refresh interval, verification is not paying for a refetch.
      expect(as.count(METADATA_PATH)).toBe(1);
      expect(as.count(JWKS_V1_PATH)).toBe(1);

      as.rotateJwksUri();
      const v1RequestsAtRotation = as.count(JWKS_V1_PATH);
      const requestsAtRotation = as.requests.length;

      // Nothing but the passage of time and ordinary traffic from here on.
      await sleepPastRefreshInterval();

      const token = await mintToken({
        keypair: as.v2,
        issuer: as.origin,
        audience: `${as.origin}/api`,
      });
      const claims = await resource.verify(token);
      expect(claims.sub).toBe("user_1");
      expect(claims.kid).toBe("key-v2");

      // Two metadata reads land here: the refresh interval elapsed, so verify()
      // re-read the document (2); the `kid` miss then forced a JWKS refetch,
      // which re-reads metadata rather than resolving the URI from a cached
      // document that may still name the withdrawn one (3). That second read is
      // what makes a rotation observed inside the stale-while-revalidate window
      // land, instead of only one observed after full expiry.
      expect(as.count(METADATA_PATH)).toBe(3);
      expect(as.count(JWKS_V2_PATH)).toBe(1);

      // The withdrawn URI was not touched again — not even as a fallback on the
      // request that first observed the rotation.
      expect(as.count(JWKS_V1_PATH)).toBe(v1RequestsAtRotation);
      expect(as.requests.slice(requestsAtRotation)).not.toContain(JWKS_V1_PATH);

      // Further traffic inside the new interval resolves the new URI from the
      // cached document without refetching either.
      const later = await resource.verify(
        await mintToken({
          keypair: as.v2,
          issuer: as.origin,
          audience: `${as.origin}/api`,
        }),
      );
      expect(later.kid).toBe("key-v2");
      expect(as.count(METADATA_PATH)).toBe(3);
      expect(as.count(JWKS_V2_PATH)).toBe(1);
      expect(as.count(JWKS_V1_PATH)).toBe(v1RequestsAtRotation);
    } finally {
      await client.close();
    }
  });

  it("follows a rotation observed inside the stale-while-revalidate window", async () => {
    // `shouldRefreshInBackground` trips at 80% of TTL, so under steady traffic
    // this window opens long before the document expires and is the branch a
    // continuously-served resource server reaches *first*. A cache hit here
    // returns immediately, so the JWKS fetch that follows must not be allowed to
    // resolve its URI from the document being revalidated.
    const JWKS_V2_ROUND_TRIP_MS = 300;
    const METADATA_ROUND_TRIP_MS = 400;
    const swrAs = await startRotatingAuthServer(
      JWKS_V2_ROUND_TRIP_MS,
      METADATA_ROUND_TRIP_MS,
    );
    const client = await AuthplaneClient.create({
      issuer: swrAs.origin,
      devMode: true,
      metadataRefreshSeconds: SWR_METADATA_REFRESH_SECONDS,
      jwksRefreshSeconds: 300,
    });
    const resource = client.resource({
      resource: `${swrAs.origin}/api`,
      scopes: ["read:data"],
    });

    // Real time still has to pass for the HTTP round trips, so the clock is
    // offset rather than frozen: the cache reads `Date.now()` for both the age
    // and the commit stamp, and an 8.5 s offset puts it inside the window
    // without an 8.5 s sleep.
    const realNow = Date.now.bind(Date);
    const bootedAt = realNow();
    let clockOffsetMs = 0;
    const nowSpy = vi
      .spyOn(Date, "now")
      .mockImplementation(() => realNow() + clockOffsetMs);

    try {
      const beforeRotation = await resource.verify(
        await mintToken({
          keypair: swrAs.v1,
          issuer: swrAs.origin,
          audience: `${swrAs.origin}/api`,
        }),
      );
      expect(beforeRotation.kid).toBe("key-v1");

      swrAs.rotateJwksUri();
      const v1RequestsAtRotation = swrAs.count(JWKS_V1_PATH);
      const requestsAtRotation = swrAs.requests.length;

      // Land strictly inside the SWR window: past 80% of the TTL, before expiry.
      // Computed at the point of use rather than as a fixed offset. The cache
      // stamped `cacheTimeSeconds` from the real clock during `create()`, before
      // the spy existed, so a constant would drift by however long everything
      // since then took — an RSA sign, a JWKS round trip, a second mint — and the
      // window is only two whole seconds wide. Off the end of it the test silently
      // goes back to exercising the expired path.
      const elapsedSinceBoot = realNow() - bootedAt;
      clockOffsetMs =
        SWR_METADATA_REFRESH_SECONDS * 1000 * 0.85 - elapsedSinceBoot;
      const metadataRequestsBeforeWindow = swrAs.count(METADATA_PATH);

      // Ordinary traffic on a still-valid token. This is the cache hit that
      // starts the background refresh; the v1 keys are still cached, so it
      // succeeds without touching the network.
      const startedDuringWindow = realNow();
      const duringWindow = await resource.verify(
        await mintToken({
          keypair: swrAs.v1,
          issuer: swrAs.origin,
          audience: `${swrAs.origin}/api`,
        }),
      );
      const duringWindowMs = realNow() - startedDuringWindow;
      expect(duringWindow.kid).toBe("key-v1");

      // The assertion that tells the two branches apart. The metadata endpoint
      // answers in `METADATA_ROUND_TRIP_MS`; on the SWR path that fetch runs
      // *beside* the verify, which returns off the cached document, so the verify
      // finishes well inside it. On the expired path the verify awaits the fetch
      // and cannot finish before it. A fetch count cannot discriminate here — the
      // expired path issues exactly one metadata request too, which is how the
      // round-4 version of this test passed while never entering the window.
      expect(duringWindowMs).toBeLessThan(METADATA_ROUND_TRIP_MS / 2);

      // Long enough for the background metadata refresh to commit the rotated
      // document, short enough that anything it depends on is still in flight.
      await new Promise((resolve) =>
        setTimeout(resolve, JWKS_V2_ROUND_TRIP_MS / 4),
      );

      // And the refresh did run: a cache hit that does not trip
      // `shouldRefreshInBackground` issues no request at all. Necessary but not
      // sufficient on its own — see the latency assertion above for the half that
      // discriminates.
      expect(swrAs.count(METADATA_PATH)).toBe(metadataRequestsBeforeWindow + 1);

      const claims = await resource.verify(
        await mintToken({
          keypair: swrAs.v2,
          issuer: swrAs.origin,
          audience: `${swrAs.origin}/api`,
        }),
      );
      expect(claims.sub).toBe("user_1");
      expect(claims.kid).toBe("key-v2");

      // The withdrawn URI was never requested again, and both tokens verified.
      // Before this change, a rotation observed in this window left the cached
      // document and the key source disagreeing for as long as the JWKS round
      // trip lasted, and verification inside that gap failed outright — the
      // document said one thing about where keys live and `jwksCache` another.
      expect(swrAs.count(JWKS_V1_PATH)).toBe(v1RequestsAtRotation);
      expect(swrAs.requests.slice(requestsAtRotation)).not.toContain(
        JWKS_V1_PATH,
      );
      expect(swrAs.count(JWKS_V2_PATH)).toBe(1);
    } finally {
      nowSpy.mockRestore();
      await client.close();
      await new Promise<void>((resolve, reject) =>
        swrAs.server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("does not repoint key retrieval from a metadata document that fails validation", async () => {
    // The document is rejected; the key source it names must not survive it.
    // Putting the metadata read on the verification path is what makes this
    // reachable on every request for a verify-only resource server, so the
    // rejection has to happen before the document is committed — validating on
    // the way out would leave a rejected document deciding where keys come from,
    // and a token minted by the key it names would then verify.
    const rogue = await generateKeypair("key-rogue");
    const ROGUE_JWKS_PATH = "/jwks-rogue.json";
    let serveRogue = false;

    const honest = await generateKeypair("key-honest");
    const server = createServer();
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    server.on("request", (req, res) => {
      const url = req.url ?? "";
      res.setHeader("content-type", "application/json");
      if (url === METADATA_PATH) {
        res.end(
          JSON.stringify(
            serveRogue
              ? // RFC 8414 §3.3: the issuer is not ours, so this document is not
                // about this authorization server at all.
                {
                  issuer: "http://127.0.0.1:1/elsewhere",
                  jwks_uri: `${origin}${ROGUE_JWKS_PATH}`,
                }
              : { issuer: origin, jwks_uri: `${origin}${JWKS_V1_PATH}` },
          ),
        );
        return;
      }
      if (url === JWKS_V1_PATH) {
        res.end(JSON.stringify(honest.jwks));
        return;
      }
      if (url === ROGUE_JWKS_PATH) {
        res.end(JSON.stringify(rogue.jwks));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const client = await AuthplaneClient.create({
      issuer: origin,
      devMode: true,
      metadataRefreshSeconds: METADATA_REFRESH_SECONDS,
      jwksRefreshSeconds: 300,
    });
    const resource = client.resource({
      resource: `${origin}/api`,
      scopes: ["read:data"],
    });

    try {
      const good = await resource.verify(
        await mintToken({
          keypair: honest,
          issuer: origin,
          audience: `${origin}/api`,
        }),
      );
      expect(good.kid).toBe("key-honest");

      serveRogue = true;
      await sleepPastRefreshInterval();

      // Minted by the key the rejected document points at, but carrying the
      // real issuer — the shape a client would present after the AS metadata
      // endpoint is compromised.
      const forged = await mintToken({
        keypair: rogue,
        issuer: origin,
        audience: `${origin}/api`,
      });
      await expect(resource.verify(forged)).rejects.toThrow();

      // And the honest key still verifies: rejecting the document left the
      // previous one in place rather than emptying the cache.
      const stillGood = await resource.verify(
        await mintToken({
          keypair: honest,
          issuer: origin,
          audience: `${origin}/api`,
        }),
      );
      expect(stillGood.kid).toBe("key-honest");
    } finally {
      await client.close();
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("pays for an unreachable metadata endpoint once per floor, not once per verification", async () => {
    // Once `metadataRefreshSeconds` elapses against a down metadata endpoint,
    // every verification would otherwise start a fresh fetch and stall on it —
    // an AS outage amplified into per-request latency on the resource server.
    // The retry floor caps that at one attempt per
    // `max(1, min(fetchFailureBackoffSeconds, metadataRefreshSeconds))`;
    // verifications in between are served entirely from the cached documents.
    const keypair = await generateKeypair("key-v1");
    let metadataDown = false;
    let metadataRequests = 0;

    const server = createServer();
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    server.on("request", (req, res) => {
      const url = req.url ?? "";
      if (url === METADATA_PATH) {
        metadataRequests += 1;
        if (metadataDown) {
          res.statusCode = 503;
          res.end();
          return;
        }
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            issuer: origin,
            jwks_uri: `${origin}${JWKS_V1_PATH}`,
          }),
        );
        return;
      }
      if (url === JWKS_V1_PATH) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(keypair.jwks));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const client = await AuthplaneClient.create({
      issuer: origin,
      devMode: true,
      metadataRefreshSeconds: METADATA_REFRESH_SECONDS,
      jwksRefreshSeconds: 300,
    });
    const resource = client.resource({
      resource: `${origin}/api`,
      scopes: ["read:data"],
    });
    const verifyOne = async () => {
      const claims = await resource.verify(
        await mintToken({
          keypair,
          issuer: origin,
          audience: `${origin}/api`,
        }),
      );
      expect(claims.kid).toBe("key-v1");
    };

    try {
      await verifyOne();
      expect(metadataRequests).toBe(1);

      metadataDown = true;
      await sleepPastRefreshInterval();

      // The first verification past the interval pays for the failed attempt,
      // and still succeeds on the cached keys.
      await verifyOne();
      expect(metadataRequests).toBe(2);

      // Immediate traffic behind it touches nothing on the network: the floor
      // is open, so these are pure cache reads.
      await verifyOne();
      await verifyOne();
      expect(metadataRequests).toBe(2);

      // Past the floor — min(30, metadataRefreshSeconds) — exactly one more
      // attempt is admitted for the next wave.
      await sleepPastRefreshInterval();
      await verifyOne();
      await verifyOne();
      expect(metadataRequests).toBe(3);

      // The endpoint comes back: the next admitted attempt succeeds, closes
      // the floor, and refresh behaviour is back to interval-driven.
      metadataDown = false;
      await sleepPastRefreshInterval();
      await verifyOne();
      expect(metadataRequests).toBe(4);
      await verifyOne();
      expect(metadataRequests).toBe(4);
    } finally {
      await client.close();
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
    // Three real refresh intervals have to pass: one to reach the failed
    // attempt, one to outlast the floor, one to observe the recovery.
  }, 20_000);
});
