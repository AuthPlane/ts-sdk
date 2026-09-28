import { describe, expect, it, vi } from "vitest";

import { MetadataFetchError } from "../../src/core/errors.js";
import {
  DocumentCache,
  JWKSCache,
  MetadataCache,
} from "../../src/core/fetching/documentCache.js";

type Doc = { v: number };

describe("fetching/documentCache", () => {
  it("returns cached value when valid (no refetch)", async () => {
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        return { document: { v: 1 }, expiresAt: undefined };
      },
      { refreshSeconds: 100 },
    );

    try {
      const d1 = await cache.get();
      expect(d1).toEqual({ v: 1 });
      const d2 = await cache.get();
      expect(d2).toEqual({ v: 1 });
      expect(fetchCount).toBe(1);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("deduplicates concurrent fetches via fetchInFlight", async () => {
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    let resolveFetch: ((doc: Doc) => void) | undefined;
    let fetchCount = 0;

    const fetcher = async () => {
      fetchCount += 1;
      return new Promise<{ document: Doc; expiresAt: number | undefined }>(
        (resolve) => {
          resolveFetch = (doc) => resolve({ document: doc, expiresAt: undefined });
        },
      );
    };

    const cache = new DocumentCache<Doc>(fetcher, { refreshSeconds: 100 });

    try {
      const p1 = cache.get();
      const p2 = cache.get();

      expect(fetchCount).toBe(1);

      resolveFetch?.({ v: 1 });

      const [d1, d2] = await Promise.all([p1, p2]);
      expect(d1).toEqual({ v: 1 });
      expect(d2).toEqual({ v: 1 });
      expect(fetchCount).toBe(1);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("triggers background refresh once and serves the new document after it lands", async () => {
    const t0 = 1_700_000_000;

    // Background refresh should start when nowSeconds - cacheTimeSeconds >= ttl * 0.8.
    // Here we force serverExpiresAt to make ttl smaller, so it triggers earlier.
    let call = 0;
    let resolveSecond: (() => void) | undefined;

    const fetcher = async () => {
      call += 1;
      if (call === 1) {
        return {
          document: { v: 1 },
          // Make server TTL=50 seconds so ttl*0.8=40.
          expiresAt: t0 + 50,
        };
      }
      if (call === 2) {
        return new Promise<{ document: Doc; expiresAt: number | undefined }>(
          (resolve) => {
            resolveSecond = () => resolve({ document: { v: 2 }, expiresAt: t0 + 150 });
          },
        );
      }
      return { document: { v: 3 }, expiresAt: t0 + 200 };
    };

    const cache = new DocumentCache<Doc>(fetcher, {
      refreshSeconds: 100,
    });

    const nowSpy = vi.spyOn(Date, "now");
    try {
      nowSpy.mockReturnValue(t0 * 1000);
      const d1 = await cache.get();
      expect(d1).toEqual({ v: 1 });

      // Now within the valid TTL and after ttl*0.8, so background refresh should start.
      nowSpy.mockReturnValue((t0 + 41) * 1000);
      const dBefore = await cache.get();
      expect(dBefore).toEqual({ v: 1 });

      // Complete background refresh.
      resolveSecond?.();
      await new Promise((r) => setTimeout(r, 1));

      // Next get should observe the updated document.
      const dAfter = await cache.get();
      expect(dAfter).toEqual({ v: 2 });
      expect(call).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("keeps the cached document when validation rejects a fetched one", async () => {
    // The rejected document must not reach `this.cache` even transiently:
    // `jwks_uri` resolution reads the cache, so a document that fails validation
    // deciding where keys come from is the defect this ordering exists to close.
    class ValidatingCache extends DocumentCache<Doc> {
      public validated: Doc[] = [];
      protected override validateDocument(document: Doc): Doc {
        this.validated.push(document);
        if (document.v === 2) {
          throw new Error("rejected by validation");
        }
        return document;
      }
    }

    let call = 0;
    const cache = new ValidatingCache(
      async () => {
        call += 1;
        return { document: { v: call }, expiresAt: undefined };
      },
      { refreshSeconds: 100 },
    );

    const nowSpy = vi.spyOn(Date, "now");
    try {
      const t0 = 1_700_000_000;
      nowSpy.mockReturnValue(t0 * 1000);
      expect(await cache.get()).toEqual({ v: 1 });

      // Past the TTL: the fetch returns { v: 2 }, which validation rejects.
      nowSpy.mockReturnValue((t0 + 200) * 1000);
      expect(await cache.get()).toEqual({ v: 1 });
      expect(cache.validated).toEqual([{ v: 1 }, { v: 2 }]);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("throws through the error factory when validation rejects the first document", async () => {
    class AlwaysRejects extends DocumentCache<Doc> {
      protected override validateDocument(): Doc {
        throw new Error("bad document");
      }
    }

    const cache = new AlwaysRejects(
      async () => ({ document: { v: 1 }, expiresAt: undefined }),
      {
        refreshSeconds: 100,
        errorFactory: (message) => new Error(`wrapped: ${message}`),
      },
    );

    await expect(cache.get()).rejects.toThrow(
      "wrapped: Failed to fetch document: bad document",
    );
  });

  it("close() drains an in-flight background refresh", async () => {
    const t0 = 1_700_000_000;
    let settled = false;
    let resolveSecond: (() => void) | undefined;
    let call = 0;

    const cache = new DocumentCache<Doc>(
      async () => {
        call += 1;
        if (call === 1) {
          return { document: { v: 1 }, expiresAt: t0 + 50 };
        }
        return new Promise<{ document: Doc; expiresAt: number | undefined }>(
          (resolve) => {
            resolveSecond = () => {
              settled = true;
              resolve({ document: { v: 2 }, expiresAt: t0 + 150 });
            };
          },
        );
      },
      { refreshSeconds: 100 },
    );

    const nowSpy = vi.spyOn(Date, "now");
    try {
      nowSpy.mockReturnValue(t0 * 1000);
      await cache.get();
      nowSpy.mockReturnValue((t0 + 41) * 1000);
      await cache.get();

      const closing = cache.close();
      expect(settled).toBe(false);
      resolveSecond?.();
      await closing;
      expect(settled).toBe(true);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("deduplicates background refresh start when refreshInFlight already exists", async () => {
    const t0 = 1_700_000_000;
    let call = 0;
    let resolveSecond: (() => void) | undefined;

    const fetcher = async () => {
      call += 1;
      if (call === 1) {
        return { document: { v: 1 }, expiresAt: t0 + 50 };
      }
      if (call === 2) {
        return new Promise<{ document: Doc; expiresAt: number | undefined }>(
          (resolve) => {
            resolveSecond = () => resolve({ document: { v: 2 }, expiresAt: t0 + 150 });
          },
        );
      }
      return { document: { v: 3 }, expiresAt: t0 + 200 };
    };

    const cache = new DocumentCache<Doc>(fetcher, { refreshSeconds: 100 });
    const nowSpy = vi.spyOn(Date, "now");

    try {
      nowSpy.mockReturnValue(t0 * 1000);
      await cache.get();
      expect(call).toBe(1);

      nowSpy.mockReturnValue((t0 + 41) * 1000);

      // First get triggers background refresh (call 2 created but not resolved).
      const d1 = await cache.get();
      expect(d1).toEqual({ v: 1 });
      expect(call).toBe(2);

      // Second get while refreshInFlight is pending should not trigger a new refresh fetch.
      const d2 = await cache.get();
      expect(d2).toEqual({ v: 1 });
      expect(call).toBe(2);

      resolveSecond?.();
      await new Promise((r) => setTimeout(r, 1));

      const d3 = await cache.get();
      expect(d3).toEqual({ v: 2 });
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("returns cached value when refresh fails (fail-open)", async () => {
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    let shouldThrow = false;
    const fetcher = async () => {
      if (shouldThrow) {
        throw new Error("fetch failed");
      }
      return { document: { v: 1 }, expiresAt: undefined };
    };

    const cache = new DocumentCache<Doc>(fetcher, { refreshSeconds: 1, errorFactory: (m) => new Error(m) });

    try {
      const d1 = await cache.get();
      expect(d1).toEqual({ v: 1 });
      shouldThrow = true;

      const d2 = await cache.get(true);
      expect(d2).toEqual({ v: 1 });
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("throws when cache is empty and fetch fails (fail-closed)", async () => {
    const fetcher = async () => {
      throw new Error("nope");
    };

    const cache = new DocumentCache<Doc>(fetcher, {
      refreshSeconds: 10,
      errorFactory: (message) => new Error(message),
    });

    await expect(cache.get()).rejects.toThrow(/Failed to fetch document: nope/);
  });
  it("does not let a slower background refresh overwrite a newer forced fetch", async () => {
    // A forced caller deliberately does not join a non-forced fetch already in
    // flight, which is what puts two fetches in the air at once. Committing
    // unconditionally is then last-writer-wins rather than
    // latest-document-wins: the background refresh started before the rotation
    // lands after the forced read that observed it, and puts the withdrawn
    // document back for the rest of the interval.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    const release: Array<() => void> = [];
    const cache = new DocumentCache<Doc>(
      async (forceUpstream) => {
        // v1 for the background read, v2 for the forced one: the forced read is
        // the one that saw the newer upstream state.
        const document = { v: forceUpstream ? 2 : 1 };
        await new Promise<void>((resolve) => release.push(resolve));
        return { document, expiresAt: undefined };
      },
      { refreshSeconds: 100 },
    );

    try {
      const boot = cache.get();
      release[0]?.();
      await boot;

      // Into the stale-while-revalidate window, so an ordinary read starts a
      // background refresh instead of returning from cache alone.
      now = (t0 + 85) * 1000;
      await cache.get();
      const forced = cache.get(true);

      // Two fetchers are suspended: [1] the background refresh, [2] the forced
      // read. Release the forced one first so the stale answer commits last.
      release[2]?.();
      await forced;
      release[1]?.();
      await cache.close();

      // The document that saw the newer state survives the one that landed
      // after it.
      now = (t0 + 86) * 1000;
      expect(await cache.get()).toEqual({ v: 2 });
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("keeps deduping after a concurrent fetch settles", async () => {
    // Clearing `fetchInFlight` unconditionally in `finally` tears down the
    // dedupe state of a fetch that is still running, so the next caller starts a
    // duplicate upstream fetch instead of joining the one in flight.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    const release: Array<() => void> = [];
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        const v = fetchCount;
        await new Promise<void>((resolve) => release.push(resolve));
        return { document: { v }, expiresAt: undefined };
      },
      { refreshSeconds: 100 },
    );

    try {
      const boot = cache.get();
      release[0]?.();
      await boot;
      expect(fetchCount).toBe(1);

      now = (t0 + 85) * 1000;
      await cache.get();
      const forced = cache.get(true);
      expect(fetchCount).toBe(3);

      // Settle the background refresh, which started first and no longer owns
      // the dedupe fields.
      release[1]?.();
      await cache.close();

      // A caller arriving now must join the forced fetch that is still running.
      // Asserted before releasing anything: the fetcher increments
      // synchronously, so a fourth upstream fetch would already be counted here.
      // Waiting instead would turn the regression into a hang, not a failure.
      const joined = cache.get(true);
      expect(fetchCount).toBe(3);

      for (const resolve of release) {
        resolve();
      }
      await Promise.all([forced, joined]);
    } finally {
      nowSpy.mockRestore();
    }
  });
  it("caps forced metadata reads at one per floor, and follows a rotation after it", async () => {
    // A forced read bypasses `refreshSeconds`, and the caller that reaches it is
    // a JWKS `kid` miss — unauthenticated, since only the token header has been
    // decoded. Without a floor an attacker-chosen `kid` costs the AS one
    // discovery fetch per request. Refusing downgrades the read rather than
    // failing it, so a valid cached document is still served.
    const issuer = "https://as.example.com";
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    let jwksUri = `${issuer}/jwks-v1.json`;
    const cache = new MetadataCache(
      async () => {
        fetchCount += 1;
        return {
          document: { issuer, jwks_uri: jwksUri },
          expiresAt: undefined,
        };
      },
      { refreshSeconds: 100, expectedIssuer: issuer },
    );

    try {
      await cache.get();
      expect(fetchCount).toBe(1);

      // First miss after boot: admitted, so a real rotation is followed at once.
      await cache.get(true);
      expect(fetchCount).toBe(2);

      // A flood of misses inside the floor costs the AS nothing more.
      now = (t0 + 5) * 1000;
      jwksUri = `${issuer}/jwks-v2.json`;
      for (let i = 0; i < 10; i += 1) {
        await cache.get(true);
      }
      expect(fetchCount).toBe(2);
      expect((await cache.get()).jwks_uri).toBe(`${issuer}/jwks-v1.json`);

      // Past the floor — `min(refreshSeconds, 60)` — the next miss re-reads and
      // the rotation lands.
      now = (t0 + 61) * 1000;
      await cache.get(true);
      expect(fetchCount).toBe(3);
      expect((await cache.get()).jwks_uri).toBe(`${issuer}/jwks-v2.json`);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("does not re-attempt a failed fetch before the retry floor elapses", async () => {
    // Once the refresh interval lapses against an unreachable upstream, every
    // call would otherwise start a fresh fetch and pay the timeout again — the
    // in-flight dedupe collapses a wave of concurrent callers, not the waves
    // that follow. The floor turns that into one attempt per
    // `max(1, min(30, refreshSeconds))`, serving the last known good document
    // in between.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    let failing = false;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        if (failing) {
          throw new Error("upstream unreachable");
        }
        return { document: { v: fetchCount }, expiresAt: undefined };
      },
      { refreshSeconds: 100, errorFactory: (m) => new Error(m) },
    );

    try {
      expect(await cache.get()).toEqual({ v: 1 });
      failing = true;

      // Expired: this call pays for the attempt, which fails and opens the
      // floor. The cached document is still served.
      now = (t0 + 101) * 1000;
      expect(await cache.get()).toEqual({ v: 1 });
      expect(fetchCount).toBe(2);

      // Inside the floor nothing reaches upstream — not an ordinary read, not
      // a forced one. Both are served from cache.
      now = (t0 + 102) * 1000;
      expect(await cache.get()).toEqual({ v: 1 });
      expect(await cache.get(true)).toEqual({ v: 1 });
      expect(fetchCount).toBe(2);

      // The floor — min(30, refreshSeconds) after the failure — elapses, and
      // the next call retries. Upstream is back, so the fresh document lands.
      failing = false;
      now = (t0 + 131) * 1000;
      expect(await cache.get()).toEqual({ v: 3 });
      expect(fetchCount).toBe(3);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("fails fast inside the floor when nothing is cached", async () => {
    // With no last known good document there is nothing to serve, so refusal
    // surfaces the retained failure immediately instead of stalling the caller
    // on another doomed fetch.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        throw new Error("nope");
      },
      { refreshSeconds: 100, errorFactory: (message) => new Error(message) },
    );

    try {
      await expect(cache.get()).rejects.toThrow(/Failed to fetch document: nope/);
      expect(fetchCount).toBe(1);

      // Same typed error, no fetch attempt.
      now = (t0 + 1) * 1000;
      await expect(cache.get()).rejects.toThrow(/Failed to fetch document: nope/);
      expect(fetchCount).toBe(1);

      // Past the floor the attempt is admitted again.
      now = (t0 + 31) * 1000;
      await expect(cache.get()).rejects.toThrow(/Failed to fetch document: nope/);
      expect(fetchCount).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("closes the floor on a successful fetch", async () => {
    // Success must clear the failure state, not restart the window: a forced
    // read shortly after a successful one is admitted, where a floor stamped
    // at the success would have refused it and served the older document.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        if (fetchCount === 1) {
          throw new Error("upstream unreachable");
        }
        return { document: { v: fetchCount }, expiresAt: undefined };
      },
      { refreshSeconds: 100, errorFactory: (message) => new Error(message) },
    );

    try {
      await expect(cache.get()).rejects.toThrow();
      expect(fetchCount).toBe(1);

      // Floor elapsed; the retry succeeds and closes it.
      now = (t0 + 31) * 1000;
      expect(await cache.get()).toEqual({ v: 2 });

      // Nine seconds later — inside what a floor restarted at the success
      // would still cover — a forced read reaches upstream.
      now = (t0 + 40) * 1000;
      expect(await cache.get(true)).toEqual({ v: 3 });
      expect(fetchCount).toBe(3);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("caps the floor at the refresh interval and lifts it to one second", async () => {
    // `max(1, min(configured, refreshSeconds))`: a cache asked to refresh
    // every 2 seconds must not be pinned to the 30-second default, and a
    // configured zero must not collapse the floor entirely — that would put
    // the unbounded retry behaviour back under another name.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    let failing = true;
    const shortRefresh = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        if (failing) {
          throw new Error("down");
        }
        return { document: { v: fetchCount }, expiresAt: undefined };
      },
      { refreshSeconds: 2, errorFactory: (message) => new Error(message) },
    );

    try {
      await expect(shortRefresh.get()).rejects.toThrow();
      now = (t0 + 1) * 1000;
      await expect(shortRefresh.get()).rejects.toThrow();
      expect(fetchCount).toBe(1);

      // The interval, not the default, bounds the floor: 2 s, not 30.
      failing = false;
      now = (t0 + 2) * 1000;
      expect(await shortRefresh.get()).toEqual({ v: 2 });
      expect(fetchCount).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }

    let zeroFloorFetches = 0;
    const zeroConfigured = new DocumentCache<Doc>(
      async () => {
        zeroFloorFetches += 1;
        throw new Error("down");
      },
      {
        refreshSeconds: 100,
        failureBackoffSeconds: 0,
        errorFactory: (message) => new Error(message),
      },
    );

    const zeroSpy = vi.spyOn(Date, "now");
    try {
      const t1 = 1_700_001_000;
      zeroSpy.mockReturnValue(t1 * 1000);
      await expect(zeroConfigured.get()).rejects.toThrow();
      await expect(zeroConfigured.get()).rejects.toThrow();
      expect(zeroFloorFetches).toBe(1);

      zeroSpy.mockReturnValue((t1 + 1) * 1000);
      await expect(zeroConfigured.get()).rejects.toThrow();
      expect(zeroFloorFetches).toBe(2);
    } finally {
      zeroSpy.mockRestore();
    }
  });

  it("does not open the floor when a superseded fetch fails after a newer one committed", async () => {
    // The failure path must carry the same sequence guard as the success path:
    // an older fetch that fails after a newer one has already committed proves
    // nothing about the upstream now — it demonstrably answered seconds ago —
    // and stamping the floor from it would refuse the next forced read for up
    // to a full window. Under steady verify traffic this is the ordinary
    // shape: a background refresh opens at 80% of TTL, a `kid` miss forces a
    // read, and the background refresh returns last and fails.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    const release: Array<(ok: boolean) => void> = [];
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        const document = { v: fetchCount };
        await new Promise<void>((resolve, reject) => {
          release.push((ok) =>
            ok ? resolve() : reject(new Error("stale fetch failed")),
          );
        });
        return { document, expiresAt: undefined };
      },
      { refreshSeconds: 100, errorFactory: (message) => new Error(message) },
    );

    try {
      const boot = cache.get();
      release[0]?.(true);
      await boot;

      // Into the stale-while-revalidate window: an ordinary read starts a
      // non-forced background refresh [1], then a forced read [2] runs
      // concurrently — a forced caller deliberately does not join it.
      now = (t0 + 85) * 1000;
      await cache.get();
      const forced = cache.get(true);

      // The forced read succeeds and commits first; the stale background
      // refresh then fails.
      release[2]?.(true);
      await forced;
      release[1]?.(false);
      await cache.close();

      // The superseded failure must not have opened the floor: the next
      // forced read reaches upstream instead of being served the cache.
      // Asserted before releasing: the fetcher increments synchronously, so a
      // floored read would leave the count unchanged here.
      now = (t0 + 86) * 1000;
      const attemptsBefore = fetchCount;
      const next = cache.get(true);
      expect(fetchCount).toBe(attemptsBefore + 1);
      release[3]?.(true);
      await next;
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("does not spend the forced-read budget on a floor-refused metadata read", async () => {
    // `admitForcedRead()` stamps the forced-read budget, which exists solely
    // to cap what an attacker-chosen `kid` can make the SDK ask of the AS.
    // A read the failure floor is going to refuse sends nothing upstream, so
    // it must not spend that budget: otherwise the first miss after the floor
    // elapses — exactly the read that follows a rotation — is downgraded to
    // an ordinary one and served the withdrawn document.
    const issuer = "https://as.example.com";
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    const attempts: Array<{ at: number; forced: boolean }> = [];
    let failing = false;
    let jwksUri = `${issuer}/jwks-old.json`;
    const cache = new MetadataCache(
      async (forceUpstream) => {
        attempts.push({
          at: Math.floor(Date.now() / 1000) - t0,
          forced: forceUpstream,
        });
        if (failing) {
          throw new Error("as unreachable");
        }
        return { document: { issuer, jwks_uri: jwksUri }, expiresAt: undefined };
      },
      { refreshSeconds: 3600, expectedIssuer: issuer },
    );

    try {
      await cache.get();

      // At 80% of the interval the background refresh fails, opening the
      // 30-second failure floor.
      failing = true;
      now = (t0 + 2880) * 1000;
      await cache.get();
      await cache.close();

      // A `kid` miss inside the floor: refused, downgraded, served from
      // cache — and the 60-second forced-read budget must not be burnt.
      now = (t0 + 2881) * 1000;
      expect((await cache.get(true)).jwks_uri).toBe(`${issuer}/jwks-old.json`);

      // The AS recovers and rotates. The first miss past the failure floor
      // must be a FORCED attempt that lands the rotation.
      failing = false;
      jwksUri = `${issuer}/jwks-new.json`;
      now = (t0 + 2911) * 1000;
      expect((await cache.get(true)).jwks_uri).toBe(`${issuer}/jwks-new.json`);
      expect(attempts).toEqual([
        { at: 0, forced: false },
        { at: 2880, forced: false },
        { at: 2911, forced: true },
      ]);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("honours a configured failureBackoffSeconds", async () => {
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        throw new Error("down");
      },
      {
        refreshSeconds: 100,
        failureBackoffSeconds: 5,
        errorFactory: (message) => new Error(message),
      },
    );

    try {
      await expect(cache.get()).rejects.toThrow();
      now = (t0 + 4) * 1000;
      await expect(cache.get()).rejects.toThrow();
      expect(fetchCount).toBe(1);

      now = (t0 + 5) * 1000;
      await expect(cache.get()).rejects.toThrow();
      expect(fetchCount).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("applies no failure floor when refreshSeconds is zero", async () => {
    // `refreshSeconds: 0` means "re-read every time" — the opt-out the
    // CHANGELOG and the user guide document, and the configuration the
    // rotation conformance cases run. It must opt out of the failure floor
    // exactly as it opts out of the forced-read floor: clamping it to 1 would
    // refuse same-second retries the operator asked for.
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        throw new Error("down");
      },
      { refreshSeconds: 0, errorFactory: (message) => new Error(message) },
    );

    try {
      await expect(cache.get()).rejects.toThrow(/down/);
      await expect(cache.get()).rejects.toThrow(/down/);
      expect(fetchCount).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("falls back to the default floor when a knob is not finite", async () => {
    // `min`/`max` propagate `NaN`, and `x < NaN` is always false — an
    // unguarded clamp would silently disable the floor entirely, which is the
    // unbounded retry behaviour it exists to prevent, reachable from
    // `Number(process.env.X)` on an unset variable.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);

    let nanBackoffFetches = 0;
    const nanBackoff = new DocumentCache<Doc>(
      async () => {
        nanBackoffFetches += 1;
        throw new Error("down");
      },
      {
        refreshSeconds: 100,
        failureBackoffSeconds: Number.NaN,
        errorFactory: (message) => new Error(message),
      },
    );

    let nanRefreshFetches = 0;
    const nanRefresh = new DocumentCache<Doc>(
      async () => {
        nanRefreshFetches += 1;
        throw new Error("down");
      },
      {
        refreshSeconds: Number.NaN,
        errorFactory: (message) => new Error(message),
      },
    );

    try {
      await expect(nanBackoff.get()).rejects.toThrow(/down/);
      await expect(nanRefresh.get()).rejects.toThrow(/down/);

      // Inside the default 30-second floor: refused, no attempt.
      now = (t0 + 29) * 1000;
      await expect(nanBackoff.get()).rejects.toThrow(/down/);
      await expect(nanRefresh.get()).rejects.toThrow(/down/);
      expect(nanBackoffFetches).toBe(1);
      expect(nanRefreshFetches).toBe(1);

      // Past it: admitted again.
      now = (t0 + 30) * 1000;
      await expect(nanBackoff.get()).rejects.toThrow(/down/);
      await expect(nanRefresh.get()).rejects.toThrow(/down/);
      expect(nanBackoffFetches).toBe(2);
      expect(nanRefreshFetches).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("warns once per floor window when refusals suppress attempts", async () => {
    // An operator must be able to tell a 30-second backoff from a live
    // outage — the retained error is deliberately the same one a fresh
    // attempt would produce — but per-refusal logging under per-request
    // traffic would be spam, so the warning is bounded to one per window.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        throw new Error("down");
      },
      { refreshSeconds: 100, errorFactory: (message) => new Error(message) },
    );

    try {
      // The attempt itself does not warn — only a refusal does.
      await expect(cache.get()).rejects.toThrow();
      expect(warnSpy).not.toHaveBeenCalled();

      // First refusal in the window warns; the rest of the window is silent.
      now = (t0 + 1) * 1000;
      await expect(cache.get()).rejects.toThrow();
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenLastCalledWith(
        "[authplane] Document refresh backing off after a failed attempt (retry in 29s).",
      );
      now = (t0 + 2) * 1000;
      await expect(cache.get()).rejects.toThrow();
      await expect(cache.get()).rejects.toThrow();
      expect(warnSpy).toHaveBeenCalledTimes(1);

      // A new failed attempt opens a new window, and its first refusal warns
      // again.
      now = (t0 + 31) * 1000;
      await expect(cache.get()).rejects.toThrow();
      expect(fetchCount).toBe(2);
      now = (t0 + 32) * 1000;
      await expect(cache.get()).rejects.toThrow();
      expect(warnSpy).toHaveBeenCalledTimes(2);
    } finally {
      warnSpy.mockRestore();
      nowSpy.mockRestore();
    }
  });

  it("names the document in the backoff warning", async () => {
    // Two caches share this class, and a floored metadata document and a
    // floored JWKS one have different causes and different fixes — an operator
    // watching a resource server during an AS outage needs to know which is
    // backing off. Same labels as the java-sdk's `documentType`.
    const t0 = 1_700_000_000;
    let now = t0 * 1000;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => now);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const failingFetcher = async (): Promise<never> => {
      throw new Error("down");
    };
    const metadataCache = new MetadataCache(failingFetcher, {
      refreshSeconds: 100,
    });
    const jwksCache = new JWKSCache(failingFetcher, 100);

    try {
      await expect(metadataCache.get()).rejects.toThrow();
      await expect(jwksCache.get()).rejects.toThrow();
      now = (t0 + 1) * 1000;
      await expect(metadataCache.get()).rejects.toThrow();
      await expect(jwksCache.get()).rejects.toThrow();
      expect(warnSpy).toHaveBeenCalledTimes(2);
      expect(warnSpy).toHaveBeenNthCalledWith(
        1,
        "[authplane] metadata refresh backing off after a failed attempt (retry in 29s).",
      );
      expect(warnSpy).toHaveBeenNthCalledWith(
        2,
        "[authplane] JWKS refresh backing off after a failed attempt (retry in 29s).",
      );
    } finally {
      warnSpy.mockRestore();
      nowSpy.mockRestore();
    }
  });

  it("rethrows the retained failure with its stack intact on every refusal", async () => {
    // A refusal rethrows the retained instance itself — deliberately shared
    // across the window, so what callers catch is a real Error carrying the
    // original attempt's stack. A per-caller rebuild is worse: a
    // descriptor-copying clone has no `[[ErrorData]]` slot, so its `stack`
    // getter yields `undefined` and it fails `isNativeError` — a stackless
    // error on exactly the path that dominates during an outage.
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    const cache = new DocumentCache<Record<string, unknown>>(
      async () => {
        throw new MetadataFetchError("as down");
      },
      { refreshSeconds: 100 },
    );

    try {
      const errors: unknown[] = [];
      for (let i = 0; i < 3; i += 1) {
        await cache.get().catch((error: unknown) => errors.push(error));
      }
      const [first, second, third] = errors;
      // Same typed error a fresh attempt would have produced — refusals are
      // indistinguishable from the attempt they suppress, stack included.
      for (const error of errors) {
        expect(error).toBeInstanceOf(MetadataFetchError);
        expect((error as Error).message).toBe("as down");
        expect(typeof (error as Error).stack).toBe("string");
        expect((error as Error).stack).toContain("as down");
      }
      expect(second).toBe(first);
      expect(third).toBe(first);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("applies no forced-read floor when refreshSeconds is zero", async () => {
    // `refreshSeconds: 0` means "re-read every time", which is what the rotation
    // conformance cases configure, and what the CHANGELOG and the user guide both
    // tell operators opts out of the floor. The floor is `min(refreshSeconds, 60)`.
    //
    // Asserted on the flags the fetcher receives, not on the fetch count: at a TTL
    // of 0 an ordinary read fetches too, so a count is 3 whether or not the floor
    // refused anything. `forceUpstream` is the one thing the opt-out still changes
    // at this interval, and it is load-bearing — the join condition in
    // `fetchAndUpdate` treats a forced caller differently from an ordinary one.
    const issuer = "https://as.example.com";
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    const forcedFlags: boolean[] = [];
    const cache = new MetadataCache(
      async (forceUpstream) => {
        forcedFlags.push(forceUpstream);
        return {
          document: { issuer, jwks_uri: `${issuer}/jwks.json` },
          expiresAt: undefined,
        };
      },
      { refreshSeconds: 0, expectedIssuer: issuer },
    );

    try {
      await cache.get();
      await cache.get(true);
      await cache.get(true);
      expect(forcedFlags).toEqual([false, true, true]);
    } finally {
      nowSpy.mockRestore();
    }
  });
});

describe("fetching/documentCache server expiry", () => {
  // The pre-existing coverage above only exercises a server expiry in the
  // future, which is honoured before and after this fix and so says nothing
  // about a non-future one. These two pin the open door: `max-age=0` and a
  // stale `Expires:` header both arrive as a zero or negative TTL, and honouring
  // either leaves the document expired on every read — every verification takes
  // the synchronous re-fetch path, which on this cache is an unauthenticated
  // caller driving one upstream fetch per request.
  it("ignores a server expiry of zero and lets the configured interval govern", async () => {
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        return { document: { v: fetchCount }, expiresAt: 0 };
      },
      { refreshSeconds: 100 },
    );

    try {
      expect(await cache.get()).toEqual({ v: 1 });
      nowSpy.mockReturnValue((t0 + 50) * 1000);
      expect(await cache.get()).toEqual({ v: 1 });
      expect(fetchCount).toBe(1);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("ignores a server expiry that is already in the past when the document is cached", async () => {
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        return { document: { v: fetchCount }, expiresAt: t0 - 1 };
      },
      { refreshSeconds: 100 },
    );

    try {
      expect(await cache.get()).toEqual({ v: 1 });
      nowSpy.mockReturnValue((t0 + 50) * 1000);
      expect(await cache.get()).toEqual({ v: 1 });
      expect(fetchCount).toBe(1);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("still shortens the interval for a server expiry in the future", async () => {
    // The negative control for the two above: only a non-future expiry is
    // discarded. A server that asks for a shorter TTL than the configured
    // interval is still obeyed, so the fix cannot be "ignore the server".
    const t0 = 1_700_000_000;
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(t0 * 1000);

    let fetchCount = 0;
    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        return { document: { v: fetchCount }, expiresAt: t0 + 10 };
      },
      { refreshSeconds: 100 },
    );

    try {
      expect(await cache.get()).toEqual({ v: 1 });
      nowSpy.mockReturnValue((t0 + 11) * 1000);
      expect(await cache.get()).toEqual({ v: 2 });
      expect(fetchCount).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }
  });
});
