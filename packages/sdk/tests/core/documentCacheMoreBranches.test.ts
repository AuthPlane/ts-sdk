import { describe, expect, it, vi } from "vitest";

import { DocumentCache, JWKSCache, MetadataCache } from "../../src/core/fetching/documentCache.js";
import { MetadataFetchError } from "../../src/core/errors.js";

type Doc = { v: number };

describe("fetching/documentCache extra branches", () => {
  it("covers JWKSCache containsKid() and getKeyByKid()", async () => {
    const fetcher = async () => {
      return {
        document: {
          keys: [{ kid: "kid_1" }, { kid: "kid_2" }],
        },
        expiresAt: undefined,
      };
    };

    const jwksCache = new JWKSCache(fetcher, 100);

    expect(await jwksCache.containsKid("kid_1")).toBe(true);
    expect(await jwksCache.containsKid("missing")).toBe(false);

    expect((await jwksCache.getKeyByKid("kid_2"))?.kid).toBe("kid_2");
    expect(await jwksCache.getKeyByKid("missing")).toBeUndefined();
  });

  it("throws MetadataFetchError when jwks_uri is missing/empty", async () => {
    const cache = new MetadataCache(
      async () => ({
        document: {},
        expiresAt: undefined,
      }),
      { refreshSeconds: 10 },
    );

    await expect(cache.getJwksUri()).rejects.toBeInstanceOf(MetadataFetchError);
  });

  it("throws MetadataFetchError when token_endpoint is missing/empty", async () => {
    const cache = new MetadataCache(
      async () => ({
        document: {},
        expiresAt: undefined,
      }),
      { refreshSeconds: 10 },
    );

    await expect(cache.getTokenEndpoint()).rejects.toBeInstanceOf(MetadataFetchError);
  });

  it("throws MetadataFetchError when revocation_endpoint is missing/empty", async () => {
    const cache = new MetadataCache(
      async () => ({
        document: {},
        expiresAt: undefined,
      }),
      { refreshSeconds: 10 },
    );

    await expect(cache.getRevocationEndpoint()).rejects.toBeInstanceOf(MetadataFetchError);
  });

  it("throws MetadataFetchError when introspection_endpoint is missing/empty", async () => {
    const cache = new MetadataCache(
      async () => ({
        document: {},
        expiresAt: undefined,
      }),
      { refreshSeconds: 10 },
    );

    await expect(cache.getIntrospectionEndpoint()).rejects.toBeInstanceOf(
      MetadataFetchError,
    );
  });

  it("covers shouldRefreshInBackground() ttl<=0 by moving time backwards", async () => {
    const t1 = 1_700_000_000;
    let fetchCount = 0;

    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => t1 * 1000);

    const cache = new DocumentCache<Doc>(
      async () => {
        fetchCount += 1;
        return {
          document: { v: 1 },
          // Make serverExpiresAt == cacheTimeSeconds so effective TTL becomes 0.
          expiresAt: t1,
        };
      },
      { refreshSeconds: 100 },
    );

    try {
      // Initial fetch at t1.
      const d1 = await cache.get();
      expect(d1).toEqual({ v: 1 });
      expect(fetchCount).toBe(1);

      // Move clock backwards so "hasValidCache" is still true, but ttl<=0
      // makes shouldRefreshInBackground return false.
      nowSpy.mockImplementation(() => (t1 - 1) * 1000);
      const d2 = await cache.get();
      expect(d2).toEqual({ v: 1 });
      expect(fetchCount).toBe(1);
    } finally {
      nowSpy.mockRestore();
    }
  });
});

