import { describe, expect, it, vi } from "vitest";

import { DocumentCache } from "../../src/core/fetching/documentCache.js";

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

  it("triggers background refresh once and calls onChange when document differs", async () => {
    const t0 = 1_700_000_000;

    // Background refresh should start when nowSeconds - cacheTimeSeconds >= ttl * 0.8.
    // Here we force serverExpiresAt to make ttl smaller, so it triggers earlier.
    const onChange = vi.fn(async () => {});

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
      onChange,
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
      expect(onChange).toHaveBeenCalledTimes(1);
      expect(onChange).toHaveBeenCalledWith({ v: 1 }, { v: 2 });
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
});

