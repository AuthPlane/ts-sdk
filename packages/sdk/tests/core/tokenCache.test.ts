import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TokenCache } from "../../src/core/cache.js";

beforeEach(() => {
	vi.useFakeTimers();
	vi.setSystemTime(new Date("2026-06-05T00:00:00Z"));
});

afterEach(() => {
	vi.useRealTimers();
});

describe("TokenCache — TTL + buffer", () => {
	it("returns undefined for missing keys", () => {
		const cache = new TokenCache<string>();
		expect(cache.get("missing")).toBeUndefined();
	});

	it("returns the stored value before the buffered expiry", () => {
		const cache = new TokenCache<string>(0, 3600);
		cache.set("k", "v", 60);
		expect(cache.get("k")).toBe("v");
	});

	it("evicts an entry whose buffered TTL has elapsed", () => {
		const cache = new TokenCache<string>(0, 3600);
		cache.set("k", "v", 60);
		vi.advanceTimersByTime(61_000);
		expect(cache.get("k")).toBeUndefined();
	});

	it("subtracts the ttlBufferSeconds from the AS-supplied TTL", () => {
		// 60s TTL minus 30s buffer ⇒ effective expiry at +30s.
		const cache = new TokenCache<string>(30, 3600);
		cache.set("k", "v", 60);
		vi.advanceTimersByTime(29_000);
		expect(cache.get("k")).toBe("v");
		vi.advanceTimersByTime(2_000);
		expect(cache.get("k")).toBeUndefined();
	});

	it("falls back to defaultTtlSeconds when expiresInSeconds is omitted", () => {
		const cache = new TokenCache<string>(0, 120);
		cache.set("k", "v");
		vi.advanceTimersByTime(119_000);
		expect(cache.get("k")).toBe("v");
		vi.advanceTimersByTime(2_000);
		expect(cache.get("k")).toBeUndefined();
	});
});

describe("TokenCache — bounded LRU", () => {
	it("exposes a default maxEntries cap", () => {
		expect(TokenCache.DEFAULT_MAX_ENTRIES).toBe(10_000);
	});

	it("rejects a non-positive or non-integer maxEntries at construction", () => {
		expect(() => new TokenCache<string>(0, 3600, 0)).toThrow(RangeError);
		expect(() => new TokenCache<string>(0, 3600, -1)).toThrow(RangeError);
		expect(() => new TokenCache<string>(0, 3600, 1.5)).toThrow(RangeError);
	});

	it("evicts the least-recently-used entry when the cap is exceeded", () => {
		// Cap = 2. Insert k1, k2, k3 — k1 should be evicted as the LRU.
		const cache = new TokenCache<string>(0, 3600, 2);
		cache.set("k1", "v1", 3600);
		cache.set("k2", "v2", 3600);
		expect(cache.size()).toBe(2);
		cache.set("k3", "v3", 3600);
		expect(cache.size()).toBe(2);
		expect(cache.get("k1")).toBeUndefined();
		expect(cache.get("k2")).toBe("v2");
		expect(cache.get("k3")).toBe("v3");
	});

	it("bumps an entry to MRU on get so the next eviction targets a colder key", () => {
		// With cap = 2, touch k1 before inserting k3 — k2 should now be
		// the LRU victim instead of k1.
		const cache = new TokenCache<string>(0, 3600, 2);
		cache.set("k1", "v1", 3600);
		cache.set("k2", "v2", 3600);
		expect(cache.get("k1")).toBe("v1"); // touch
		cache.set("k3", "v3", 3600);
		expect(cache.get("k1")).toBe("v1");
		expect(cache.get("k2")).toBeUndefined();
		expect(cache.get("k3")).toBe("v3");
	});

	it("re-setting an existing key does not increase cache size", () => {
		const cache = new TokenCache<string>(0, 3600, 2);
		cache.set("k1", "v1", 3600);
		cache.set("k1", "v1-updated", 3600);
		expect(cache.size()).toBe(1);
		expect(cache.get("k1")).toBe("v1-updated");
	});

	it("re-setting an existing key bumps it to MRU (touch-on-write)", () => {
		// Without the touch-on-write bump, k1 stays LRU and gets evicted
		// when k3 lands. That'd surprise callers who treat `.set` as a
		// "I care about this entry" signal.
		const cache = new TokenCache<string>(0, 3600, 2);
		cache.set("k1", "v1", 3600);
		cache.set("k2", "v2", 3600);
		cache.set("k1", "v1-updated", 3600); // bump k1 to MRU
		cache.set("k3", "v3", 3600);
		expect(cache.get("k1")).toBe("v1-updated");
		expect(cache.get("k2")).toBeUndefined();
		expect(cache.get("k3")).toBe("v3");
	});

	it("does not store a token whose buffered TTL is <= 0", () => {
		// `expiresInSeconds <= ttlBufferSeconds` ⇒ the entry is dead on
		// arrival, so `set` early-returns on `bufferedTtl <= 0`.
		// Without this skip, the entry would sit in the map until the next
		// `get` reaped it — and on a bounded cache that's a wasted slot
		// that can evict a live entry.
		const cache = new TokenCache<string>(30, 3600);
		cache.set("k", "v", 30); // 30 - 30 = 0 ⇒ skipped
		expect(cache.size()).toBe(0);
		expect(cache.get("k")).toBeUndefined();
		cache.set("k2", "v2", 10); // 10 - 30 = -20 ⇒ skipped
		expect(cache.size()).toBe(0);
	});

	it("a dead-on-arrival set does not evict a live entry from the bounded cache", () => {
		// The teeth of the parity gap: with the cap, a stored-then-expired
		// entry occupies a slot and could evict a real, longer-lived entry
		// before the lazy `get` sweep ran. Pin that the skip path leaves
		// live entries alone.
		const cache = new TokenCache<string>(30, 3600, 2);
		cache.set("k1", "v1", 3600);
		cache.set("k2", "v2", 3600);
		cache.set("dead", "x", 10); // 10 - 30 = -20 ⇒ skipped, no eviction
		expect(cache.size()).toBe(2);
		expect(cache.get("k1")).toBe("v1");
		expect(cache.get("k2")).toBe("v2");
		expect(cache.get("dead")).toBeUndefined();
	});
});
