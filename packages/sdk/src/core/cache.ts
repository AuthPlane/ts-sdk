export interface TokenCacheEntry<T> {
	value: T;
	expiresAtSeconds: number;
}

/**
 * Small in-memory cache used to avoid repeated AS calls for short-lived
 * tokens.
 *
 * Cache entries expire slightly before their server TTL (buffer) to reduce
 * edge races. The cache is bounded by a configurable `maxEntries` cap and
 * evicts the least-recently-used entry when the cap is exceeded.
 *
 * **Why the LRU bound matters.** Token-exchange cache keys are
 * high-cardinality because the subject token is part of the key, so
 * never-re-read keys accumulate without bound on an unbounded cache. The
 * cap is exposed alongside `ttlBufferSeconds` and `defaultTtlSeconds`.
 *
 * Recency is tracked by `Map`'s insertion-order iteration: every `get`
 * deletes and re-inserts the entry so the iterator's first key is always
 * the least-recently-touched.
 */
export class TokenCache<T> {
	/** Default cap on cached entries. */
	public static readonly DEFAULT_MAX_ENTRIES = 10_000;

	private readonly ttlBufferSeconds: number;
	private readonly defaultTtlSeconds: number;
	private readonly maxEntries: number;
	private readonly map = new Map<string, TokenCacheEntry<T>>();

	public constructor(
		ttlBufferSeconds = 30,
		defaultTtlSeconds = 3600,
		maxEntries: number = TokenCache.DEFAULT_MAX_ENTRIES,
	) {
		if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
			throw new RangeError(
				`TokenCache maxEntries must be a positive integer, got ${maxEntries}`,
			);
		}
		this.ttlBufferSeconds = ttlBufferSeconds;
		this.defaultTtlSeconds = defaultTtlSeconds;
		this.maxEntries = maxEntries;
	}

	/**
	 * Current number of stored entries — exposed for tests and operators
	 * that want to alert on cache pressure (steady-state size tracking
	 * `maxEntries` signals the cap is too low).
	 */
	public size(): number {
		return this.map.size;
	}

	private nowSeconds(): number {
		return Math.floor(Date.now() / 1000);
	}

	public get(key: string): T | undefined {
		const entry = this.map.get(key);
		if (!entry) {
			return undefined;
		}
		if (this.nowSeconds() >= entry.expiresAtSeconds) {
			this.map.delete(key);
			return undefined;
		}
		// Bump to most-recently-used: re-insert keeps the key at the end of
		// the Map's iteration order, so the LRU victim on overflow is
		// always the iterator's first entry.
		this.map.delete(key);
		this.map.set(key, entry);
		return entry.value;
	}

	public set(key: string, value: T, expiresInSeconds?: number | null): void {
		const ttl = expiresInSeconds ?? this.defaultTtlSeconds;
		const bufferedTtl = ttl - this.ttlBufferSeconds;
		if (bufferedTtl <= 0) {
			// A token whose effective lifetime is already
			// non-positive (`expires_in <= ttlBufferSeconds`) is born
			// expired. Storing it would consume a slot toward `maxEntries`
			// and could evict a live entry before `get` lazily reaps it.
			// Drop on the floor instead.
			return;
		}
		const expiresAt = this.nowSeconds() + bufferedTtl;
		// Re-inserting an existing key bumps it to MRU. Setting a new key
		// appends to the iteration end.
		this.map.delete(key);
		this.map.set(key, { value, expiresAtSeconds: expiresAt });
		// Evict at most one LRU victim: `maxEntries` is `readonly` and
		// `set` is the only path that can grow the map, so any overflow
		// is exactly +1.
		if (this.map.size > this.maxEntries) {
			const oldestKey = this.map.keys().next().value as string;
			this.map.delete(oldestKey);
		}
	}
}
