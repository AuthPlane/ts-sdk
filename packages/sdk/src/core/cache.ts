export interface TokenCacheEntry<T> {
	value: T;
	expiresAtSeconds: number;
}

/**
 * Small in-memory cache used to avoid repeated AS calls for short-lived tokens.
 *
 * Mirrors the Python SDK TokenCache behavior conceptually:
 * cache entries expire slightly before their server TTL (buffer) to reduce edge races.
 */
export class TokenCache<T> {
	private readonly ttlBufferSeconds: number;
	private readonly defaultTtlSeconds: number;
	private readonly map = new Map<string, TokenCacheEntry<T>>();

	public constructor(ttlBufferSeconds = 30, defaultTtlSeconds = 3600) {
		this.ttlBufferSeconds = ttlBufferSeconds;
		this.defaultTtlSeconds = defaultTtlSeconds;
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
		return entry.value;
	}

	public set(key: string, value: T, expiresInSeconds?: number | null): void {
		const ttl = expiresInSeconds ?? this.defaultTtlSeconds;
		const expiresAt =
			this.nowSeconds() + Math.max(0, ttl - this.ttlBufferSeconds);
		this.map.set(key, { value, expiresAtSeconds: expiresAt });
	}
}
