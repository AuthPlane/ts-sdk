import { FetchSettings } from "../auth/fetchSettings.js";
import {
	type IntrospectionResponse,
	introspectToken,
} from "../auth/introspection.js";
import { clientCredentialsGrant } from "../auth/oauth/clientCredentials.js";
import { revokeToken } from "../auth/oauth/revocation.js";
import { exchange } from "../auth/oauth/tokenExchange.js";
import type {
	TokenExchangeOptions,
	TokenResponse,
} from "../auth/oauth/types.js";
import { type AuthProvider, toAuthProvider } from "./authProvider.js";
import { TokenCache } from "./cache.js";
import { CircuitBreaker } from "./circuitBreaker.js";
import { shouldTripCircuit } from "./circuitPolicy.js";
import type { ASCredentials } from "./credentials.js";
import type { DPoPProvider } from "./dpop.js";
import {
	JWKSCache,
	type JwksDocument,
	MetadataCache,
} from "./fetching/documentCache.js";
import { DocumentFetcher } from "./fetching/documentFetcher.js";
import { buildMetadataUrl } from "./fetching/metadataUrl.js";
import {
	AuthplaneResource,
	type AuthplaneResourceOptions,
} from "./resource.js";

/**
 * Unified OAuth client for Authplane authorization servers.
 *
 * Owns AS connection state (metadata, JWKS), caches, and resilience
 * (circuit breaker + token cache). Creates protected resources via `resource()`.
 */
export class AuthplaneClient {
	private issuer = "";
	private authProvider: AuthProvider | undefined;
	private fetchSettings: FetchSettings = new FetchSettings();
	private jwksRefreshSeconds = 300;
	private metadataRefreshSeconds = 3600;
	private fetchFailureBackoffSeconds: number | undefined;

	private metadataCache: MetadataCache | undefined;
	private jwksCache: JWKSCache | undefined;

	private tokenCache = new TokenCache<TokenResponse>();
	private circuitBreaker = new CircuitBreaker();
	private dpopProvider: DPoPProvider | undefined;

	private constructor() {}

	public static async create(options: {
		issuer: string;
		/**
		 * Authentication for AS-facing operations. Accepts any
		 * {@link AuthProvider} implementation (`ClientCredentialsProvider`,
		 * `private_key_jwt`, mTLS-aware providers, ...), or raw
		 * {@link ASCredentials} which are wrapped in `ClientCredentialsProvider`.
		 */
		auth?: AuthProvider | ASCredentials | undefined;
		devMode?: boolean | undefined;
		/**
		 * Outbound fetch hardening (SSRF, timeouts, allowlists) applied to both
		 * AS metadata and JWKS document fetches. When omitted, defaults are
		 * derived from `devMode`. RFC 8414 / RFC 7517 — both endpoints share the
		 * same threat profile, so a single setting governs both.
		 */
		fetchSettings?: FetchSettings | undefined;
		jwksRefreshSeconds?: number | undefined;
		metadataRefreshSeconds?: number | undefined;
		/**
		 * Minimum interval between metadata/JWKS fetch attempts after a failed
		 * one (default `30`). While it holds, the last known good document keeps
		 * being served — or the retained failure surfaces immediately when there
		 * is none — instead of every caller re-paying the fetch timeout against
		 * an unreachable AS. The effective floor per cache is
		 * `max(1, min(this, refreshSeconds))`, so it never exceeds the cache's
		 * own refresh interval and never collapses to zero — except that a cache
		 * whose refresh interval is `0` ("re-read every time") opts out of the
		 * floor entirely, and a non-finite value here falls back to the default.
		 * One knob governs both documents for the same reason `fetchSettings`
		 * does: they share the fetch path and the failure mode.
		 */
		fetchFailureBackoffSeconds?: number | undefined;
		cacheTtlBufferSeconds?: number | undefined;
		defaultTtlSeconds?: number | undefined;
		/**
		 * Maximum number of entries kept in the outbound token cache.
		 * Default `10_000`. Override on hosts with very high subject-token
		 * cardinality (token-exchange keys include the subject token, so this
		 * is the bound that actually limits memory growth).
		 */
		cacheMaxEntries?: number | undefined;
		circuitBreakerThreshold?: number | undefined;
		circuitBreakerCooldownSeconds?: number | undefined;
		dpopProvider?: DPoPProvider | undefined;
	}): Promise<AuthplaneClient> {
		const client = new AuthplaneClient();
		// RFC 8414 §2/§3.3: the issuer is an identity, not a location. Store it
		// byte-for-byte — it is passed to the token verifier as the expected `iss`
		// and compared against the AS metadata `issuer`. Silently stripping a
		// trailing slash here desynchronizes the configured issuer from the token's
		// `iss`, causing every otherwise-valid token to be rejected. Derivation of
		// the `.well-known` URL (which does drop a terminating slash) happens in
		// `buildMetadataUrl`, not here.
		client.issuer = options.issuer;
		client.authProvider = toAuthProvider(options.auth);

		const resolvedDevMode = options.devMode ?? false;
		const defaultSettings = FetchSettings.fromDevMode(resolvedDevMode);
		client.fetchSettings = options.fetchSettings ?? defaultSettings;

		client.jwksRefreshSeconds = options.jwksRefreshSeconds ?? 300;
		client.metadataRefreshSeconds = options.metadataRefreshSeconds ?? 3600;
		client.fetchFailureBackoffSeconds = options.fetchFailureBackoffSeconds;

		client.tokenCache = new TokenCache<TokenResponse>(
			options.cacheTtlBufferSeconds ?? 30,
			options.defaultTtlSeconds ?? 3600,
			options.cacheMaxEntries ?? TokenCache.DEFAULT_MAX_ENTRIES,
		);
		client.circuitBreaker = new CircuitBreaker(
			options.circuitBreakerThreshold ?? 5,
			options.circuitBreakerCooldownSeconds ?? 30,
		);
		client.dpopProvider = options.dpopProvider;

		await client.initializeCaches();
		return client;
	}

	private async initializeCaches(): Promise<void> {
		const metadataUrl = buildMetadataUrl(this.issuer);
		const metadataFetcher = new DocumentFetcher<Record<string, unknown>>(
			metadataUrl,
			{
				settings: this.fetchSettings,
				maxSize: 131_072,
			},
		);
		const metadataCache = new MetadataCache(() => metadataFetcher.fetch(), {
			refreshSeconds: this.metadataRefreshSeconds,
			failureBackoffSeconds: this.fetchFailureBackoffSeconds,
			expectedIssuer: this.issuer,
			allowHttp: this.fetchSettings.allowHttp,
		});
		this.metadataCache = metadataCache;

		// The JWKS URI is resolved from the metadata cache on every JWKS fetch,
		// rather than captured once and rebound when the document changes. That
		// leaves no window in which the cache holds keys fetched from a URI the
		// current metadata no longer names, and no second cache object to swap in:
		// a rotation takes effect on the next JWKS fetch, whichever path reaches
		// it first. `getJwksUri()` reads the validated document, so a metadata
		// response that fails validation can never redirect key retrieval.
		// Read the metadata document once here so a malformed or unreachable one
		// fails `create()` as a metadata error, rather than reaching the operator
		// wrapped in whatever the first JWKS fetch happened to raise.
		await metadataCache.get();

		const settings = this.fetchSettings;
		this.jwksCache = new JWKSCache(
			async (forceUpstream) => {
				// A forced JWKS fetch means the caller already missed the `kid` it
				// needed, so the cached metadata is not trustworthy about where keys
				// live either — re-read it rather than resolving against a document
				// that may name the withdrawn URI.
				const jwksUri = await metadataCache.getJwksUri(forceUpstream);
				const jwksFetcher = new DocumentFetcher<JwksDocument>(jwksUri, {
					settings,
					maxSize: 65_536,
				});
				return jwksFetcher.fetch();
			},
			this.jwksRefreshSeconds,
			this.fetchFailureBackoffSeconds,
		);
		await this.jwksCache.get();
	}

	private authHeaders(): Record<string, string> {
		return this.authProvider ? this.authProvider.authHeaders() : {};
	}

	public resource(options: AuthplaneResourceOptions): AuthplaneResource {
		if (!this.metadataCache || !this.jwksCache) {
			throw new Error("authplane: client not initialized");
		}

		return new AuthplaneResource({
			...options,
			issuer: this.issuer,
			metadataCache: this.metadataCache,
			fetchSettings: this.fetchSettings,
			getJwksCache: () => {
				if (!this.jwksCache) {
					throw new Error("authplane: client not initialized");
				}
				return this.jwksCache;
			},
		});
	}

	public async clientCredentials(
		scopes: string[] = [],
		resources: string[] = [],
	): Promise<TokenResponse> {
		this.circuitBreaker.assertClosed();
		const scopeParam = scopes.join(" ").trim();
		const filteredResources = resources.filter(
			(r) => typeof r === "string" && r.trim().length > 0,
		);
		const cacheKey = `client_credentials:${scopeParam}|resources:${filteredResources.join(",")}`;
		const cached = this.tokenCache.get(cacheKey);
		if (cached) {
			return cached;
		}

		if (!this.metadataCache) {
			throw new Error("authplane: client not initialized");
		}
		try {
			const tokenEndpoint = await this.metadataCache.getTokenEndpoint();
			const token = await clientCredentialsGrant({
				tokenEndpoint,
				scope: scopeParam.length > 0 ? scopeParam : undefined,
				resources: filteredResources,
				authHeader: this.authHeaders(),
				fetchSettings: this.fetchSettings,
				dpopProvider: this.dpopProvider,
			});
			this.tokenCache.set(cacheKey, token, token.expiresIn);
			this.circuitBreaker.recordSuccess();
			return token;
		} catch (e) {
			this.handleFailure(e);
			throw e;
		}
	}

	public async exchange(
		tokenExchange: TokenExchangeOptions,
	): Promise<TokenResponse> {
		this.circuitBreaker.assertClosed();
		if (!this.metadataCache) {
			throw new Error("authplane: client not initialized");
		}
		try {
			const tokenEndpoint = await this.metadataCache.getTokenEndpoint();
			const token = await exchange({
				tokenEndpoint,
				exchange: tokenExchange,
				authHeader: this.authHeaders(),
				fetchSettings: this.fetchSettings,
				dpopProvider: this.dpopProvider,
			});
			this.circuitBreaker.recordSuccess();
			return token;
		} catch (e) {
			this.handleFailure(e);
			throw e;
		}
	}

	public async revoke(token: string): Promise<void> {
		this.circuitBreaker.assertClosed();
		if (!this.metadataCache) {
			throw new Error("authplane: client not initialized");
		}
		try {
			const revocationEndpoint =
				await this.metadataCache.getRevocationEndpoint();
			await revokeToken({
				revocationEndpoint,
				token,
				authHeader: this.authHeaders(),
				fetchSettings: this.fetchSettings,
				dpopProvider: this.dpopProvider,
			});
			this.circuitBreaker.recordSuccess();
		} catch (e) {
			this.handleFailure(e);
			throw e;
		}
	}

	private handleFailure(error: unknown): void {
		if (shouldTripCircuit(error)) {
			this.circuitBreaker.recordFailure();
		}
	}

	public async introspect(token: string): Promise<IntrospectionResponse> {
		if (!this.metadataCache) {
			throw new Error("authplane: client not initialized");
		}
		const introspectionEndpoint =
			await this.metadataCache.getIntrospectionEndpoint();
		return await introspectToken({
			introspectionEndpoint,
			token,
			authHeader: this.authHeaders(),
			fetchSettings: this.fetchSettings,
			dpopProvider: this.dpopProvider,
		});
	}

	public async close(): Promise<void> {
		await this.metadataCache?.close().catch(() => {});
		await this.jwksCache?.close().catch(() => {});
	}
}
