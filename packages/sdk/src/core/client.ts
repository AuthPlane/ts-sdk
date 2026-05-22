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
		cacheTtlBufferSeconds?: number | undefined;
		defaultTtlSeconds?: number | undefined;
		circuitBreakerThreshold?: number | undefined;
		circuitBreakerCooldownSeconds?: number | undefined;
		dpopProvider?: DPoPProvider | undefined;
	}): Promise<AuthplaneClient> {
		const client = new AuthplaneClient();
		client.issuer = options.issuer.replace(/\/+$/g, "");
		client.authProvider = toAuthProvider(options.auth);

		const resolvedDevMode = options.devMode ?? false;
		const defaultSettings = FetchSettings.fromDevMode(resolvedDevMode);
		client.fetchSettings = options.fetchSettings ?? defaultSettings;

		client.jwksRefreshSeconds = options.jwksRefreshSeconds ?? 300;
		client.metadataRefreshSeconds = options.metadataRefreshSeconds ?? 3600;

		client.tokenCache = new TokenCache<TokenResponse>(
			options.cacheTtlBufferSeconds ?? 30,
			options.defaultTtlSeconds ?? 3600,
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
		const buildJwks = (jwksUri: string): JWKSCache => {
			const jwksFetcher = new DocumentFetcher<JwksDocument>(jwksUri, {
				settings: this.fetchSettings,
				maxSize: 65_536,
			});
			return new JWKSCache(() => jwksFetcher.fetch(), this.jwksRefreshSeconds);
		};

		this.metadataCache = new MetadataCache(() => metadataFetcher.fetch(), {
			refreshSeconds: this.metadataRefreshSeconds,
			expectedIssuer: this.issuer,
			allowHttp: this.fetchSettings.allowHttp,
			onChange: async (oldMetadata, newMetadata) => {
				const newJwksUri = newMetadata.jwks_uri;
				if (oldMetadata.jwks_uri === newJwksUri) return;
				if (typeof newJwksUri !== "string" || newJwksUri.length === 0) return;

				// Probe the candidate before swapping; on failure, keep the existing
				// cache in place so verification stays available. The old cache may
				// serve stale keys if the AS actually rotated signing material — that
				// is a louder failure mode than silently leaving `jwksCache` undefined.
				const candidate = buildJwks(newJwksUri);
				try {
					await candidate.get();
				} catch (error) {
					console.warn(
						`[authplane] JWKS URI rotated to '${newJwksUri}' but initial fetch failed; continuing with existing JWKS cache: ${String(error)}`,
					);
					return;
				}
				const previous = this.jwksCache;
				this.jwksCache = candidate;
				await previous?.close().catch(() => {});
			},
		});

		const jwksUri = await this.metadataCache.getJwksUri();
		this.jwksCache = buildJwks(jwksUri);
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
