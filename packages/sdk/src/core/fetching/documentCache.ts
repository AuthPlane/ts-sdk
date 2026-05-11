import {
	JWKSFetchError,
	MetadataFetchError,
	MissingMetadataEndpoint,
} from "../errors.js";
import type { FetchResult } from "./fetchResult.js";

type Fetcher<TDocument extends Record<string, unknown>> = () => Promise<
	FetchResult<TDocument>
>;

export class DocumentCache<TDocument extends Record<string, unknown>> {
	private readonly fetcher: Fetcher<TDocument>;
	private readonly refreshSeconds: number;
	private readonly onChange?:
		| ((oldDoc: TDocument, newDoc: TDocument) => Promise<void>)
		| undefined;
	private readonly errorFactory: (message: string) => Error;

	private cache: TDocument | undefined;
	private cacheTimeSeconds = 0;
	private serverExpiresAt: number | undefined;
	private fetchInFlight: Promise<TDocument> | undefined;
	private refreshInFlight: Promise<void> | undefined;

	public constructor(
		fetcher: Fetcher<TDocument>,
		options: {
			refreshSeconds: number;
			errorFactory?: (message: string) => Error;
			onChange?: (oldDoc: TDocument, newDoc: TDocument) => Promise<void>;
		},
	) {
		this.fetcher = fetcher;
		this.refreshSeconds = options.refreshSeconds;
		this.onChange = options.onChange;
		this.errorFactory =
			options.errorFactory ?? ((message) => new JWKSFetchError(message));
	}

	private effectiveExpiresAt(): number {
		const localExpiry = this.cacheTimeSeconds + this.refreshSeconds;
		if (this.serverExpiresAt === undefined) {
			return localExpiry;
		}
		return Math.min(localExpiry, this.serverExpiresAt);
	}

	private shouldRefreshInBackground(nowSeconds: number): boolean {
		if (!this.cache) {
			return false;
		}
		const expiry = this.effectiveExpiresAt();
		const ttl = expiry - this.cacheTimeSeconds;
		if (ttl <= 0) {
			return false;
		}
		return nowSeconds - this.cacheTimeSeconds >= ttl * 0.8;
	}

	private triggerBackgroundRefresh(): void {
		if (this.refreshInFlight) {
			return;
		}
		this.refreshInFlight = this.get(true)
			.then(() => {})
			.finally(() => {
				this.refreshInFlight = undefined;
			});
	}

	private async fetchAndUpdate(): Promise<TDocument> {
		if (this.fetchInFlight) {
			return this.fetchInFlight;
		}

		this.fetchInFlight = (async () => {
			const oldCache = this.cache;
			const result = await this.fetcher();
			const now = Math.floor(Date.now() / 1000);
			this.cache = result.document;
			this.cacheTimeSeconds = now;
			this.serverExpiresAt = result.expiresAt;

			if (
				oldCache &&
				this.onChange &&
				JSON.stringify(oldCache) !== JSON.stringify(result.document)
			) {
				void this.onChange(oldCache, result.document);
			}

			return result.document;
		})();

		try {
			return await this.fetchInFlight;
		} finally {
			this.fetchInFlight = undefined;
		}
	}

	public async get(forceRefresh = false): Promise<TDocument> {
		const now = Math.floor(Date.now() / 1000);
		const hasValidCache =
			this.cache !== undefined && now < this.effectiveExpiresAt();

		if (!forceRefresh && hasValidCache) {
			if (this.shouldRefreshInBackground(now)) {
				this.triggerBackgroundRefresh();
			}
			return this.cache as TDocument;
		}

		try {
			return await this.fetchAndUpdate();
		} catch (error) {
			if (this.cache !== undefined) {
				return this.cache;
			}
			const message = error instanceof Error ? error.message : String(error);
			throw this.errorFactory(`Failed to fetch document: ${message}`);
		}
	}

	public async close(): Promise<void> {
		if (this.refreshInFlight) {
			await this.refreshInFlight.catch(() => {});
		}
	}
}

export interface Jwk extends Record<string, unknown> {
	[key: string]: unknown;
}

export interface JwksDocument extends Record<string, unknown> {
	[key: string]: unknown;
	keys: Jwk[];
}

export class JWKSCache extends DocumentCache<JwksDocument> {
	public constructor(fetcher: Fetcher<JwksDocument>, refreshSeconds: number) {
		super(fetcher, {
			refreshSeconds,
			errorFactory: (message) => new JWKSFetchError(message),
		});
	}

	private static isKeyUsableForVerification(
		key: Jwk,
		kid: string,
		algorithm: string | undefined,
	): boolean {
		if (key.kid !== kid) {
			return false;
		}
		// RFC 7517 §4.2: `use` restricts the key's purpose. Only `sig` is valid
		// for signature verification; absence means no restriction.
		const use = key.use;
		if (typeof use === "string" && use !== "sig") {
			return false;
		}
		// RFC 7517 §4.3: `key_ops` is a list of permitted operations. If
		// present, verification requires `verify` in the list.
		const keyOps = key.key_ops;
		if (Array.isArray(keyOps) && !keyOps.includes("verify")) {
			return false;
		}
		// RFC 7517 §4.4: `alg` when present pins the key to a single algorithm.
		const jwkAlg = key.alg;
		if (
			algorithm !== undefined &&
			typeof jwkAlg === "string" &&
			jwkAlg !== algorithm
		) {
			return false;
		}
		return true;
	}

	public async containsKid(
		kid: string,
		forceRefresh = false,
		algorithm?: string,
	): Promise<boolean> {
		const jwks = await this.get(forceRefresh);
		return jwks.keys.some((key) =>
			JWKSCache.isKeyUsableForVerification(key, kid, algorithm),
		);
	}

	public async getKeyByKid(
		kid: string,
		forceRefresh = false,
		algorithm?: string,
	): Promise<Jwk | undefined> {
		const jwks = await this.get(forceRefresh);
		return jwks.keys.find((key) =>
			JWKSCache.isKeyUsableForVerification(key, kid, algorithm),
		);
	}
}

export class MetadataCache extends DocumentCache<Record<string, unknown>> {
	private readonly expectedIssuer: string;
	private readonly allowHttp: boolean;
	private static readonly VALIDATED_ENDPOINT_FIELDS = [
		"jwks_uri",
		"token_endpoint",
		"introspection_endpoint",
		"revocation_endpoint",
	] as const;

	public constructor(
		fetcher: Fetcher<Record<string, unknown>>,
		options: {
			refreshSeconds: number;
			onChange?: (
				oldDoc: Record<string, unknown>,
				newDoc: Record<string, unknown>,
			) => Promise<void>;
			expectedIssuer?: string;
			allowHttp?: boolean;
		},
	) {
		const config: {
			refreshSeconds: number;
			onChange?: (
				oldDoc: Record<string, unknown>,
				newDoc: Record<string, unknown>,
			) => Promise<void>;
			errorFactory: (message: string) => Error;
		} = {
			refreshSeconds: options.refreshSeconds,
			errorFactory: (message) => new MetadataFetchError(message),
		};
		if (options.onChange) {
			config.onChange = options.onChange;
		}

		super(fetcher, {
			...config,
		});

		this.expectedIssuer = (options.expectedIssuer ?? "").replace(/\/+$/g, "");
		this.allowHttp = options.allowHttp ?? false;
	}

	private validateEndpointUrl(field: string, value: string): void {
		let parsed: URL;
		try {
			parsed = new URL(value);
		} catch {
			throw new MetadataFetchError(
				`AS metadata field '${field}' is not an absolute URL: '${value}'`,
			);
		}
		if (!parsed.host) {
			throw new MetadataFetchError(
				`AS metadata field '${field}' is not an absolute URL: '${value}'`,
			);
		}
		if (!this.allowHttp && parsed.protocol !== "https:") {
			throw new MetadataFetchError(
				`AS metadata field '${field}' must use HTTPS, got '${parsed.protocol.replace(/:$/, "")}': '${value}'`,
			);
		}
	}

	private validateMetadata(
		metadata: Record<string, unknown>,
	): Record<string, unknown> {
		const rawIssuer =
			typeof metadata.issuer === "string" ? metadata.issuer : "";
		const issuer = rawIssuer.replace(/\/+$/g, "");
		if (!issuer) {
			throw new MetadataFetchError(
				"AS metadata missing required 'issuer' field.",
			);
		}
		if (this.expectedIssuer && issuer !== this.expectedIssuer) {
			throw new MetadataFetchError(
				`AS metadata issuer mismatch: expected '${this.expectedIssuer}', got '${issuer}'.`,
			);
		}
		for (const field of MetadataCache.VALIDATED_ENDPOINT_FIELDS) {
			const value = metadata[field];
			if (typeof value === "string" && value.length > 0) {
				this.validateEndpointUrl(field, value);
			}
		}
		return metadata;
	}

	public override async get(
		forceRefresh = false,
	): Promise<Record<string, unknown>> {
		const metadata = await super.get(forceRefresh);
		return this.validateMetadata(metadata);
	}

	public async getJwksUri(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const jwksUri = metadata.jwks_uri;
		if (typeof jwksUri !== "string" || jwksUri.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'jwks_uri' field.",
			);
		}
		return jwksUri;
	}

	public async getTokenEndpoint(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const tokenEndpoint = metadata.token_endpoint;
		if (typeof tokenEndpoint !== "string" || tokenEndpoint.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'token_endpoint' field.",
			);
		}
		return tokenEndpoint;
	}

	public async getRevocationEndpoint(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const endpoint = metadata.revocation_endpoint;
		if (typeof endpoint !== "string" || endpoint.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'revocation_endpoint' field.",
			);
		}
		return endpoint;
	}

	public async getIntrospectionEndpoint(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const endpoint = metadata.introspection_endpoint;
		if (typeof endpoint !== "string" || endpoint.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'introspection_endpoint' field.",
			);
		}
		return endpoint;
	}
}
