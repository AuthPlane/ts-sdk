import {
	decodeProtectedHeader,
	importJWK,
	errors as joseErrors,
	jwtVerify,
} from "jose";
import {
	type IntrospectionConfig,
	IntrospectionRevocation,
} from "../auth/introspection.js";
import { VerifiedClaims } from "./claims.js";
import { ALLOWED_ALGORITHMS, CLOCK_SKEW_SECONDS } from "./constants.js";
import type { ASCredentials } from "./credentials.js";
import {
	type DPoPAlgorithm,
	type DPoPReplayStore,
	type DPoPRequestContext,
	type InboundDPoPOptions,
	InMemoryDPoPReplayStore,
	normalizeInboundDPoPAlgorithms,
	SUPPORTED_DPOP_ALGORITHMS,
	type VerifiedDPoPProof,
	verifyDpopProof,
} from "./dpop.js";
import {
	DPoPBindingMismatch,
	DPoPNotSupported,
	DPoPProofMissing,
	InvalidClaims,
	InvalidSignature,
	TokenExpired,
	TokenRevoked,
} from "./errors.js";
import type {
	JWKSCache,
	Jwk,
	MetadataCache,
} from "./fetching/documentCache.js";
import type { FetchSettings } from "./fetching/fetchSettings.js";
import { IntrospectionChecker } from "./introspectionChecker.js";
import {
	buildPrm,
	oauthProtectedResourceMetadataDocumentUrl,
	type ProtectedResourceMetadata,
} from "./prm.js";

/**
 * Async callable for custom revocation checking.
 * Receives the verified claims and the raw token string.
 * Return `true` to reject the token (revoked).
 */
export type RevocationChecker = (
	claims: VerifiedClaims,
	rawToken: string,
) => Promise<boolean>;

export interface AuthplaneResourceOptions {
	/**
	 * Resource URI this token must be bound to.
	 */
	resource: string;

	/**
	 * List of scopes supported by this resource server.
	 * Used for RFC 9728 Protected Resource Metadata generation.
	 */
	scopes: string[];

	/**
	 * Allowed JWT `alg` values. Dangerous algorithms (HS*) are rejected.
	 */
	allowedAlgorithms?: string[];

	clockSkewSeconds?: number;
	devMode?: boolean;

	/**
	 * Client credentials for AS-facing operations (introspection).
	 * Used only when `revocationChecker` enables introspection.
	 */
	asCredentials?: ASCredentials;

	/**
	 * Controls token revocation checking after signature validation passes.
	 */
	revocationChecker?:
		| IntrospectionRevocation
		| IntrospectionConfig
		| RevocationChecker
		| undefined;

	/**
	 * Per-resource inbound DPoP policy (RFC 9449 §7.1 + RFC 9728 §2).
	 *
	 * Presence of this field is the on/off switch for advertising DPoP
	 * support in PRM (`dpop_signing_alg_values_supported` and
	 * `dpop_bound_access_tokens_required`) and for the verifier's three-mode
	 * model:
	 *
	 * - **Required** (`{ required: true }`) — every access token must be
	 *   DPoP-bound; bearer-only tokens are rejected.
	 * - **Supported** (`{}` or `{ required: false }`) — DPoP-bound tokens
	 *   are validated; bearer-only tokens are accepted; a proof on a
	 *   bearer-only token is rejected as malformed.
	 * - **Not configured** (omitted) — any DPoP signal in the request is
	 *   rejected (RFC 9449 §6 scopes proof validation to DPoP-supporting
	 *   resources). Plain bearer tokens are accepted.
	 */
	inboundDPoP?: InboundDPoPOptions;

	/**
	 * When `true`, any error raised by the revocation checker (introspection
	 * transport error, missing metadata endpoint, user-supplied callback throw)
	 * rejects the token with {@link TokenRevoked}.
	 *
	 * When `false` (default), revocation-checker errors are logged and the
	 * token is accepted. Availability over security.
	 */
	failClosed?: boolean;
}

type InternalResourceOptions = AuthplaneResourceOptions & {
	issuer: string;
	metadataCache: MetadataCache;
	fetchSettings: FetchSettings;
	getJwksCache: () => JWKSCache;
};

/**
 * `AuthplaneResource` validates OAuth 2.1 JWT access tokens for a given resource server.
 *
 * It does not own metadata discovery or JWKS caching; those are provided by `AuthplaneClient`.
 */
export class AuthplaneResource {
	private static readonly DANGEROUS_ALGORITHMS = new Set([
		"none",
		"HS256",
		"HS384",
		"HS512",
	]);

	private readonly issuer: string;
	private readonly resource: string;
	private readonly allowedAlgorithms: readonly string[];
	private readonly clockSkewSeconds: number;
	private readonly failClosed: boolean;

	private readonly inboundDPoPConfigured: boolean;
	private readonly dpopRequired: boolean;
	private readonly dpopMaxProofAgeSeconds: number;
	private readonly dpopClockSkewSeconds: number;
	private readonly dpopAllowedProofAlgorithms: readonly DPoPAlgorithm[];
	private readonly dpopReplayStore: DPoPReplayStore | undefined;

	public readonly scopes: readonly string[];
	private readonly asCredentials: ASCredentials | undefined;
	private readonly revocationChecker:
		| IntrospectionRevocation
		| IntrospectionConfig
		| RevocationChecker
		| undefined;

	private readonly getJwksCache: () => JWKSCache;
	private readonly introspectionChecker: IntrospectionChecker | undefined;

	public constructor(options: InternalResourceOptions) {
		const allowedAlgorithms = options.allowedAlgorithms ?? [
			...ALLOWED_ALGORITHMS,
		];

		const dangerousFound = allowedAlgorithms.filter((algorithm) =>
			AuthplaneResource.DANGEROUS_ALGORITHMS.has(algorithm),
		);
		if (dangerousFound.length > 0) {
			throw new Error(
				`Dangerous algorithms are not allowed: ${dangerousFound.join(", ")}.`,
			);
		}

		this.issuer = options.issuer;
		this.resource = options.resource;
		this.scopes = Object.freeze([...options.scopes]);
		this.allowedAlgorithms = Object.freeze(allowedAlgorithms);
		this.clockSkewSeconds = options.clockSkewSeconds ?? CLOCK_SKEW_SECONDS;
		this.failClosed = options.failClosed ?? false;

		// Per-resource DPoP policy (RFC 9728 §2 + RFC 9449 §7.1). Tuning
		// lives at-rest so a missing per-request context cannot silently
		// bypass sender-binding. Presence of `inboundDPoP` is the on/off
		// switch for advertising DPoP support in PRM; `required` further
		// promotes that to a hard requirement.
		const inbound = options.inboundDPoP;
		this.inboundDPoPConfigured = inbound !== undefined;
		this.dpopRequired = inbound?.required ?? false;
		this.dpopMaxProofAgeSeconds = inbound?.maxProofAgeSeconds ?? 300;
		this.dpopClockSkewSeconds = inbound?.clockSkewSeconds ?? CLOCK_SKEW_SECONDS;
		const normalizedAlgs = normalizeInboundDPoPAlgorithms(
			inbound?.allowedProofAlgorithms,
		);
		this.dpopAllowedProofAlgorithms =
			normalizedAlgs ?? Object.freeze([...SUPPORTED_DPOP_ALGORITHMS]);
		// Allocate a replay store only when the resource has opted into DPoP.
		// In Mode 3 (inboundDPoP undefined) the verify path rejects DPoP signals
		// before reaching proof verification, so no replay store is needed.
		this.dpopReplayStore = inbound
			? (inbound.replayStore ?? new InMemoryDPoPReplayStore())
			: undefined;

		this.asCredentials = options.asCredentials;
		this.revocationChecker = options.revocationChecker;
		this.getJwksCache = options.getJwksCache;

		// Prepare introspection revocation checks eagerly so verify() stays fast.
		let introspectionChecker: IntrospectionChecker | undefined;
		if (
			this.isIntrospectionRevocation(this.revocationChecker) ||
			this.isIntrospectionConfig(this.revocationChecker)
		) {
			if (this.isIntrospectionRevocation(this.revocationChecker)) {
				if (!this.asCredentials) {
					console.warn(
						"[authplane] IntrospectionRevocation used without asCredentials; introspection requests will be unauthenticated.",
					);
				}
				introspectionChecker = new IntrospectionChecker(
					() => options.metadataCache.get(),
					{
						fetchSettings: options.fetchSettings,
						clientId: this.asCredentials?.clientId,
						clientSecret: this.asCredentials?.clientSecret,
					},
				);
			} else {
				const config = this.revocationChecker as IntrospectionConfig;
				introspectionChecker = new IntrospectionChecker(
					() => options.metadataCache.get(),
					{
						fetchSettings: options.fetchSettings,
						clientId: config.clientId,
						clientSecret: config.clientSecret,
					},
				);
			}
		}

		this.introspectionChecker = introspectionChecker;
	}

	private isIntrospectionRevocation(
		value: unknown,
	): value is IntrospectionRevocation {
		return value instanceof IntrospectionRevocation;
	}

	private isIntrospectionConfig(value: unknown): value is IntrospectionConfig {
		if (this.isIntrospectionRevocation(value)) {
			return false;
		}
		return (
			typeof value === "object" &&
			value !== null &&
			typeof (value as RevocationChecker).call !== "function"
		);
	}

	/** Verify a JWT access token and return validated claims. */
	public async verify(
		token: string,
		options: { dpopRequest?: DPoPRequestContext | undefined } = {},
	): Promise<VerifiedClaims> {
		const jwksCache = this.getJwksCache();

		let header: ReturnType<typeof decodeProtectedHeader>;
		try {
			header = decodeProtectedHeader(token);
		} catch (error) {
			throw new InvalidSignature(
				`Failed to decode token header: ${String(error)}`,
			);
		}

		const kid = header.kid;
		const alg = header.alg;
		const typ = header.typ;

		if (!kid) {
			throw new InvalidClaims("Token header missing 'kid' field.");
		}
		if (!alg) {
			throw new InvalidClaims("Token header missing 'alg' field.");
		}
		if (!this.allowedAlgorithms.includes(alg)) {
			throw new InvalidClaims(
				`Token algorithm '${alg}' is not in the allowed list: ${this.allowedAlgorithms.join(
					", ",
				)}`,
			);
		}
		if (typ !== "at+jwt") {
			throw new InvalidClaims(
				`Token type must be 'at+jwt', got '${String(typ)}'.`,
			);
		}

		let key = await jwksCache.getKeyByKid(kid, false, alg);
		if (!key) {
			key = await jwksCache.getKeyByKid(kid, true, alg);
		}
		if (!key) {
			// Distinguishable from a bad-token `InvalidSignature`: forced refresh
			// already ran and still didn't produce the kid. In production this is
			// the symptom of a missed key rotation or a failed `jwks_uri` swap.
			console.warn(
				`[authplane] Token kid '${kid}' not found in JWKS after forced refresh; possible missed key rotation or failed 'jwks_uri' swap.`,
			);
			throw new InvalidSignature(
				`Token kid '${kid}' not found in JWKS after refresh.`,
			);
		}

		let claims = await this.verifyWithKey(token, key, kid, alg);

		const dpopProof = await this.maybeVerifyDpop(
			claims,
			token,
			options.dpopRequest,
		);
		if (dpopProof) {
			claims = new VerifiedClaims({
				sub: claims.sub,
				clientId: claims.clientId,
				scopes: [...claims.scopes],
				issuer: claims.issuer,
				audience: [...claims.audience],
				expiresAt: claims.expiresAt,
				issuedAt: claims.issuedAt,
				jti: claims.jti,
				kid: claims.kid,
				agentId: claims.agentId,
				agentChain: [...claims.agentChain],
				notBefore: claims.notBefore,
				raw: { ...(claims.raw as Record<string, unknown>) },
				dpopProof,
			});
		}

		const revocationFn = this.resolveRevocationChecker();
		if (revocationFn) {
			let isRevoked: boolean;
			try {
				isRevoked = await revocationFn(claims, token);
			} catch (error) {
				if (this.failClosed) {
					throw new TokenRevoked(
						`Token '${claims.jti}' rejected: revocation check failed: ${String(error)}`,
					);
				}
				console.warn(
					`[authplane] Revocation check failed (fail-open): token accepted despite error: jti=${claims.jti} error=${String(error)}`,
				);
				isRevoked = false;
			}
			if (isRevoked) {
				throw new TokenRevoked(`Token '${claims.jti}' has been revoked`);
			}
		}

		return claims;
	}

	private resolveRevocationChecker(): RevocationChecker | undefined {
		if (
			this.isIntrospectionRevocation(this.revocationChecker) ||
			this.isIntrospectionConfig(this.revocationChecker)
		) {
			const introspection = this.introspectionChecker;
			if (!introspection) {
				return undefined;
			}
			return (claims, rawToken) => introspection.check(claims, rawToken);
		}
		if (this.revocationChecker !== undefined) {
			return this.revocationChecker as RevocationChecker;
		}
		return undefined;
	}

	private async maybeVerifyDpop(
		claims: VerifiedClaims,
		rawToken: string,
		dpopRequest: DPoPRequestContext | undefined,
	): Promise<VerifiedDPoPProof | undefined> {
		const raw = claims.raw as Record<string, unknown>;
		const cnf = raw.cnf;
		const tokenIsBound = typeof cnf === "object" && cnf !== null;
		const proofPresent = Boolean(dpopRequest?.proof);

		// Mode 3 — resource has not opted into DPoP. Reject any DPoP signal
		// upfront rather than fall back to bearer (which would silently drop
		// sender-binding) or apply ad-hoc defaults that were never advertised
		// in PRM (RFC 9449 §6).
		if (!this.inboundDPoPConfigured) {
			if (tokenIsBound || proofPresent) {
				throw new DPoPNotSupported();
			}
			return undefined;
		}

		// Modes 1 & 2 — resource supports DPoP (and possibly requires it).
		if (!tokenIsBound) {
			if (this.dpopRequired) {
				throw new DPoPBindingMismatch(
					"Resource requires DPoP-bound access tokens but the presented token has no `cnf.jkt`",
				);
			}
			if (proofPresent) {
				// Proof attached to a bearer-only token is structurally
				// malformed: the proof's `ath` claim has nothing to bind to.
				throw new DPoPBindingMismatch(
					"DPoP proof presented but the access token is not DPoP-bound (`cnf.jkt` missing); proof has nothing to bind to. Send the request without the DPoP header, or use a DPoP-bound access token.",
				);
			}
			return undefined; // plain bearer accepted (Mode 2)
		}

		const jkt = (cnf as Record<string, unknown>).jkt;
		if (typeof jkt !== "string" || jkt.length === 0) {
			// `cnf` present without `jkt` is structurally deficient per RFC 9449 §6;
			// the binding cannot be verified, so the token must be rejected.
			throw new InvalidClaims(
				"Access token has 'cnf' claim but missing 'cnf.jkt' — cannot verify DPoP binding",
			);
		}

		if (!dpopRequest) {
			throw new DPoPBindingMismatch(
				"Access token is DPoP-bound (`cnf.jkt` present) but no DPoP request context was provided",
			);
		}
		if (!dpopRequest.proof) {
			throw new DPoPProofMissing(
				"Access token is DPoP-bound (`cnf.jkt` present) but no DPoP proof was supplied",
			);
		}

		// `dpopReplayStore` is non-null by construction whenever execution
		// reaches here: the constructor allocates it iff `inboundDPoP` is
		// configured, and Mode 3 returns earlier in this function.
		return await verifyDpopProof({
			proof: dpopRequest.proof,
			method: dpopRequest.method,
			url: dpopRequest.url,
			accessToken: rawToken,
			expectedJkt: String(jkt),
			maxAgeSeconds: this.dpopMaxProofAgeSeconds,
			clockSkewSeconds: this.dpopClockSkewSeconds,
			allowedAlgorithms: this.dpopAllowedProofAlgorithms,
			// biome-ignore lint/style/noNonNullAssertion: see comment above
			replayStore: this.dpopReplayStore!,
		});
	}

	private ensureRequiredStringClaim(
		payload: Record<string, unknown>,
		claim: string,
	): string {
		const value = payload[claim];
		if (typeof value !== "string" || value.length === 0) {
			throw new InvalidClaims(`Token missing required '${claim}' claim.`);
		}
		return value;
	}

	private ensureRequiredNumberClaim(
		payload: Record<string, unknown>,
		claim: string,
	): number {
		const value = payload[claim];
		if (typeof value !== "number" || !Number.isFinite(value)) {
			throw new InvalidClaims(`Token missing required '${claim}' claim.`);
		}
		return value;
	}

	private async verifyWithKey(
		token: string,
		key: Jwk,
		kid: string,
		alg: string,
	): Promise<VerifiedClaims> {
		try {
			const importedKey = await importJWK(
				key as unknown as Parameters<typeof importJWK>[0],
				alg,
			);

			const verified = await jwtVerify(token, importedKey, {
				algorithms: [alg],
				issuer: this.issuer,
				audience: this.resource,
				typ: "at+jwt",
				clockTolerance: this.clockSkewSeconds,
			});

			const payload = verified.payload as Record<string, unknown>;

			let normalizedAudience: string[];
			if (Array.isArray(payload.aud)) {
				const audiences = payload.aud.filter(
					(a): a is string => typeof a === "string" && a.length > 0,
				);
				if (audiences.length === 0) {
					throw new InvalidClaims(
						"Token 'aud' must contain at least one non-empty string.",
					);
				}
				normalizedAudience = audiences;
			} else {
				normalizedAudience = [this.ensureRequiredStringClaim(payload, "aud")];
			}

			const iat = this.ensureRequiredNumberClaim(payload, "iat");
			const nowSeconds = Math.floor(Date.now() / 1000);
			if (iat > nowSeconds + this.clockSkewSeconds) {
				throw new InvalidClaims(
					`Token 'iat' claim is in the future (iat=${iat}, now=${nowSeconds}, leeway=${this.clockSkewSeconds}s).`,
				);
			}

			const scopeClaim = payload.scope;
			const scopeString = typeof scopeClaim === "string" ? scopeClaim : "";
			const scopes = scopeString.length > 0 ? scopeString.split(/\s+/) : [];

			const subject = this.ensureRequiredStringClaim(payload, "sub");
			const clientId = this.ensureRequiredStringClaim(payload, "client_id");
			const issuer = this.ensureRequiredStringClaim(payload, "iss");
			const expiresAt = this.ensureRequiredNumberClaim(payload, "exp");
			const jti = this.ensureRequiredStringClaim(payload, "jti");

			const agentId =
				typeof payload.agent_id === "string" ? payload.agent_id : "";

			const rawChain = payload.agent_chain;
			const agentChain = Array.isArray(rawChain)
				? rawChain
						.map((x) => (typeof x === "string" ? x : String(x)))
						.filter((x) => x.length > 0)
				: [];

			const rawNbf = payload.nbf;
			const notBefore =
				typeof rawNbf === "number"
					? Number.isFinite(rawNbf)
						? rawNbf
						: 0
					: typeof rawNbf === "string"
						? (() => {
								const n = Number(rawNbf);
								return Number.isFinite(n) ? n : 0;
							})()
						: 0;

			return new VerifiedClaims({
				sub: subject,
				clientId,
				scopes,
				issuer,
				audience: normalizedAudience,
				expiresAt,
				issuedAt: iat,
				jti,
				kid,
				agentId,
				agentChain,
				notBefore,
				raw: payload,
			});
		} catch (error) {
			if (error instanceof InvalidClaims) {
				throw error;
			}
			if (error instanceof joseErrors.JWTExpired) {
				throw new TokenExpired(`Token has expired: ${error.message}`);
			}
			if (error instanceof joseErrors.JWSSignatureVerificationFailed) {
				throw new InvalidSignature(
					`Token signature verification failed: ${error.message}`,
				);
			}
			if (error instanceof joseErrors.JWTClaimValidationFailed) {
				throw new InvalidClaims(
					`Token claims validation failed: ${error.message}`,
				);
			}
			if (error instanceof Error) {
				throw new InvalidSignature(
					`Token verification failed: ${error.message}`,
				);
			}
			throw new InvalidSignature("Token verification failed.");
		}
	}

	public prmResponse(): ProtectedResourceMetadata {
		if (!this.inboundDPoPConfigured) {
			return buildPrm(this.issuer, this.resource, this.scopes);
		}
		return buildPrm(this.issuer, this.resource, this.scopes, {
			dpopSigningAlgValuesSupported: this.dpopAllowedProofAlgorithms,
			dpopBoundAccessTokensRequired: this.dpopRequired,
		});
	}

	/** RFC 9728 §3.1 — absolute URL of the Protected Resource Metadata document for this resource. */
	public prmDocumentUrl(): string {
		return oauthProtectedResourceMetadataDocumentUrl(this.resource);
	}

	public async close(): Promise<void> {
		// AuthplaneResource does not own caches; no-op.
		return;
	}

	public get config(): {
		allowedAlgorithms: readonly string[];
		clockSkewSeconds: number;
		inboundDPoPConfigured: boolean;
		dpopRequired: boolean;
		dpopMaxProofAgeSeconds: number;
		dpopClockSkewSeconds: number;
		dpopAllowedProofAlgorithms: readonly DPoPAlgorithm[];
	} {
		return {
			allowedAlgorithms: this.allowedAlgorithms,
			clockSkewSeconds: this.clockSkewSeconds,
			inboundDPoPConfigured: this.inboundDPoPConfigured,
			dpopRequired: this.dpopRequired,
			dpopMaxProofAgeSeconds: this.dpopMaxProofAgeSeconds,
			dpopClockSkewSeconds: this.dpopClockSkewSeconds,
			dpopAllowedProofAlgorithms: this.dpopAllowedProofAlgorithms,
		};
	}
}
