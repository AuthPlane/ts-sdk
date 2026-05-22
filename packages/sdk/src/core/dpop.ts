import {
	calculateJwkThumbprint,
	decodeProtectedHeader,
	importJWK,
	type JWK,
	jwtVerify,
} from "jose";
import {
	type DPoPAlgorithm,
	normalizeHtu,
	SUPPORTED_DPOP_ALGORITHMS,
	sha256Base64Url,
} from "../auth/dpop.js";
import {
	DPoPBindingMismatch,
	DPoPProofMissing,
	DPoPReplayDetected,
	InvalidDPoPProof,
} from "./errors.js";

// Re-export client-side DPoP so `@authplane/sdk/core` consumers still have a
// single surface. Client-side DPoP concretely lives in `src/auth/dpop.ts` so
// that the leaf `src/auth/*` layer can use it without importing from core.
export {
	type DPoPAlgorithm,
	DPoPKeyMaterial,
	type DPoPNonceStore,
	DPoPProvider,
	InMemoryDPoPNonceStore,
	SUPPORTED_DPOP_ALGORITHMS,
} from "../auth/dpop.js";

export type SupportedDPoPAlgorithm = (typeof SUPPORTED_DPOP_ALGORITHMS)[number];

/**
 * Per-request DPoP inputs for {@link AuthplaneResource.verify}.
 *
 * Carries only what RFC 9449 §7 says is per-request: the proof JWT and the
 * binding to this HTTP request (`htm`/`htu`). Replay store, accepted proof
 * algorithms, max proof age, and clock skew are per-resource configuration
 * carried on {@link InboundDPoPOptions}; mixing them per-call let two
 * handlers on the same resource deduplicate against different stores.
 */
export interface DPoPRequestContext {
	method: string;
	url: string;
	proof?: string | undefined;
}

export interface VerifiedDPoPProof {
	jkt: string;
	jti: string;
	iat: number;
}

/**
 * Atomic replay store used by inbound DPoP proof verification.
 *
 * `checkAndStore` returns `true` when the `jti` was newly stored (first sight)
 * and `false` when it was already present. Implementations MUST make the
 * check-and-store pair atomic so concurrent `verifyDpopProof` calls cannot
 * both pass with the same `jti` under a TOCTOU race.
 */
export interface DPoPReplayStore {
	checkAndStore(jti: string, expiresAtSeconds: number): Promise<boolean>;
}

export class InMemoryDPoPReplayStore implements DPoPReplayStore {
	private static readonly SWEEP_INTERVAL = 256;

	private readonly map = new Map<string, number>();
	private insertsSinceSweep = 0;

	/**
	 * Atomic by virtue of running synchronously (no `await`) inside a single
	 * event-loop tick — concurrent callers cannot interleave between the read
	 * and the write. Multi-process / distributed deployments should supply a
	 * Redis-backed implementation using `SET NX` (or equivalent).
	 *
	 * Memory is bounded by `(verifications/sec) × maxAgeSeconds`: expired
	 * entries are swept every {@link SWEEP_INTERVAL} inserts, so steady-state
	 * size tracks the valid-proof window rather than lifetime traffic.
	 */
	public async checkAndStore(
		jti: string,
		expiresAtSeconds: number,
	): Promise<boolean> {
		const now = Math.floor(Date.now() / 1000);
		const existing = this.map.get(jti);
		if (existing !== undefined && now < existing) {
			return false;
		}
		this.map.set(jti, expiresAtSeconds);
		this.insertsSinceSweep += 1;
		if (this.insertsSinceSweep >= InMemoryDPoPReplayStore.SWEEP_INTERVAL) {
			this.sweepExpired(now);
			this.insertsSinceSweep = 0;
		}
		return true;
	}

	private sweepExpired(nowSeconds: number): void {
		for (const [jti, expiresAt] of this.map) {
			if (nowSeconds >= expiresAt) {
				this.map.delete(jti);
			}
		}
	}
}

/**
 * Per-resource inbound DPoP validation policy
 * (RFC 9449 §7.1 + RFC 9728 §2).
 *
 * Passing any instance to `client.resource(..., inboundDPoP=...)` is the
 * on/off switch for advertising DPoP support in PRM
 * (`dpop_signing_alg_values_supported` and
 * `dpop_bound_access_tokens_required`). Omitting `inboundDPoP` keeps DPoP
 * fields out of PRM and rejects any DPoP signal at verify time.
 */
export interface InboundDPoPOptions {
	/**
	 * Replay detector for accepted proof `jti` values. When omitted, the
	 * resource allocates a per-resource {@link InMemoryDPoPReplayStore}.
	 * Use a shared store (Redis, database) for multi-process deployments.
	 */
	replayStore?: DPoPReplayStore;
	/** Maximum proof age accepted from `iat` (seconds). Defaults to 300. */
	maxProofAgeSeconds?: number;
	/** Allowable clock skew for proof time validation (seconds). Defaults to 30. */
	clockSkewSeconds?: number;
	/**
	 * Accepted JOSE `alg` values for DPoP proofs. Also advertised as
	 * `dpop_signing_alg_values_supported` in the PRM. Defaults to
	 * `["ES256", "RS256"]`. Narrowed to {@link DPoPAlgorithm} so typos
	 * fail at the type layer; JSON-config callers can cast at the
	 * boundary, and `normalizeInboundDPoPAlgorithms` keeps the runtime
	 * check for defense-in-depth.
	 */
	allowedProofAlgorithms?: readonly DPoPAlgorithm[];
	/**
	 * When `true`, advertises `dpop_bound_access_tokens_required: true` in
	 * the PRM and rejects bearer-only access tokens at verify time. When
	 * `false` (the default), the resource advertises DPoP capability while
	 * still accepting bearer-only tokens.
	 */
	required?: boolean;
}

/**
 * Validate an {@link InboundDPoPOptions} value and return a frozen copy of
 * `allowedProofAlgorithms` (or `undefined` to fall back to the default).
 *
 * Validation runs at resource construction so a misconfigured
 * `allowedProofAlgorithms` fails fast instead of at verify-time.
 */
export function normalizeInboundDPoPAlgorithms(
	algorithms: readonly DPoPAlgorithm[] | undefined,
): readonly DPoPAlgorithm[] | undefined {
	if (algorithms === undefined) {
		return undefined;
	}
	if (algorithms.length === 0) {
		throw new Error(
			`allowedProofAlgorithms must be non-empty; omit the field to accept the default ${JSON.stringify(SUPPORTED_DPOP_ALGORITHMS)}`,
		);
	}
	const supported = SUPPORTED_DPOP_ALGORITHMS as readonly string[];
	const invalid = algorithms.filter((alg) => !supported.includes(alg));
	if (invalid.length > 0) {
		throw new Error(
			`Unsupported DPoP proof algorithms ${JSON.stringify(invalid)}; only ${JSON.stringify(SUPPORTED_DPOP_ALGORITHMS)} are permitted`,
		);
	}
	return Object.freeze([...algorithms]);
}

const PRIVATE_JWK_PARAMS = new Set(["d", "p", "q", "dp", "dq", "qi", "oth"]);

function safeNormalizeHtu(url: string): string {
	try {
		return normalizeHtu(url);
	} catch (error) {
		throw new InvalidDPoPProof(`DPoP URL must be absolute: ${String(error)}`);
	}
}

export async function verifyDpopProof(options: {
	proof: string;
	method: string;
	url: string;
	accessToken: string;
	expectedJkt: string;
	maxAgeSeconds: number;
	clockSkewSeconds: number;
	replayStore: DPoPReplayStore;
	allowedAlgorithms?: readonly string[];
	expectedNonce?: string | undefined;
}): Promise<VerifiedDPoPProof> {
	let header: ReturnType<typeof decodeProtectedHeader>;
	try {
		header = decodeProtectedHeader(options.proof);
	} catch (error) {
		throw new InvalidDPoPProof(
			`Failed to decode DPoP proof header: ${String(error)}`,
		);
	}

	if (header.typ !== "dpop+jwt") {
		throw new InvalidDPoPProof(
			`DPoP proof header 'typ' must be 'dpop+jwt', got '${String(header.typ)}'`,
		);
	}

	const allowed: readonly string[] =
		options.allowedAlgorithms ?? SUPPORTED_DPOP_ALGORITHMS;
	const alg = typeof header.alg === "string" ? header.alg : "";
	if (!allowed.includes(alg)) {
		throw new InvalidDPoPProof(
			`Unsupported DPoP algorithm '${alg}'; expected one of ${allowed.join(", ")}`,
		);
	}

	const jwk = header.jwk as JWK | undefined;
	if (!jwk || typeof jwk !== "object") {
		throw new InvalidDPoPProof("DPoP proof missing 'jwk' header.");
	}
	for (const k of Object.keys(jwk)) {
		if (PRIVATE_JWK_PARAMS.has(k)) {
			throw new InvalidDPoPProof(
				"DPoP proof header JWK must not include private key material",
			);
		}
	}

	let payload: Record<string, unknown>;
	try {
		const key = await importJWK(jwk, alg);
		const result = await jwtVerify(options.proof, key, {
			algorithms: [alg],
			clockTolerance: options.clockSkewSeconds,
		});
		payload = result.payload as Record<string, unknown>;
	} catch (error) {
		if (error instanceof InvalidDPoPProof) {
			throw error;
		}
		throw new InvalidDPoPProof(
			`DPoP proof signature verification failed: ${String(error)}`,
		);
	}

	const htm = typeof payload.htm === "string" ? payload.htm : "";
	const htu = typeof payload.htu === "string" ? payload.htu : "";
	const iat = typeof payload.iat === "number" ? payload.iat : NaN;
	const jti = typeof payload.jti === "string" ? payload.jti : "";
	const ath = typeof payload.ath === "string" ? payload.ath : "";

	if (!htm || !htu || !Number.isFinite(iat) || !jti) {
		throw new InvalidDPoPProof("DPoP proof missing required claims.");
	}

	// RFC 9110 §9.1: method tokens are case-sensitive. Trust the caller's
	// method (already RFC-canonical uppercase for standard verbs) and require
	// the proof's declared `htm` to match it exactly.
	if (htm !== options.method.toUpperCase()) {
		throw new InvalidDPoPProof("DPoP proof htm mismatch.");
	}
	if (safeNormalizeHtu(htu) !== safeNormalizeHtu(options.url)) {
		throw new InvalidDPoPProof("DPoP proof htu mismatch.");
	}

	// RFC 9449 §8: resource servers MAY issue their own DPoP-Nonce challenges.
	// When a nonce policy is configured, proofs carrying a different or
	// missing `nonce` claim MUST be rejected.
	if (options.expectedNonce) {
		const actualNonce = typeof payload.nonce === "string" ? payload.nonce : "";
		if (actualNonce !== options.expectedNonce) {
			throw new InvalidDPoPProof(
				`DPoP proof nonce mismatch: expected '${options.expectedNonce}', got '${actualNonce}'`,
			);
		}
	}

	const now = Math.floor(Date.now() / 1000);
	if (iat > now + options.clockSkewSeconds) {
		throw new InvalidDPoPProof("DPoP proof iat is in the future.");
	}
	if (now - iat > options.maxAgeSeconds + options.clockSkewSeconds) {
		throw new InvalidDPoPProof("DPoP proof is too old.");
	}

	const expectedAth = sha256Base64Url(options.accessToken);
	if (ath && ath !== expectedAth) {
		throw new InvalidDPoPProof("DPoP proof ath mismatch.");
	}

	const jkt = await calculateJwkThumbprint(jwk);
	if (jkt !== options.expectedJkt) {
		throw new DPoPBindingMismatch(
			"DPoP proof key does not match token cnf.jkt.",
		);
	}

	const stored = await options.replayStore.checkAndStore(
		jti,
		iat + options.maxAgeSeconds,
	);
	if (!stored) {
		throw new DPoPReplayDetected("DPoP proof jti has already been seen.");
	}

	return { jkt, jti, iat };
}

export function requireDpopProof(ctx: DPoPRequestContext | undefined): string {
	if (!ctx?.proof) {
		throw new DPoPProofMissing();
	}
	return ctx.proof;
}
