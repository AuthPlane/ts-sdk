import type { KeyObject } from "node:crypto";
import {
	createHash,
	createPrivateKey,
	createPublicKey,
	randomUUID,
} from "node:crypto";

import { exportJWK, type JWK, type KeyLike, SignJWT } from "jose";

/**
 * JOSE `alg` values accepted for DPoP — both for outbound proof signing
 * ({@link DPoPKeyMaterial}) and inbound proof verification (advertised in PRM
 * as `dpop_signing_alg_values_supported`). Single source of truth so the
 * verifier and PRM emitter cannot drift.
 *
 * `auth/*` is the leaf layer in the SDK, so this constant lives here and is
 * re-exported from `core/*` for consumers who only import the core surface.
 */
export const SUPPORTED_DPOP_ALGORITHMS = ["ES256", "RS256"] as const;

export type DPoPAlgorithm = (typeof SUPPORTED_DPOP_ALGORITHMS)[number];

// ---------------------------------------------------------------------------
// Helpers — exported so the inbound verifier in src/core/dpop.ts can reuse
// them without duplicating logic. `auth/*` is a leaf (cannot import core/*),
// so shared helpers belong here.
// ---------------------------------------------------------------------------

/**
 * Normalize a URL for DPoP `htu` generation and comparison (RFC 9449 §4.2).
 * Throws a plain `Error` on malformed input; callers that need SDK-specific
 * error classes should wrap.
 */
export function normalizeHtu(url: string): string {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error(`DPoP URL must be absolute, got '${url}'`);
	}
	if (!parsed.hostname) {
		throw new Error(`DPoP URL must be absolute, got '${url}'`);
	}
	const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
	const hostname = parsed.hostname.toLowerCase();
	let netloc = hostname;
	if (parsed.port) {
		const portNum = Number(parsed.port);
		const isDefaultPort =
			(scheme === "https" && portNum === 443) ||
			(scheme === "http" && portNum === 80);
		if (!isDefaultPort) {
			netloc = `${hostname}:${parsed.port}`;
		}
	}
	const path = parsed.pathname || "/";
	return `${scheme}://${netloc}${path}`;
}

export function sha256Base64Url(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("base64url");
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/**
 * Signing key material for DPoP proof generation.
 *
 * Parity with Python's `authplane.dpop.DPoPKeyMaterial`.
 */
export class DPoPKeyMaterial {
	public readonly privateKey: KeyLike;
	public readonly publicJwk: JWK;
	public readonly algorithm: DPoPAlgorithm;

	public constructor(options: {
		privateKey: KeyLike;
		publicJwk: JWK;
		algorithm?: DPoPAlgorithm | undefined;
	}) {
		const algorithm = options.algorithm ?? "ES256";
		if (!SUPPORTED_DPOP_ALGORITHMS.includes(algorithm)) {
			throw new Error(
				`DPoP algorithm must be one of ${SUPPORTED_DPOP_ALGORITHMS.join(", ")}, got '${algorithm}'`,
			);
		}
		this.privateKey = options.privateKey;
		this.publicJwk = options.publicJwk;
		this.algorithm = algorithm;
	}

	/**
	 * Import a PEM-encoded PKCS#8 private key and derive its public JWK.
	 * Parity with Python's `DPoPKeyMaterial.from_pem`.
	 */
	public static async fromPem(
		privateKeyPem: string,
		options: { algorithm?: DPoPAlgorithm } = {},
	): Promise<DPoPKeyMaterial> {
		const algorithm = options.algorithm ?? "ES256";
		const privateKey = createPrivateKey(privateKeyPem);
		const publicKey = createPublicKey(privateKey);
		const publicJwk = (await exportJWK(publicKey)) as JWK;
		return new DPoPKeyMaterial({
			privateKey: privateKey as KeyObject,
			publicJwk,
			algorithm,
		});
	}

	/** RFC 7638 SHA-256 thumbprint of the public JWK. */
	public get thumbprint(): string {
		return jwkThumbprint(this.publicJwk);
	}
}

/**
 * RFC 7638 SHA-256 thumbprint — sync implementation over the canonical JWK
 * members. Mirrors Python's `jwk_thumbprint`.
 */
function jwkThumbprint(jwk: JWK): string {
	const kty = String(jwk.kty ?? "");
	let members: Record<string, string>;
	if (kty === "EC") {
		members = {
			crv: String(jwk.crv ?? ""),
			kty,
			x: String(jwk.x ?? ""),
			y: String(jwk.y ?? ""),
		};
	} else if (kty === "RSA") {
		members = { e: String(jwk.e ?? ""), kty, n: String(jwk.n ?? "") };
	} else if (kty === "OKP") {
		members = {
			crv: String(jwk.crv ?? ""),
			kty,
			x: String(jwk.x ?? ""),
		};
	} else {
		throw new Error(`Unsupported DPoP JWK type: '${kty}'`);
	}
	const sortedKeys = Object.keys(members).sort();
	const canonical = `{${sortedKeys
		.map((k) => `${JSON.stringify(k)}:${JSON.stringify(members[k])}`)
		.join(",")}}`;
	return createHash("sha256").update(canonical, "utf8").digest("base64url");
}

// ---------------------------------------------------------------------------
// Nonce store
// ---------------------------------------------------------------------------

export interface DPoPNonceStore {
	get(key: string): string;
	put(key: string, nonce: string): void;
}

export class InMemoryDPoPNonceStore implements DPoPNonceStore {
	private readonly maxEntries: number;
	private readonly entries: Map<string, string>;

	public constructor(maxEntries = 128) {
		if (maxEntries <= 0) {
			throw new Error(
				`DPoP nonce store maxEntries must be positive, got ${maxEntries}`,
			);
		}
		this.maxEntries = maxEntries;
		this.entries = new Map();
	}

	public get(key: string): string {
		const value = this.entries.get(key) ?? "";
		if (value) {
			this.entries.delete(key);
			this.entries.set(key, value);
		}
		return value;
	}

	public put(key: string, nonce: string): void {
		if (this.entries.has(key)) {
			this.entries.delete(key);
		}
		this.entries.set(key, nonce);
		while (this.entries.size > this.maxEntries) {
			const first = this.entries.keys().next().value as string | undefined;
			if (!first) {
				break;
			}
			this.entries.delete(first);
		}
	}
}

// ---------------------------------------------------------------------------
// DPoPProvider — the single client-side DPoP entry point (RFC 9449 §4).
// Parity with Python's `DPoPProvider`.
// ---------------------------------------------------------------------------

export class DPoPProvider {
	private readonly keyMaterial: DPoPKeyMaterial;
	private readonly proofTtlSeconds: number;
	private readonly nonceStore: DPoPNonceStore;

	public constructor(options: {
		keyMaterial: DPoPKeyMaterial;
		proofTtlSeconds?: number | undefined;
		nonceStore?: DPoPNonceStore | undefined;
	}) {
		const proofTtlSeconds = options.proofTtlSeconds ?? 300;
		if (proofTtlSeconds <= 0) {
			throw new Error(
				`DPoP proofTtlSeconds must be positive, got ${proofTtlSeconds}`,
			);
		}
		this.keyMaterial = options.keyMaterial;
		this.proofTtlSeconds = proofTtlSeconds;
		this.nonceStore = options.nonceStore ?? new InMemoryDPoPNonceStore();
	}

	private nonceKey(url: string): string {
		const parsed = new URL(url);
		const scheme = parsed.protocol.toLowerCase();
		const host = parsed.hostname.toLowerCase();
		const port = parsed.port
			? Number.parseInt(parsed.port, 10)
			: scheme === "https:"
				? 443
				: 80;
		return `${scheme}//${host}:${port}`;
	}

	public noteNonce(url: string, nonce: string): void {
		this.nonceStore.put(this.nonceKey(url), nonce);
	}

	public currentNonce(url: string): string {
		return this.nonceStore.get(this.nonceKey(url));
	}

	public async createProof(options: {
		method: string;
		url: string;
		accessToken?: string | undefined;
		nonce?: string | undefined;
	}): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = {
			htm: options.method.toUpperCase(),
			htu: normalizeHtu(options.url),
			jti: randomUUID(),
			iat: now,
			exp: now + this.proofTtlSeconds,
		};
		const nonce = options.nonce ?? this.currentNonce(options.url);
		if (nonce) {
			payload.nonce = nonce;
		}
		if (options.accessToken) {
			payload.ath = sha256Base64Url(options.accessToken);
		}
		return await new SignJWT(payload)
			.setProtectedHeader({
				alg: this.keyMaterial.algorithm,
				typ: "dpop+jwt",
				jwk: this.keyMaterial.publicJwk,
			})
			.sign(this.keyMaterial.privateKey);
	}

	public async buildHeadersAsync(
		method: string,
		url: string,
		options: { accessToken?: string | undefined } = {},
	): Promise<Record<string, string>> {
		const proof = await this.createProof({
			method,
			url,
			accessToken: options.accessToken,
		});
		return { DPoP: proof };
	}
}
