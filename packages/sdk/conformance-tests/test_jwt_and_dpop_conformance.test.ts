import { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";

import { decodeJwt, decodeProtectedHeader } from "jose";
import { expect } from "vitest";

import { FetchSettings } from "../src/auth/fetchSettings.js";
import { ProtocolError } from "../src/auth/errors.js";
import { AuthplaneClient } from "../src/core/client.js";
import {
	DPoPBindingMismatch,
	DPoPNotSupported,
	DPoPProofMissing,
	DPoPReplayDetected,
	InvalidClaims,
	InvalidDPoPProof,
	InvalidSignature,
	MissingMetadataEndpoint,
	ServerError,
	TokenExpired,
} from "../src/core/errors.js";
import {
	DPoPProvider,
	InMemoryDPoPReplayStore,
	verifyDpopProof,
	DPoPKeyMaterial,
} from "../src/core/dpop.js";
import { MetadataCache } from "../src/core/fetching/documentCache.js";
import { parseTokenResponse } from "../src/auth/oauth/parsing.js";
import { exchange } from "../src/auth/oauth/tokenExchange.js";
import { revokeToken } from "../src/auth/oauth/revocation.js";
import { buildPrm } from "../src/core/prm.js";

import { conformanceCase } from "./conformanceCase.js";
import {
	createMockAsServer,
	createTestFixture,
	createTokenFactory,
	generateDpopKeypair,
	generateEs256Keypair,
	signDpopProof,
	staticMetadataFetcher,
} from "./helpers.js";

// Python parity: mirrors `conformance-tests/test_jwt_and_dpop_conformance.py`.

const NO_SSRF = new FetchSettings({
	ssrfProtection: false,
	allowHttp: true,
	allowLocalhost: true,
	allowPrivateNetworks: true,
});

function sha256Base64Url(value: string): string {
	return createHash("sha256").update(value, "utf-8").digest("base64url");
}

// ---------------------------------------------------------------------------
// RFC 9068 — JWT access token validation
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc9068-valid-at-jwt-must-verify",
	"RFC9068: validates a correct token",
	async () => {
		const fixture = await createTestFixture();
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
			});
			const claims = await fixture.resource.verify(token);
			expect(claims.sub).toBe("user123");
			expect(claims.clientId).toBe("client456");
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-issuer-must-match",
	"RFC9068: token issuer must match configured issuer",
	async () => {
		const fixture = await createTestFixture();
		try {
			const token = await fixture.tokenFactory({
				iss: "https://wrong-issuer.com",
				aud: `${fixture.server.origin}/api`,
			});
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				InvalidClaims,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-audience-must-match-resource",
	"RFC9068: audience must match configured resource",
	async () => {
		const fixture = await createTestFixture();
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: "https://wrong-audience.com",
			});
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				InvalidClaims,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-required-claims-must-be-enforced",
	"RFC9068: required claims must be enforced",
	async () => {
		for (const missing of ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]) {
			const fixture = await createTestFixture();
			try {
				const token = await fixture.tokenFactory({
					iss: fixture.server.origin,
					aud: `${fixture.server.origin}/api`,
					excludeClaims: [missing],
				});
				await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
					InvalidClaims,
				);
			} finally {
				await fixture.close();
			}
		}
	},
);

conformanceCase(
	"rfc9068-token-header-must-contain-kid",
	"RFC9068: token header must contain kid",
	async () => {
		const fixture = await createTestFixture();
		try {
			const { SignJWT } = await import("jose");
			const now = Math.floor(Date.now() / 1000);
			const token = await new SignJWT({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				sub: "user123",
				client_id: "client456",
				exp: now + 3600,
				iat: now,
				jti: "token-id-123",
			})
				// kid deliberately omitted
				.setProtectedHeader({ alg: "ES256", typ: "at+jwt" })
				.sign(fixture.keypair.privateKey);
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				InvalidClaims,
			);
			await expect(fixture.resource.verify(token)).rejects.toThrow(/kid/);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-typ-must-be-at-jwt",
	"RFC9068: rejects wrong typ header",
	async () => {
		const fixture = await createTestFixture();
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				typ: "JWT",
			});
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				InvalidClaims,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-iat-future-must-be-rejected-beyond-leeway",
	"RFC9068: future iat must be rejected beyond leeway",
	async () => {
		const fixture = await createTestFixture();
		try {
			const now = Math.floor(Date.now() / 1000);
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				iat: now + 3600, // far in the future
				nbf: now + 3600,
				exp: now + 7200,
			});
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				InvalidClaims,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-nbf-must-be-honored-when-present",
	"RFC9068: nbf honored when present",
	async () => {
		const fixture = await createTestFixture();
		try {
			const now = Math.floor(Date.now() / 1000);
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				nbf: now + 600, // 10 minutes in the future
			});
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				InvalidClaims,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-token-header-must-contain-alg",
	"RFC9068: token header must contain alg",
	async () => {
		const fixture = await createTestFixture();
		try {
			// jose's SignJWT rejects empty alg, so forge a token directly.
			const header = Buffer.from(
				JSON.stringify({ typ: "at+jwt", kid: fixture.keypair.kid }),
			).toString("base64url");
			const payload = Buffer.from(
				JSON.stringify({
					iss: fixture.server.origin,
					aud: `${fixture.server.origin}/api`,
					sub: "user123",
					client_id: "client456",
					exp: Math.floor(Date.now() / 1000) + 3600,
					iat: Math.floor(Date.now() / 1000),
					jti: "token-id-123",
				}),
			).toString("base64url");
			const unsignedToken = `${header}.${payload}.signature`;
			await expect(
				fixture.resource.verify(unsignedToken),
			).rejects.toBeInstanceOf(InvalidClaims);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-signature-failure-must-reject-token",
	"RFC9068: signature failure rejects token",
	async () => {
		const fixture = await createTestFixture();
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
			});
			// Tamper with the signature segment.
			const [h, p] = token.split(".");
			const tampered = `${h}.${p}.${Buffer.from("tampered").toString("base64url")}`;
			await expect(fixture.resource.verify(tampered)).rejects.toBeInstanceOf(
				InvalidSignature,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9068-expiration-and-clock-skew-must-be-enforced",
	"RFC9068: exp/clock skew enforced",
	async () => {
		const fixture = await createTestFixture();
		try {
			const now = Math.floor(Date.now() / 1000);
			// exp past beyond skew must reject
			const expired = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				iat: now - 7200,
				exp: now - 3600,
				nbf: now - 7200,
			});
			await expect(fixture.resource.verify(expired)).rejects.toBeInstanceOf(
				TokenExpired,
			);

			// nbf future beyond skew must reject
			const notYet = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				nbf: now + 3600,
			});
			await expect(fixture.resource.verify(notYet)).rejects.toBeInstanceOf(
				InvalidClaims,
			);

			// exp within default skew (30s) must pass
			const freshlyExpired = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				exp: now - 5,
				iat: now - 3605,
			});
			await fixture.resource.verify(freshlyExpired);
		} finally {
			await fixture.close();
		}
	},
);

// ---------------------------------------------------------------------------
// RFC 8725 — algorithm restriction and JWKS discipline
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc8725-allowed-jwt-algorithms-must-be-restricted",
	"RFC8725: allowed JWT algorithms must be restricted",
	async () => {
		const fixture = await createTestFixture();
		try {
			// Constructor must reject dangerous algorithms.
			for (const alg of ["none", "HS256", "HS384", "HS512"]) {
				expect(() =>
					fixture.client.resource({
						resource: `${fixture.server.origin}/api`,
						scopes: ["read:data"],
						allowedAlgorithms: [alg],
					}),
				).toThrow();
			}
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc8725-kid-must-resolve-through-jwks-with-single-refresh-on-miss",
	"RFC8725: kid resolves via JWKS with single refresh on miss",
	async () => {
		// Catalog: unknown kid triggers one JWKS refresh, then either accept if
		// the key appeared or reject if still missing. Exercised end-to-end:
		// initial JWKS is empty; the refreshed JWKS includes the signing key.
		const keypair = await generateEs256Keypair("rotated-key");
		const { createServer } = await import("node:http");
		const server = createServer();
		await new Promise<void>((resolve) =>
			server.listen(0, "127.0.0.1", resolve),
		);
		const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		let jwksCalls = 0;
		server.on("request", (req, res) => {
			res.setHeader("content-type", "application/json");
			if (req.url === "/.well-known/oauth-authorization-server") {
				res.end(
					JSON.stringify({
						issuer: origin,
						jwks_uri: `${origin}/.well-known/jwks.json`,
					}),
				);
				return;
			}
			if (req.url === "/.well-known/jwks.json") {
				jwksCalls += 1;
				if (jwksCalls === 1) {
					res.end(JSON.stringify({ keys: [] }));
					return;
				}
				res.end(JSON.stringify(keypair.jwks));
				return;
			}
			res.statusCode = 404;
			res.end();
		});
		try {
			const client = await AuthplaneClient.create({
				issuer: origin,
				fetchSettings: NO_SSRF,
			});
			try {
				const resource = client.resource({
					resource: `${origin}/api`,
					scopes: ["read:data"],
				});
				const token = await createTokenFactory(keypair)({
					iss: origin,
					aud: `${origin}/api`,
				});
				await resource.verify(token);
				expect(jwksCalls).toBeGreaterThanOrEqual(2);
			} finally {
				await client.close();
			}
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	},
);

conformanceCase(
	"rfc8725-jwk-selection-must-honor-use-key-ops-and-alg",
	"RFC8725: JWK selection honors use/key_ops/alg",
	async () => {
		// Catalog: jwks_cache.get_key_by_kid(kid='k1', algorithm='ES256') must
		// reject keys whose declared use/key_ops/alg are incompatible with
		// verification. TS SDK's JWKSCache.getKeyByKid selects by kid only.
		const { JWKSCache } = await import("../src/core/fetching/documentCache.js");
		const keys = [
			{ kid: "k1", kty: "EC", use: "enc", alg: "ES256" },
			{ kid: "k1", kty: "EC", key_ops: ["sign"], alg: "ES256" },
			{ kid: "k1", kty: "EC", use: "sig", key_ops: ["verify"], alg: "RS256" },
		];
		const cache = new JWKSCache(
			async () => ({ document: { keys }, expiresAt: undefined }),
			3600,
		);
		// A compliant SDK would return `undefined` for kid='k1' with algorithm
		// 'ES256' because no key satisfies all three constraints. TS only
		// indexes by kid and returns the first match, ignoring algorithm.
		const key = await cache.getKeyByKid("k1", false, "ES256");
		expect(key).toBeUndefined();
	},
);

// ---------------------------------------------------------------------------
// RFC 9449 — outbound DPoP provider
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc9449-dpop-provider-must-build-dpop-jwt-header",
	"RFC9449: DPoP provider builds correct JWT header",
	async () => {
		const dpop = await generateDpopKeypair();
		const provider = new DPoPProvider({
			keyMaterial: new DPoPKeyMaterial({
				privateKey: dpop.privateKey,
				publicJwk: dpop.publicJwk,
				algorithm: "ES256",
			}),
		});
		const headers = await provider.buildHeadersAsync(
			"POST",
			"https://auth.example.com/oauth/token",
		);
		expect(headers.DPoP).toBeDefined();
		const header = decodeProtectedHeader(headers.DPoP as string);
		expect(header.typ).toBe("dpop+jwt");
		expect(header.alg).toBe("ES256");
		expect(header.jwk).toBeDefined();
	},
);

conformanceCase(
	"rfc9449-generated-dpop-proof-should-include-exp",
	"RFC9449: generated DPoP proof includes exp",
	async () => {
		const dpop = await generateDpopKeypair();
		const provider = new DPoPProvider({
			keyMaterial: new DPoPKeyMaterial({
				privateKey: dpop.privateKey,
				publicJwk: dpop.publicJwk,
				algorithm: "ES256",
			}),
		});
		const proof = await provider.createProof({
			method: "POST",
			url: "https://auth.example.com/oauth/token",
		});
		const payload = decodeJwt(proof);
		expect(payload.iat).toBeDefined();
		expect(payload.exp).toBeDefined();
		expect(Number(payload.exp)).toBeGreaterThan(Number(payload.iat));
	},
);

conformanceCase(
	"rfc9449-dpop-proof-htu-must-strip-query-and-fragment",
	"RFC9449: DPoP proof htu strips query and fragment",
	async () => {
		const dpop = await generateDpopKeypair();
		const provider = new DPoPProvider({
			keyMaterial: new DPoPKeyMaterial({
				privateKey: dpop.privateKey,
				publicJwk: dpop.publicJwk,
				algorithm: "ES256",
			}),
		});
		const proof = await provider.createProof({
			method: "GET",
			url: "https://api.example.com/resource?page=1&size=10#section",
		});
		const payload = decodeJwt(proof);
		expect(payload.htu).toBe("https://api.example.com/resource");
	},
);

// ---------------------------------------------------------------------------
// RFC 9449 — DPoP nonce challenge / retry / storage
// ---------------------------------------------------------------------------

async function runNonceRetryServer(nonceHeaderName: string): Promise<{
	origin: string;
	calls: number;
	close(): Promise<void>;
	nonceSeen(): string | undefined;
}> {
	const { createServer } = await import("node:http");
	const server = createServer();
	let calls = 0;
	let lastNonceOnRequest: string | undefined;
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	server.on("request", (req, res) => {
		calls += 1;
		if (calls === 1) {
			res.statusCode = 400;
			res.setHeader("content-type", "application/json");
			res.setHeader(nonceHeaderName, "nonce-123");
			res.end(JSON.stringify({ error: "use_dpop_nonce" }));
			return;
		}
		lastNonceOnRequest = undefined;
		let body = "";
		req.on("data", (chunk: Buffer) => {
			body += chunk.toString("utf-8");
		});
		req.on("end", () => {
			res.statusCode = 200;
			res.setHeader("content-type", "application/json");
			res.end(
				JSON.stringify({
					access_token: "ok",
					token_type: "DPoP",
					expires_in: 3600,
				}),
			);
		});
	});
	return {
		origin,
		get calls() {
			return calls;
		},
		nonceSeen: () => lastNonceOnRequest,
		close: () =>
			new Promise<void>((resolve) => {
				server.close(() => resolve());
			}),
	};
}

conformanceCase(
	"rfc9449-dpop-nonce-challenge-must-trigger-single-retry",
	"RFC9449: nonce challenge triggers single retry",
	async () => {
		const handle = await runNonceRetryServer("DPoP-Nonce");
		try {
			const dpop = await generateDpopKeypair();
			const provider = new DPoPProvider({
				keyMaterial: new DPoPKeyMaterial({
					privateKey: dpop.privateKey,
					publicJwk: dpop.publicJwk,
					algorithm: "ES256",
				}),
			});
			const { clientCredentialsGrant } = await import(
				"../src/auth/oauth/clientCredentials.js"
			);
			await clientCredentialsGrant({
				tokenEndpoint: `${handle.origin}/oauth/token`,
				authHeader: {},
				fetchSettings: NO_SSRF,
				dpopProvider: provider,
			});
			expect(handle.calls).toBe(2);
			expect(provider.currentNonce(`${handle.origin}/oauth/token`)).toBe(
				"nonce-123",
			);
		} finally {
			await handle.close();
		}
	},
);

conformanceCase(
	"rfc9449-dpop-nonce-on-success-response-should-be-stored",
	"RFC9449: nonce on success is stored",
	async () => {
		const { createServer } = await import("node:http");
		const server = createServer();
		await new Promise<void>((resolve) =>
			server.listen(0, "127.0.0.1", resolve),
		);
		const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		server.on("request", (_req, res) => {
			res.statusCode = 200;
			res.setHeader("content-type", "application/json");
			res.setHeader("DPoP-Nonce", "nonce-456");
			res.end(
				JSON.stringify({
					access_token: "ok",
					token_type: "DPoP",
					expires_in: 3600,
				}),
			);
		});
		try {
			const dpop = await generateDpopKeypair();
			const provider = new DPoPProvider({
				keyMaterial: new DPoPKeyMaterial({
					privateKey: dpop.privateKey,
					publicJwk: dpop.publicJwk,
					algorithm: "ES256",
				}),
			});
			const { clientCredentialsGrant } = await import(
				"../src/auth/oauth/clientCredentials.js"
			);
			await clientCredentialsGrant({
				tokenEndpoint: `${origin}/oauth/token`,
				authHeader: {},
				fetchSettings: NO_SSRF,
				dpopProvider: provider,
			});
			expect(provider.currentNonce(`${origin}/oauth/token`)).toBe("nonce-456");
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	},
);

conformanceCase(
	"rfc9110-rfc9449-dpop-nonce-header-must-be-treated-case-insensitively",
	"RFC9110/RFC9449: DPoP nonce header treated case-insensitively",
	async () => {
		// Node.js normalizes header names to lower-case in IncomingMessage, so
		// sending `Dpop-Nonce` exercises the client's lookup which must match
		// the normalized key. Verify the retry happens and the nonce is stored.
		const handle = await runNonceRetryServer("Dpop-Nonce");
		try {
			const dpop = await generateDpopKeypair();
			const provider = new DPoPProvider({
				keyMaterial: new DPoPKeyMaterial({
					privateKey: dpop.privateKey,
					publicJwk: dpop.publicJwk,
					algorithm: "ES256",
				}),
			});
			const { clientCredentialsGrant } = await import(
				"../src/auth/oauth/clientCredentials.js"
			);
			await clientCredentialsGrant({
				tokenEndpoint: `${handle.origin}/oauth/token`,
				authHeader: {},
				fetchSettings: NO_SSRF,
				dpopProvider: provider,
			});
			expect(handle.calls).toBe(2);
			expect(provider.currentNonce(`${handle.origin}/oauth/token`)).toBe(
				"nonce-123",
			);
		} finally {
			await handle.close();
		}
	},
);

conformanceCase(
	"rfc9449-dpop-grant-token-type-must-be-dpop",
	"RFC9449: DPoP grant response token_type must be DPoP",
	async () => {
		expect(() =>
			parseTokenResponse(
				{ access_token: "tok", token_type: "Bearer" },
				{ expectDpop: true },
			),
		).toThrow(ProtocolError);
		expect(() =>
			parseTokenResponse(
				{ access_token: "tok", token_type: "Bearer" },
				{ expectDpop: true },
			),
		).toThrow(/DPoP|token_type/);
	},
);

// ---------------------------------------------------------------------------
// RFC 9449 — inbound proof verification (direct)
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc9449-dpop-proof-header-typ-must-be-dpop-jwt",
	"RFC9449: DPoP proof typ must be dpop+jwt",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({
			keypair: dpop,
			headerOverrides: { typ: "JWT" },
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-proof-must-carry-public-jwk",
	"RFC9449: DPoP proof carries public JWK",
	async () => {
		const dpop = await generateDpopKeypair();
		// `jwk: undefined` in the protected header gets encoded as no-jwk.
		const proof = await signDpopProof({
			keypair: dpop,
			headerOverrides: { jwk: undefined },
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-proof-jwk-must-not-include-private-key-material",
	"RFC9449: DPoP proof JWK does not include private material",
	async () => {
		const dpop = await generateDpopKeypair();
		const tamperedJwk = { ...dpop.publicJwk, d: "private-material" };
		const proof = await signDpopProof({
			keypair: dpop,
			headerOverrides: { jwk: tamperedJwk },
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-proof-alg-must-be-supported-asymmetric",
	"RFC9449: DPoP proof alg supported for asymmetric keys",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({
			keypair: dpop,
			headerOverrides: { alg: "HS256" },
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-method-mismatch-must-be-rejected",
	"RFC9449: DPoP htm mismatch rejected",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({
			keypair: dpop,
			method: "POST",
			url: "https://api.example.com/resource",
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-url-mismatch-must-be-rejected",
	"RFC9449: DPoP htu mismatch rejected",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({
			keypair: dpop,
			method: "GET",
			url: "https://api.example.com/other",
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource?query=ignored",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-proof-htu-must-be-normalized-before-comparison",
	"RFC9449: DPoP htu normalized before comparison",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({
			keypair: dpop,
			method: "GET",
			url: "HTTPS://API.EXAMPLE.COM:443/resource",
		});
		// The verifier must normalize scheme/host case and default ports before
		// comparing the proof htu to the request URL.
		await verifyDpopProof({
			proof,
			method: "GET",
			url: "https://api.example.com/resource?query=ignored",
			accessToken: "tok",
			expectedJkt: dpop.jkt,
			maxAgeSeconds: 300,
			clockSkewSeconds: 30,

			replayStore: new InMemoryDPoPReplayStore(),
		});
	},
);

conformanceCase(
	"rfc9449-dpop-proof-htm-must-be-case-sensitive",
	"RFC9449: DPoP htm must be case-sensitive",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({
			keypair: dpop,
			payloadOverrides: { htm: "get" },
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-proof-iat-must-not-be-in-the-future-beyond-leeway",
	"RFC9449: DPoP proof iat not in future beyond leeway",
	async () => {
		const dpop = await generateDpopKeypair();
		const now = Math.floor(Date.now() / 1000);
		const proof = await signDpopProof({
			keypair: dpop,
			iat: now + 600,
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-proof-must-not-be-too-old",
	"RFC9449: DPoP proof not too old",
	async () => {
		const dpop = await generateDpopKeypair();
		const now = Math.floor(Date.now() / 1000);
		const proof = await signDpopProof({
			keypair: dpop,
			iat: now - 600,
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-proof-exp-must-be-enforced-when-present",
	"RFC9449: DPoP proof exp enforced when present",
	async () => {
		const dpop = await generateDpopKeypair();
		const now = Math.floor(Date.now() / 1000);
		const proof = await signDpopProof({
			keypair: dpop,
			iat: now,
			exp: now - 120,
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-ath-mismatch-must-be-rejected",
	"RFC9449: DPoP ath mismatch rejected",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({
			keypair: dpop,
			ath: sha256Base64Url("token-b"),
		});
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "token-a",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

conformanceCase(
	"rfc9449-dpop-binding-mismatch-must-be-rejected",
	"RFC9449: DPoP binding mismatch rejected",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({ keypair: dpop });
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: "different-thumbprint",
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(DPoPBindingMismatch);
	},
);

conformanceCase(
	"rfc9449-dpop-replay-must-be-detected",
	"RFC9449: DPoP replay is detected",
	async () => {
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({ keypair: dpop });
		const replayStore = new InMemoryDPoPReplayStore();
		const opts = {
			proof,
			method: "GET",
			url: "https://api.example.com/resource",
			accessToken: "tok",
			expectedJkt: dpop.jkt,
			maxAgeSeconds: 300,
			clockSkewSeconds: 30,
			replayStore,
		};
		await verifyDpopProof(opts);
		await expect(verifyDpopProof(opts)).rejects.toBeInstanceOf(
			DPoPReplayDetected,
		);
	},
);

conformanceCase(
	"rfc9449-dpop-replay-store-must-evict-expired-entries",
	"RFC9449: DPoP replay store evicts expired entries",
	async () => {
		const store = new InMemoryDPoPReplayStore();
		const past = Math.floor(Date.now() / 1000) - 1;
		const future = Math.floor(Date.now() / 1000) + 3600;
		// Expired entries must not block a later store of the same jti.
		expect(await store.checkAndStore("proof-1", past)).toBe(true);
		expect(await store.checkAndStore("proof-1", future)).toBe(true);
		// Live entries must block replay of the same jti.
		expect(await store.checkAndStore("proof-2", future)).toBe(true);
		expect(await store.checkAndStore("proof-2", future)).toBe(false);
	},
);

conformanceCase(
	"rfc9449-dpop-inbound-nonce-must-be-validated-when-required",
	"RFC9449: inbound nonce validated when required",
	async () => {
		const dpop = await generateDpopKeypair();
		// Wrong nonce on the proof.
		const wrongNonceProof = await signDpopProof({
			keypair: dpop,
			nonce: "wrong-nonce",
		});
		await expect(
			verifyDpopProof({
				proof: wrongNonceProof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,
				expectedNonce: "server-nonce-abc",

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);

		// Missing nonce claim entirely.
		const noNonceProof = await signDpopProof({ keypair: dpop });
		await expect(
			verifyDpopProof({
				proof: noNonceProof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "tok",
				expectedJkt: dpop.jkt,
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,
				expectedNonce: "server-nonce-abc",

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(InvalidDPoPProof);
	},
);

// ---------------------------------------------------------------------------
// RFC 9449 — inbound DPoP verification via AuthplaneResource.verify
// ---------------------------------------------------------------------------

async function dpopBoundFixture(
	overrides: { required?: boolean } = {},
): Promise<{
	dpop: Awaited<ReturnType<typeof generateDpopKeypair>>;
	fixture: Awaited<ReturnType<typeof createTestFixture>>;
	boundToken(): Promise<string>;
}> {
	const dpop = await generateDpopKeypair();
	const fixture = await createTestFixture({
		inboundDPoP: { required: overrides.required ?? false },
	});
	return {
		dpop,
		fixture,
		async boundToken(): Promise<string> {
			return await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				extra: { cnf: { jkt: dpop.jkt } },
			});
		},
	};
}

conformanceCase(
	"rfc9449-inbound-dpop-proof-must-validate-method-url-and-binding",
	"RFC9449: inbound DPoP proof validates method/URL/binding",
	async () => {
		const { dpop, fixture, boundToken } = await dpopBoundFixture();
		try {
			const token = await boundToken();
			const requestUrl = `${fixture.server.origin}/api/resource`;
			const proof = await signDpopProof({
				keypair: dpop,
				method: "GET",
				url: requestUrl,
				ath: sha256Base64Url(token),
			});
			const claims = await fixture.resource.verify(token, {
				dpopRequest: {
					method: "GET",
					url: requestUrl,
					proof,
				},
			});
			expect(claims.sub).toBe("user123");
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer",
	"RFC9449: bearer token verifies without proof with request context",
	async () => {
		const fixture = await createTestFixture();
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
			});
			const claims = await fixture.resource.verify(token, {
				dpopRequest: {
					method: "GET",
					url: `${fixture.server.origin}/api/resource`,
				},
			});
			expect(claims.sub).toBe("user123");
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path",
	"RFC9449: DPoP-bound token without proof is rejected",
	async () => {
		const { fixture, boundToken } = await dpopBoundFixture();
		try {
			const token = await boundToken();
			await expect(
				fixture.resource.verify(token, {
					dpopRequest: {
						method: "GET",
						url: `${fixture.server.origin}/api/resource`,
					},
				}),
			).rejects.toBeInstanceOf(DPoPProofMissing);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9449-dpop-proof-required-when-validating-dpop-bound-token",
	"RFC9449: DPoP proof required when validating DPoP-bound token",
	async () => {
		const { fixture, boundToken } = await dpopBoundFixture();
		try {
			const token = await boundToken();
			// Pass a request context without a proof — Python parity: the
			// resource has the binding (cnf.jkt) but no proof to validate it,
			// so the verifier MUST raise DPoPProofMissing.
			await expect(
				fixture.resource.verify(token, {
					dpopRequest: {
						method: "GET",
						url: `${fixture.server.origin}/api/resource`,
					},
				}),
			).rejects.toBeInstanceOf(DPoPProofMissing);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9449-dpop-bound-token-must-contain-cnf-jkt",
	"RFC9449: DPoP-bound token contains cnf.jkt",
	async () => {
		// Catalog setup: cnf is present but jkt is missing. Resource.verify
		// should reject a token presented with a proof when cnf.jkt is absent
		// — the binding cannot be enforced.
		const dpop = await generateDpopKeypair();
		const fixture = await createTestFixture({ inboundDPoP: {} });
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				extra: { cnf: {} },
			});
			const proof = await signDpopProof({
				keypair: dpop,
				method: "GET",
				url: `${fixture.server.origin}/api/resource`,
				ath: sha256Base64Url(token),
			});
			await expect(
				fixture.resource.verify(token, {
					dpopRequest: {
						method: "GET",
						url: `${fixture.server.origin}/api/resource`,
						proof,
					},
				}),
			).rejects.toBeInstanceOf(InvalidClaims);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9449-dpop-proof-validation-must-not-skip-binding-when-access-token-is-provided",
	"RFC9449: DPoP proof validation does not skip binding check",
	async () => {
		// verifyDpopProof takes `expectedJkt`; supplying an empty/placeholder
		// value must not bypass the binding check.
		const dpop = await generateDpopKeypair();
		const proof = await signDpopProof({ keypair: dpop });
		await expect(
			verifyDpopProof({
				proof,
				method: "GET",
				url: "https://api.example.com/resource",
				accessToken: "token-a",
				expectedJkt: "",
				maxAgeSeconds: 300,
				clockSkewSeconds: 30,

				replayStore: new InMemoryDPoPReplayStore(),
			}),
		).rejects.toBeInstanceOf(DPoPBindingMismatch);
	},
);

conformanceCase(
	"rfc9449-verifier-must-reject-bearer-only-token-when-resource-requires-dpop",
	"RFC9449: verifier rejects bearer-only token when resource requires DPoP",
	async () => {
		const fixture = await createTestFixture({
			inboundDPoP: { required: true },
		});
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
			});
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				DPoPBindingMismatch,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9449-verifier-must-reject-dpop-bound-token-when-resource-does-not-support-dpop",
	"RFC9449: verifier rejects DPoP-bound token when resource does not support DPoP",
	async () => {
		const dpop = await generateDpopKeypair();
		const fixture = await createTestFixture(); // no inboundDPoP — Mode 3
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				extra: { cnf: { jkt: dpop.jkt } },
			});
			await expect(fixture.resource.verify(token)).rejects.toBeInstanceOf(
				DPoPNotSupported,
			);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9449-verifier-must-reject-dpop-proof-when-access-token-is-not-dpop-bound",
	"RFC9449: verifier rejects DPoP proof presented with bearer-only token",
	async () => {
		const dpop = await generateDpopKeypair();
		const fixture = await createTestFixture({ inboundDPoP: {} });
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				// No `cnf` claim — bearer-only token.
			});
			const proof = await signDpopProof({
				keypair: dpop,
				method: "GET",
				url: `${fixture.server.origin}/api/resource`,
				ath: sha256Base64Url(token),
			});
			await expect(
				fixture.resource.verify(token, {
					dpopRequest: {
						method: "GET",
						url: `${fixture.server.origin}/api/resource`,
						proof,
					},
				}),
			).rejects.toBeInstanceOf(DPoPBindingMismatch);
		} finally {
			await fixture.close();
		}
	},
);

// ---------------------------------------------------------------------------
// RFC 9728 — Protected Resource Metadata
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc9728-prm-must-contain-required-fields",
	"RFC9728: builds RFC9728-like metadata shape",
	async () => {
		const prm = buildPrm(
			"https://auth.example.com",
			"https://api.example.com",
			["read:data", "write:data"],
		) as Record<string, unknown>;
		expect(prm).toHaveProperty("resource");
		expect(prm).toHaveProperty("authorization_servers");
		expect(prm).toHaveProperty("bearer_methods_supported");
		expect(prm).toHaveProperty("scopes_supported");
	},
);

conformanceCase(
	"rfc9728-prm-authorization-servers-must-list-the-issuer",
	"RFC9728: PRM authorization_servers includes issuer",
	async () => {
		const prm = buildPrm(
			"https://auth.example.com",
			"https://api.example.com",
			["read:data"],
		);
		expect(prm.authorization_servers).toEqual(["https://auth.example.com"]);
	},
);

conformanceCase(
	"rfc9728-prm-supported-bearer-methods-should-be-stable",
	"RFC9728: PRM bearer_methods_supported is stable across restarts",
	async () => {
		const prm = buildPrm(
			"https://auth.example.com",
			"https://api.example.com",
			["read:data"],
		);
		expect(prm.bearer_methods_supported).toEqual(["header"]);
	},
);

// ---------------------------------------------------------------------------
// Cross-file duplicates — IDs that also appear in other test files. Assertions
// mirror the sibling implementations so the conformance report is consistent
// regardless of which duplicate writes the last result.
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc8414-introspection-endpoint-required-when-introspection-is-used",
	"RFC8414: introspection_endpoint required when introspection used",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				issuer: "https://auth.example.com",
				jwks_uri: "https://auth.example.com/.well-known/jwks.json",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getIntrospectionEndpoint()).rejects.toBeInstanceOf(
			MissingMetadataEndpoint,
		);
	},
);

conformanceCase(
	"rfc8414-revocation-endpoint-required-when-revocation-is-used",
	"RFC8414: revocation_endpoint required when revocation used",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				issuer: "https://auth.example.com",
				jwks_uri: "https://auth.example.com/.well-known/jwks.json",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getRevocationEndpoint()).rejects.toBeInstanceOf(
			MissingMetadataEndpoint,
		);
	},
);

conformanceCase(
	"rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache",
	"RFC8414: jwks_uri rotation reconfigures JWKS cache",
	async () => {
		// Thin re-run of the RFC 8414 file's test so this duplicate registration
		// records the same outcome in the conformance report.
		const v1 = await generateEs256Keypair("key-v1");
		const v2 = await generateEs256Keypair("key-v2");
		let currentJwksUriPath = "/jwks-v1.json";
		const { createServer } = await import("node:http");
		const server = createServer();
		await new Promise<void>((resolve) =>
			server.listen(0, "127.0.0.1", resolve),
		);
		const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		server.on("request", (req, res) => {
			res.setHeader("content-type", "application/json");
			if (req.url === "/.well-known/oauth-authorization-server") {
				res.end(
					JSON.stringify({
						issuer: origin,
						jwks_uri: `${origin}${currentJwksUriPath}`,
					}),
				);
				return;
			}
			if (req.url === "/jwks-v1.json") {
				res.end(JSON.stringify(v1.jwks));
				return;
			}
			if (req.url === "/jwks-v2.json") {
				res.end(JSON.stringify(v2.jwks));
				return;
			}
			res.statusCode = 404;
			res.end();
		});
		try {
			const client = await AuthplaneClient.create({
				issuer: origin,
				fetchSettings: NO_SSRF,
				metadataRefreshSeconds: 0,
			});
			try {
				currentJwksUriPath = "/jwks-v2.json";
				const privateAccess = client as unknown as {
					metadataCache: { get(force?: boolean): Promise<unknown> };
				};
				await privateAccess.metadataCache.get(true);
				await new Promise<void>((resolve) => setTimeout(resolve, 50));
				const token = await createTokenFactory(v2)({
					iss: origin,
					aud: `${origin}/api`,
				});
				const resource = client.resource({
					resource: `${origin}/api`,
					scopes: ["read:data"],
				});
				await resource.verify(token);
			} finally {
				await client.close();
			}
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	},
);

conformanceCase(
	"rfc7009-revocation-server-errors-must-surface",
	"RFC7009: server errors surface",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeRevocationEndpoint: true,
			revocationResponse: {
				status: 500,
				body: { error: "server_error" },
			},
		});
		try {
			await expect(
				revokeToken({
					revocationEndpoint: `${server.origin}/oauth/revoke`,
					token: "token_to_revoke",
					authHeader: { Authorization: "Basic dGVzdDpzZWNyZXQ=" },
					fetchSettings: NO_SSRF,
				}),
			).rejects.toBeInstanceOf(ServerError);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-audience-parameter-must-be-sent-when-configured",
	"RFC8693: audience parameter is sent when configured",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				body: {
					access_token: "tok",
					token_type: "Bearer",
					expires_in: 3600,
					issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
				},
			},
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: {
					subjectToken: "subject",
					audiences: ["api://inventory"],
				},
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request?.body.get("audience")).toBe("api://inventory");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-multiple-audience-parameters-must-be-emitted",
	"RFC8693: multiple audience parameters emitted",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				body: {
					access_token: "tok",
					token_type: "Bearer",
					expires_in: 3600,
					issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
				},
			},
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: {
					subjectToken: "subject",
					audiences: ["api://inventory", "api://billing"],
				},
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const audiences = server.tokenRequests.at(-1)?.body.getAll("audience");
			expect(audiences).toHaveLength(2);
			expect(audiences).toContain("api://inventory");
			expect(audiences).toContain("api://billing");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-empty-resource-and-audience-values-must-be-omitted",
	"RFC8693: empty resource/audience omitted",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				body: {
					access_token: "tok",
					token_type: "Bearer",
					expires_in: 3600,
					issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
				},
			},
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: {
					subjectToken: "subject",
					resources: [""],
					audiences: [""],
				},
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const body = server.tokenRequests.at(-1)?.body;
			expect(body?.getAll("resource")).toEqual([]);
			expect(body?.getAll("audience")).toEqual([]);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-success-response-must-use-access-token-issued-token-type-when-present",
	"RFC8693: token_type uses issued token_type when present",
	async () => {
		const response = parseTokenResponse(
			{
				access_token: "new_token",
				token_type: "Bearer",
				issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
			},
			{ allowIssuedTokenType: true },
		);
		expect(response.issuedTokenType).toBe(
			"urn:ietf:params:oauth:token-type:access_token",
		);
	},
);

conformanceCase(
	"rfc8707-verifier-must-accept-resource-when-present-in-aud-array",
	"RFC8707: verifier accepts resource when present in aud array",
	async () => {
		const fixture = await createTestFixture();
		try {
			const token = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: ["https://other.example.com", `${fixture.server.origin}/api`],
			});
			const claims = await fixture.resource.verify(token);
			expect(claims.audience).toContain(`${fixture.server.origin}/api`);
		} finally {
			await fixture.close();
		}
	},
);

// ---------------------------------------------------------------------------
// Authplane profile — typed first-class claims on VerifiedClaims
// ---------------------------------------------------------------------------

conformanceCase(
	"authplane-agent-id-must-be-exposed-as-first-class-field",
	"authplane: agent_id exposed as first-class field on VerifiedClaims",
	async () => {
		const fixture = await createTestFixture();
		try {
			const withClaim = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				extra: { agent_id: "research-agent" },
			});
			const claims = await fixture.resource.verify(withClaim);
			expect(claims.agentId).toBe("research-agent");

			const withoutClaim = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
			});
			const absent = await fixture.resource.verify(withoutClaim);
			expect(absent.agentId).toBe("");
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"authplane-agent-chain-must-be-exposed-as-first-class-field",
	"authplane: agent_chain exposed as first-class field on VerifiedClaims",
	async () => {
		const fixture = await createTestFixture();
		try {
			const chain = ["orchestrator", "research-agent", "summarizer"];
			const withClaim = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				extra: { agent_chain: chain },
			});
			const claims = await fixture.resource.verify(withClaim);
			expect(Array.from(claims.agentChain)).toEqual(chain);

			const withoutClaim = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
			});
			const absent = await fixture.resource.verify(withoutClaim);
			expect(Array.from(absent.agentChain)).toEqual([]);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims",
	"authplane: nbf exposed as typed field on VerifiedClaims",
	async () => {
		const fixture = await createTestFixture();
		try {
			const nbf = Math.floor(Date.now() / 1000) - 10;
			const withClaim = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				nbf,
			});
			const claims = await fixture.resource.verify(withClaim);
			expect(claims.notBefore).toBe(nbf);

			const withoutClaim = await fixture.tokenFactory({
				iss: fixture.server.origin,
				aud: `${fixture.server.origin}/api`,
				excludeClaims: ["nbf"],
			});
			const absent = await fixture.resource.verify(withoutClaim);
			expect(absent.notBefore).toBe(0);
		} finally {
			await fixture.close();
		}
	},
);
