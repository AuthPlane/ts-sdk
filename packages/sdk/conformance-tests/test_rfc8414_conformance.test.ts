import { expect } from "vitest";

import { AuthplaneClient } from "../src/core/client.js";
import {
	MetadataFetchError,
	MissingMetadataEndpoint,
} from "../src/core/errors.js";
import { MetadataCache } from "../src/core/fetching/documentCache.js";
import { buildMetadataUrl } from "../src/core/fetching/metadataUrl.js";
import {
	buildPrm,
	oauthProtectedResourceMetadataDocumentUrl,
} from "../src/core/prm.js";
import { FetchSettings } from "../src/auth/fetchSettings.js";
import { conformanceCase } from "./conformanceCase.js";
import {
	createMockAsServer,
	createTestFixture,
	generateEs256Keypair,
	staticMetadataFetcher,
} from "./helpers.js";

const NO_SSRF = new FetchSettings({
	ssrfProtection: false,
	allowHttp: true,
	allowLocalhost: true,
	allowPrivateNetworks: true,
});

conformanceCase(
	"rfc8414-metadata-issuer-must-match-configured-issuer",
	"RFC8414: metadata issuer mismatch is rejected",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			metadataOverrides: { issuer: "https://evil.example.com" },
		});
		try {
			await expect(
				AuthplaneClient.create({
					issuer: server.origin,
					fetchSettings: NO_SSRF,
				}),
			).rejects.toThrow(/issuer mismatch/);
		} finally {
			await server.close();
		}
	},
	{
		level: "partial",
		gaps: [
			"The catalog's variant — configured issuer without a trailing slash, " +
				"metadata issuer with one — is not exercised. It needs a mock AS " +
				"whose metadata issuer is its own origin plus a slash, and " +
				"metadataOverrides is a static record fixed before the port is " +
				"known, so expressing it means changing a shared helper.",
		],
		note:
			"Covers the different-host mismatch only. The behaviour is correct: " +
			"the comparison is fetching/documentCache.ts:287-290 " +
			"(issuer !== this.expectedIssuer), reached through the expectedIssuer " +
			"passed at client.ts:137 — and client.ts:86-93 is why the stored value " +
			"is not normalized before it gets there (RFC 8414 §3.3).",
	},
);

conformanceCase(
	"rfc8414-jwks-uri-required-for-jwt-validation",
	"RFC8414: jwks_uri required for JWT validation",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({ issuer: "https://auth.example.com" }),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getJwksUri()).rejects.toBeInstanceOf(
			MissingMetadataEndpoint,
		);
		await expect(cache.getJwksUri()).rejects.toThrow(/jwks_uri/);
	},
);

conformanceCase(
	"rfc8414-metadata-must-contain-issuer",
	"RFC8414: metadata must contain issuer",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				jwks_uri: "https://auth.example.com/.well-known/jwks.json",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.get()).rejects.toBeInstanceOf(MetadataFetchError);
		await expect(cache.get()).rejects.toThrow(/issuer/);
	},
);

conformanceCase(
	"rfc8414-jwks-uri-must-be-absolute-https-url",
	"RFC8414: jwks_uri must be absolute HTTPS URL",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				issuer: "https://auth.example.com",
				jwks_uri: "/relative-jwks",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getJwksUri()).rejects.toBeInstanceOf(MetadataFetchError);
		await expect(cache.getJwksUri()).rejects.toThrow(/jwks_uri/);
	},
);

conformanceCase(
	"rfc8414-token-endpoint-required-when-token-operation-is-used",
	"RFC8414: token_endpoint required when used",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				issuer: "https://auth.example.com",
				jwks_uri: "https://auth.example.com/.well-known/jwks.json",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getTokenEndpoint()).rejects.toBeInstanceOf(
			MissingMetadataEndpoint,
		);
		await expect(cache.getTokenEndpoint()).rejects.toThrow(/token_endpoint/);
	},
);

conformanceCase(
	"rfc8414-token-endpoint-must-be-absolute-https-url",
	"RFC8414: token_endpoint must be absolute HTTPS URL",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				issuer: "https://auth.example.com",
				jwks_uri: "https://auth.example.com/.well-known/jwks.json",
				token_endpoint: "http://auth.example.com/oauth/token",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getTokenEndpoint()).rejects.toBeInstanceOf(
			MetadataFetchError,
		);
		await expect(cache.getTokenEndpoint()).rejects.toThrow(/token_endpoint/);
	},
);

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
		await expect(cache.getIntrospectionEndpoint()).rejects.toThrow(
			/introspection_endpoint/,
		);
	},
);

conformanceCase(
	"rfc8414-revocation-endpoint-required-when-revocation-is-used",
	"RFC8414: revocation_endpoint required when used",
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
		await expect(cache.getRevocationEndpoint()).rejects.toThrow(
			/revocation_endpoint/,
		);
	},
);

/**
 * Explicit timeout for the jwks_uri rotation cases.
 *
 * The case waits out a real 3 s refresh interval, so its wall time is ~3.2 s
 * against Vitest's 5 s default — and nothing in this package overrides that
 * default. Measured at 3.23 s and 3.21 s for the two registrations in a full
 * suite run, which leaves under 1.8 s of headroom for two ES256 keygens, six
 * verifications and eight loopback round trips on a loaded machine. An
 * overrun does not degrade to a skip — it fails the run, and because Vitest
 * stops awaiting the case rather than throwing into it, no result record is
 * written: the report pairs a non-zero exit status with a case table that
 * reads not_run, or green off the other module's record. Hence room, not a
 * margin.
 */
const ROTATION_CASE_TIMEOUT_MS = 15_000;

conformanceCase(
	"rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache",
	"RFC8414: jwks_uri rotation reconfigures JWKS cache",
	async () => {
		// Driven entirely through `verify()`: no force-refresh argument, no
		// test-only hook, no reflective access to cache internals, and nothing
		// asserted against a locally built metadata object.
		//
		// The refresh interval is a real configured value the test waits out,
		// rather than zero. A zero interval re-reads metadata on every single
		// verification and opts out of both retry floors, so it demonstrates none
		// of "re-read metadata on its configured refresh interval" — it is a
		// different code path from the one a deployment runs.
		const METADATA_REFRESH_SECONDS = 3;

		const v1 = await generateEs256Keypair("key-v1");
		const v2 = await generateEs256Keypair("key-v2");

		const METADATA_PATH = "/.well-known/oauth-authorization-server";
		const JWKS_V1_PATH = "/jwks-v1.json";
		const JWKS_V2_PATH = "/jwks-v2.json";

		let currentJwksUriPath = JWKS_V1_PATH;
		const requests: string[] = [];
		const countOf = (path: string): number =>
			requests.filter((seen) => seen === path).length;

		const { createServer } = await import("node:http");
		const server = createServer();
		await new Promise<void>((resolve) =>
			server.listen(0, "127.0.0.1", resolve),
		);
		const addr = server.address() as import("node:net").AddressInfo;
		const origin = `http://127.0.0.1:${addr.port}`;

		server.on("request", (req, res) => {
			const url = req.url ?? "";
			requests.push(url);
			res.setHeader("content-type", "application/json");
			if (req.method === "GET" && url === METADATA_PATH) {
				res.end(
					JSON.stringify({
						issuer: origin,
						jwks_uri: `${origin}${currentJwksUriPath}`,
					}),
				);
				return;
			}
			if (req.method === "GET" && url === JWKS_V1_PATH) {
				// Withdrawn once the rotation is published, so a cache still bound to
				// this URI cannot quietly keep working.
				if (currentJwksUriPath !== JWKS_V1_PATH) {
					res.statusCode = 410;
					res.end();
					return;
				}
				res.end(JSON.stringify(v1.jwks));
				return;
			}
			if (req.method === "GET" && url === JWKS_V2_PATH) {
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
				metadataRefreshSeconds: METADATA_REFRESH_SECONDS,
				jwksRefreshSeconds: 300,
			});
			const { createTokenFactory } = await import("./helpers.js");
			const resource = client.resource({
				resource: `${origin}/api`,
				scopes: ["read:data"],
			});
			try {
				// Baseline: keys come from the originally published URI.
				const before = await resource.verify(
					await createTokenFactory(v1)({
						iss: origin,
						aud: `${origin}/api`,
					}),
				);
				expect(before.kid).toBe("key-v1");
				expect(countOf(JWKS_V1_PATH)).toBeGreaterThan(0);

				// The AS rotates: the key set moves and the old URI is withdrawn.
				// Nothing notifies the SDK.
				currentJwksUriPath = JWKS_V2_PATH;

				// Still inside the interval: the configured cadence is respected, so
				// verification keeps using the document it already holds instead of
				// re-reading on every request.
				const metadataReadsBefore = countOf(METADATA_PATH);
				await resource.verify(
					await createTokenFactory(v1)({
						iss: origin,
						aud: `${origin}/api`,
					}),
				);
				expect(countOf(METADATA_PATH)).toBe(metadataReadsBefore);

				await new Promise((resolve) =>
					setTimeout(resolve, METADATA_REFRESH_SECONDS * 1000 + 200),
				);

				// The interval has elapsed. This verification cannot miss its `kid`
				// — key-v1 is still in the cached JWKS document, which carries its own
				// 300 s interval — so nothing here can force a JWKS fetch, and the only
				// thing that can re-read metadata is the verification path itself. That
				// read is what the requirement is about: an SDK that reads metadata only
				// at construction, or only when a `kid` lookup misses, fails here.
				const metadataReadsBeforeElapse = countOf(METADATA_PATH);
				const v2FetchesBeforeElapse = countOf(JWKS_V2_PATH);
				const stillCached = await resource.verify(
					await createTokenFactory(v1)({
						iss: origin,
						aud: `${origin}/api`,
					}),
				);
				expect(stillCached.kid).toBe("key-v1");
				expect(countOf(METADATA_PATH)).toBeGreaterThan(
					metadataReadsBeforeElapse,
				);
				expect(countOf(JWKS_V2_PATH)).toBe(v2FetchesBeforeElapse);

				// One ordinary verification past the interval is all it takes: the
				// metadata read that verification performs picks up the new jwks_uri
				// and key retrieval follows it.
				const rotated = await resource.verify(
					await createTokenFactory(v2)({
						iss: origin,
						aud: `${origin}/api`,
					}),
				);
				expect(rotated.kid).toBe("key-v2");
				expect(countOf(JWKS_V2_PATH)).toBeGreaterThan(0);

				// The withdrawn URI is out of the picture: later verifications must
				// not go back to it.
				const withdrawnReads = countOf(JWKS_V1_PATH);
				await resource.verify(
					await createTokenFactory(v2)({
						iss: origin,
						aud: `${origin}/api`,
					}),
				);
				expect(countOf(JWKS_V1_PATH)).toBe(withdrawnReads);
			} finally {
				await client.close();
			}
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	},
	{
		level: "partial",
		gaps: [
			"A same-'kid' rotation is not demonstrated here, and the reason is " +
				"this case's interval ratio rather than the 'kid'. The JWKS URI is " +
				"re-resolved from the metadata document on every JWKS fetch, so a " +
				"rotation is followed under an unchanged 'kid' as well, once the " +
				"JWKS cache's own interval expires: worst case " +
				"metadataRefreshSeconds + jwksRefreshSeconds, which stays inside " +
				"the requirement's bound of two metadata refresh intervals whenever " +
				"jwksRefreshSeconds <= metadataRefreshSeconds — as the SDK defaults " +
				"(300 / 3600) do. This case configures the inverse (300 / 3), so " +
				"the cached JWKS document outlives the wait and a lookup its " +
				"unchanged 'kid' satisfies never re-drives key retrieval. Under " +
				"that ratio, and only under it, a same-'kid' rotation falls outside " +
				"the bound.",
		],
		note:
			"Ordinary verification traffic does drive the rotation: metadata is " +
			"re-read on the verification path (core/resource.ts refreshMetadata, " +
			"called unconditionally from verify) and the JWKS URI is resolved from " +
			"the validated metadata document on every JWKS fetch " +
			"(core/client.ts initializeCaches), with no force-refresh argument, " +
			"hook or reflection involved. The interval-driven read is asserted on a " +
			"verification that cannot miss its 'kid', so it is pinned independently " +
			"of the forced re-read a 'kid' miss performs — removing the read from " +
			"the verification path fails this case. What is not demonstrated is a " +
			"rotation under an unchanged 'kid' — see the gap.",
	},
	ROTATION_CASE_TIMEOUT_MS,
);

conformanceCase(
	"rfc8414-discovery-url-must-insert-well-known-before-issuer-path",
	"RFC8414: discovery URL inserts .well-known before issuer path",
	async () => {
		const issuer = "https://auth.example.com/tenant-a";
		const expected =
			"https://auth.example.com/.well-known/oauth-authorization-server/tenant-a";
		const wrong =
			"https://auth.example.com/tenant-a/.well-known/oauth-authorization-server";
		expect(buildMetadataUrl(issuer)).toBe(expected);
		expect(buildMetadataUrl(issuer)).not.toBe(wrong);
	},
);

conformanceCase(
	"rfc8414-introspection-endpoint-must-be-absolute-https-url",
	"RFC8414: introspection_endpoint must be an absolute HTTPS URL",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				issuer: "https://auth.example.com",
				jwks_uri: "https://auth.example.com/.well-known/jwks.json",
				introspection_endpoint: "http://auth.example.com/oauth/introspect",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getIntrospectionEndpoint()).rejects.toBeInstanceOf(
			MetadataFetchError,
		);
		await expect(cache.getIntrospectionEndpoint()).rejects.toThrow(
			/introspection_endpoint/,
		);
	},
);

conformanceCase(
	"rfc8414-revocation-endpoint-must-be-absolute-https-url",
	"RFC8414: revocation_endpoint must be an absolute HTTPS URL",
	async () => {
		const cache = new MetadataCache(
			staticMetadataFetcher({
				issuer: "https://auth.example.com",
				jwks_uri: "https://auth.example.com/.well-known/jwks.json",
				revocation_endpoint: "http://auth.example.com/oauth/revoke",
			}),
			{ refreshSeconds: 3600 },
		);
		await expect(cache.getRevocationEndpoint()).rejects.toBeInstanceOf(
			MetadataFetchError,
		);
		await expect(cache.getRevocationEndpoint()).rejects.toThrow(
			/revocation_endpoint/,
		);
	},
);

conformanceCase(
	"rfc9728-prm-dpop-fields-should-be-advertised-when-dpop-is-supported",
	"RFC9728: PRM DPoP fields advertised when DPoP is supported",
	async () => {
		const prm = buildPrm(
			"https://auth.example.com",
			"https://api.example.com",
			["read:data"],
			{ dpopSigningAlgValuesSupported: ["ES256", "RS256"] },
		);
		expect(prm).toHaveProperty("dpop_signing_alg_values_supported");
	},
);

conformanceCase(
	"rfc9728-prm-must-advertise-dpop-required-when-resource-requires-dpop",
	"RFC9728: PRM advertises dpop_bound_access_tokens_required when resource requires DPoP",
	async () => {
		const prm = buildPrm(
			"https://auth.example.com",
			"https://api.example.com",
			["read:data"],
			{
				dpopSigningAlgValuesSupported: ["ES256", "RS256"],
				dpopBoundAccessTokensRequired: true,
			},
		);
		expect(prm.dpop_bound_access_tokens_required).toBe(true);
	},
);

conformanceCase(
	"rfc9728-well-known-path-must-derive-from-resource-uri",
	"RFC9728: well-known path derives from resource URI",
	async () => {
		const cases: Array<[string, string]> = [
			["https://api.example.com", "/.well-known/oauth-protected-resource"],
			[
				"https://api.example.com/mcp",
				"/.well-known/oauth-protected-resource/mcp",
			],
			[
				"https://api.example.com/v2/mcp",
				"/.well-known/oauth-protected-resource/v2/mcp",
			],
			// A resource published with a trailing slash serves its metadata at the
			// slash-less well-known path, so this row and the "/mcp" one above must
			// derive the same document. The slash is dropped at derivation only —
			// the identifier itself is still compared byte-for-byte elsewhere.
			[
				"https://api.example.com/mcp/",
				"/.well-known/oauth-protected-resource/mcp",
			],
		];
		for (const [resource, expectedPath] of cases) {
			const url = oauthProtectedResourceMetadataDocumentUrl(resource);
			const parsed = new URL(url);
			expect(parsed.pathname).toBe(expectedPath);
		}
	},
);

conformanceCase(
	"rfc9728-well-known-url-must-preserve-the-resource-query-component",
	"RFC9728: the derived well-known PRM URL preserves the resource query",
	async () => {
		// The stimulus is the full derived URL, not the path: a path-only
		// accessor cannot express a query, which is why the sibling case
		// rfc9728-well-known-path-must-derive-from-resource-uri stays path-only.
		const cases: Array<[string, string]> = [
			[
				"https://api.example.com/mcp?tenant=a",
				"https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
			],
			[
				"https://api.example.com/mcp?tenant=b",
				"https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=b",
			],
			// No path and no terminating slash, so RFC 9728 §3.1 has no slash to
			// remove: the suffix lands directly after the host and the query
			// follows it.
			[
				"https://api.example.com?x=1",
				"https://api.example.com/.well-known/oauth-protected-resource?x=1",
			],
		];
		const derived = cases.map(([resource, expectedUrl]) => {
			const url = oauthProtectedResourceMetadataDocumentUrl(resource);
			expect(url).toBe(expectedUrl);
			return url;
		});
		// Two identifiers differing only by their query must not collapse onto
		// one metadata document URL — that is the multi-tenant misroute the
		// case exists to forbid, and it fails with a 200 and no server signal.
		expect(new Set(derived).size).toBe(derived.length);
	},
);

conformanceCase(
	"rfc8707-resource-indicator-must-not-contain-a-fragment",
	"RFC8707: a resource indicator carrying a fragment is rejected at construction",
	async () => {
		const fixture = await createTestFixture();
		try {
			// Rejection has to be observable from the construction call itself.
			// An SDK that hands back a resource object and only fails later — or
			// never, because the fragment was dropped while deriving the
			// well-known URL — does not satisfy this case.
			const construct = (): unknown =>
				fixture.client.resource({
					resource: "https://api.example.com/mcp#section",
					scopes: ["read:data"],
				});
			expect(construct).toThrow(TypeError);
			expect(construct).toThrow(/must not contain a fragment component/u);
		} finally {
			await fixture.close();
		}
	},
);

conformanceCase(
	"rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host",
	"RFC9728: a resource identifier without a scheme and a host is rejected at construction",
	async () => {
		const fixture = await createTestFixture();
		try {
			// Each value must reject on its own, and the two are not redundant:
			// `//api.example.com/mcp` parses with a non-empty authority, so a
			// guard phrased as "opaque or authority-less" admits it while
			// correctly rejecting `/mcp`. The scheme is what both lack.
			for (const resource of ["/mcp", "//api.example.com/mcp"]) {
				const construct = (): unknown =>
					fixture.client.resource({ resource, scopes: ["read:data"] });
				expect(construct).toThrow(TypeError);
				expect(construct).toThrow(
					/must be an absolute URL with a scheme and a host/u,
				);
			}
			// Scheme-and-host, not https-only. The case explicitly keeps a
			// loopback `http` identifier acceptable — local development loops
			// depend on it — so a gate narrowed to https would fail here.
			expect(() =>
				fixture.client.resource({
					resource: "http://localhost:8080/mcp",
					scopes: ["read:data"],
				}),
			).not.toThrow();
		} finally {
			await fixture.close();
		}
	},
);
