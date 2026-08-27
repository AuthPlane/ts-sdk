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

conformanceCase(
	"rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache",
	"RFC8414: jwks_uri rotation reconfigures JWKS cache",
	async () => {
		// Catalog stimulus: `client._on_metadata_changed` side-effect must rebind
		// JWKS fetching when metadata.jwks_uri changes.
		//
		// TS has no equivalent public method, so this test reaches into private
		// state to invoke `_on_metadata_changed` and force a metadata refetch,
		// then exercises the end-to-end side effect: a token signed with the v2
		// key must verify, which is only possible if the JWKS cache now points
		// at /jwks-v2.json.

		const v1 = await generateEs256Keypair("key-v1");
		const v2 = await generateEs256Keypair("key-v2");

		let currentJwksUriPath = "/jwks-v1.json";
		const { createServer } = await import("node:http");
		const server = createServer();
		await new Promise<void>((resolve) =>
			server.listen(0, "127.0.0.1", resolve),
		);
		const addr = server.address() as import("node:net").AddressInfo;
		const origin = `http://127.0.0.1:${addr.port}`;

		server.on("request", (req, res) => {
			const url = req.url ?? "";
			res.setHeader("content-type", "application/json");
			if (
				req.method === "GET" &&
				url === "/.well-known/oauth-authorization-server"
			) {
				res.end(
					JSON.stringify({
						issuer: origin,
						jwks_uri: `${origin}${currentJwksUriPath}`,
					}),
				);
				return;
			}
			if (req.method === "GET" && url === "/jwks-v1.json") {
				res.end(JSON.stringify(v1.jwks));
				return;
			}
			if (req.method === "GET" && url === "/jwks-v2.json") {
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

			currentJwksUriPath = "/jwks-v2.json";

			// Force metadata refetch; onChange should rebind the JWKS cache.
			const privateAccess = client as unknown as {
				metadataCache: { get(force?: boolean): Promise<unknown> };
			};
			await privateAccess.metadataCache.get(true);
			// onChange is fired via `void` — wait for the rebind to settle.
			await new Promise<void>((resolve) => setTimeout(resolve, 50));

			const { createTokenFactory } = await import("./helpers.js");
			const token = await createTokenFactory(v2)({
				iss: origin,
				aud: `${origin}/api`,
			});

			const resource = client.resource({
				resource: `${origin}/api`,
				scopes: ["read:data"],
			});
			await resource.verify(token);
			await client.close();
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	},
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
