import { Buffer } from "node:buffer";

import { expect } from "vitest";

import { FetchSettings } from "../src/auth/fetchSettings.js";
import {
	InvalidClientError,
	InvalidGrantError,
	ProtocolError,
	ServerError,
} from "../src/auth/errors.js";
import {
	type AuthplaneError,
	InsufficientScope,
	InvalidDPoPProof,
	InvalidSignature,
	TokenExpired,
	wwwAuthenticate,
} from "../src/core/errors.js";
import { introspectToken } from "../src/auth/introspection.js";
import { clientCredentialsGrant } from "../src/auth/oauth/clientCredentials.js";
import { parseTokenResponse } from "../src/auth/oauth/parsing.js";
import { revokeToken } from "../src/auth/oauth/revocation.js";
import { exchange } from "../src/auth/oauth/tokenExchange.js";
import { AuthplaneClient } from "../src/core/client.js";
import { IntrospectionRevocation } from "../src/auth/introspection.js";
import { TokenRevoked } from "../src/core/errors.js";

import { conformanceCase } from "./conformanceCase.js";
import {
	createMockAsServer,
	createTokenFactory,
	generateEs256Keypair,
} from "./helpers.js";

// Python parity: mirrors `conformance-tests/test_oauth_protocol_conformance.py`.

const NO_SSRF = new FetchSettings({
	ssrfProtection: false,
	allowHttp: true,
	allowLocalhost: true,
	allowPrivateNetworks: true,
});

const EXCHANGE_SUCCESS_BODY: Record<string, unknown> = {
	access_token: "tok",
	token_type: "Bearer",
	expires_in: 3600,
	issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
};

// ---------------------------------------------------------------------------
// Token endpoint: client_credentials grant
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc6749-client-credentials-success-response",
	"RFC6749: client credentials success response",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				body: {
					access_token: "new_token",
					token_type: "Bearer",
					expires_in: 3600,
					scope: "read",
				},
			},
		});
		try {
			const result = await clientCredentialsGrant({
				tokenEndpoint: `${server.origin}/oauth/token`,
				scope: "read",
				authHeader: { Authorization: "Basic dGVzdDpzZWNyZXQ=" },
				fetchSettings: NO_SSRF,
			});
			expect(result.accessToken).toBe("new_token");
			expect(result.tokenType).toBe("Bearer");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc6749-basic-auth-credentials-must-be-form-urlencoded-before-base64",
	"RFC6749: basic auth credentials are form-url-encoded before base64",
	async () => {
		// Catalog shape: Basic base64(urlencode(client_id):urlencode(client_secret)).
		// Exercised end-to-end via AuthplaneClient.introspect so the wire-level
		// Authorization header is captured by the mock AS.
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
		});
		try {
			const client = await AuthplaneClient.create({
				issuer: server.origin,
				fetchSettings: NO_SSRF,
				auth: {
					clientId: "http://localhost:8080/mcp",
					clientSecret: "s3cret",
				},
			});
			try {
				await client.introspect("tok");
				const authHeader =
					server.introspectionRequests[0]?.headers["authorization"];
				expect(authHeader).toBeDefined();
				expect(authHeader).toMatch(/^Basic /);
				const decoded = Buffer.from(
					(authHeader ?? "").replace(/^Basic /, ""),
					"base64",
				).toString("utf-8");
				expect(decoded).toBe("http%3A%2F%2Flocalhost%3A8080%2Fmcp:s3cret");
			} finally {
				await client.close();
			}
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc6749-invalid-client-must-map-to-authentication-failure",
	"RFC6749: invalid client maps to authentication failure",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				status: 401,
				body: { error: "invalid_client", error_description: "bad creds" },
			},
		});
		try {
			await expect(
				clientCredentialsGrant({
					tokenEndpoint: `${server.origin}/oauth/token`,
					authHeader: { Authorization: "Basic dGVzdDpzZWNyZXQ=" },
					fetchSettings: NO_SSRF,
				}),
			).rejects.toBeInstanceOf(InvalidClientError);
			await expect(
				clientCredentialsGrant({
					tokenEndpoint: `${server.origin}/oauth/token`,
					authHeader: { Authorization: "Basic dGVzdDpzZWNyZXQ=" },
					fetchSettings: NO_SSRF,
				}),
			).rejects.toThrow(/bad creds/);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8707-client-credentials-resource-parameter-should-be-supported",
	"RFC8707: client credentials supports resource parameter",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				body: {
					access_token: "tok",
					token_type: "Bearer",
					expires_in: 3600,
				},
			},
		});
		try {
			await clientCredentialsGrant({
				tokenEndpoint: `${server.origin}/oauth/token`,
				resources: ["https://api.example.com"],
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.body.get("resource")).toBe("https://api.example.com");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc6749-client-credentials-scopes-must-support-multiple-values",
	"RFC6749: client credentials supports multiple scope values",
	async () => {
		// Multiple scope values go on the wire as one space-delimited `scope`
		// parameter. The primitive takes the already-joined string; AuthplaneClient
		// joins the list before calling it.
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				body: {
					access_token: "tok",
					token_type: "Bearer",
					expires_in: 3600,
				},
			},
		});
		try {
			await clientCredentialsGrant({
				tokenEndpoint: `${server.origin}/oauth/token`,
				scope: "read write admin",
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			// URLSearchParams.get decodes; the joined scope value is a single param.
			expect(request?.body.get("scope")).toBe("read write admin");
			// Exactly one scope parameter (not repeated).
			expect(request?.body.getAll("scope")).toHaveLength(1);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8707-client-credentials-multiple-resource-parameters-must-be-emitted",
	"RFC8707: client credentials emits multiple resource parameters",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				body: {
					access_token: "tok",
					token_type: "Bearer",
					expires_in: 3600,
				},
			},
		});
		try {
			await clientCredentialsGrant({
				tokenEndpoint: `${server.origin}/oauth/token`,
				resources: [
					"https://api-one.example.com",
					"https://api-two.example.com",
				],
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			const resources = request?.body.getAll("resource") ?? [];
			expect(resources).toHaveLength(2);
			expect(resources).toContain("https://api-one.example.com");
			expect(resources).toContain("https://api-two.example.com");
		} finally {
			await server.close();
		}
	},
);

// ---------------------------------------------------------------------------
// Token response parsing
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc6749-token-response-must-contain-access-token",
	"RFC6749: token response must contain access_token",
	async () => {
		expect(() => parseTokenResponse({ token_type: "Bearer" })).toThrow(
			ProtocolError,
		);
		expect(() => parseTokenResponse({ token_type: "Bearer" })).toThrow(
			/access_token|missing required fields/,
		);
	},
);

conformanceCase(
	"rfc6749-token-response-token-type-must-be-supported",
	"RFC6749: token response token_type must be supported",
	async () => {
		expect(() =>
			parseTokenResponse({ access_token: "tok", token_type: "N_A" }),
		).toThrow(ProtocolError);
		expect(() =>
			parseTokenResponse({ access_token: "tok", token_type: "N_A" }),
		).toThrow(/unsupported token_type/);
	},
);

conformanceCase(
	"rfc9449-token-response-token-type-dpop-must-be-accepted",
	"RFC9449: token response accepts DPoP token_type",
	async () => {
		const result = parseTokenResponse({
			access_token: "tok",
			token_type: "DPoP",
		});
		expect(result.tokenType).toBe("DPoP");
	},
);

conformanceCase(
	"rfc6749-token-response-expires-in-must-be-non-negative-integer",
	"RFC6749: expires_in must be non-negative integer",
	async () => {
		expect(() =>
			parseTokenResponse({
				access_token: "tok",
				token_type: "Bearer",
				expires_in: -1,
			}),
		).toThrow(ProtocolError);
		expect(() =>
			parseTokenResponse({
				access_token: "tok",
				token_type: "Bearer",
				expires_in: -1,
			}),
		).toThrow(/non-negative/);
	},
);

conformanceCase(
	"rfc8693-token-exchange-response-must-contain-issued-token-type",
	"RFC8693: token exchange response must contain issued_token_type",
	async () => {
		expect(() =>
			parseTokenResponse(
				{ access_token: "exchanged_token", token_type: "Bearer" },
				{ allowIssuedTokenType: true },
			),
		).toThrow(ProtocolError);
		expect(() =>
			parseTokenResponse(
				{ access_token: "exchanged_token", token_type: "Bearer" },
				{ allowIssuedTokenType: true },
			),
		).toThrow(/issued_token_type/);
	},
);

// ---------------------------------------------------------------------------
// Revocation (RFC 7009)
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc7009-revocation-200-is-success-even-for-already-invalid-token",
	"RFC7009: revocation 200 succeeds for already invalid tokens",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeRevocationEndpoint: true,
			revocationResponse: { status: 200, body: {} },
		});
		try {
			await revokeToken({
				revocationEndpoint: `${server.origin}/oauth/revoke`,
				token: "token_to_revoke",
				authHeader: { Authorization: "Basic dGVzdDpzZWNyZXQ=" },
				fetchSettings: NO_SSRF,
			});
		} finally {
			await server.close();
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
	"rfc7009-revocation-request-must-post-token-and-token-type-hint",
	"RFC7009: revocation request posts token and token_type_hint",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeRevocationEndpoint: true,
			revocationResponse: { status: 200, body: {} },
		});
		try {
			await revokeToken({
				revocationEndpoint: `${server.origin}/oauth/revoke`,
				token: "token_to_revoke",
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.revocationRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.body.get("token")).toBe("token_to_revoke");
			expect(request?.body.get("token_type_hint")).toBe("access_token");
		} finally {
			await server.close();
		}
	},
);

// ---------------------------------------------------------------------------
// Introspection (RFC 7662)
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc7662-introspection-request-must-post-token-and-access-token-hint",
	"RFC7662: introspection request posts token and access token hint",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: { body: { active: true } },
		});
		try {
			await introspectToken({
				introspectionEndpoint: `${server.origin}/oauth/introspect`,
				token: "my.raw.token",
				fetchSettings: NO_SSRF,
			});
			const request = server.introspectionRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.body.get("token")).toBe("my.raw.token");
			expect(request?.body.get("token_type_hint")).toBe("access_token");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc7662-introspection-without-credentials-must-not-send-authorization-header",
	"RFC7662: without credentials, no Authorization header is sent",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: { body: { active: true } },
		});
		try {
			await introspectToken({
				introspectionEndpoint: `${server.origin}/oauth/introspect`,
				token: "raw-token",
				fetchSettings: NO_SSRF,
			});
			const request = server.introspectionRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.headers["authorization"]).toBeUndefined();
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc7662-introspection-basic-auth-must-be-supported",
	"RFC7662: basic auth must be supported for introspection",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: { body: { active: true } },
		});
		try {
			// Build Basic auth header the same way the SDK would internally.
			const encodedId = encodeURIComponent("my-client-id");
			const encodedSecret = encodeURIComponent("my-client-secret");
			const encoded = Buffer.from(`${encodedId}:${encodedSecret}`).toString(
				"base64",
			);
			await introspectToken({
				introspectionEndpoint: `${server.origin}/oauth/introspect`,
				token: "raw-token",
				authHeader: { Authorization: `Basic ${encoded}` },
				fetchSettings: NO_SSRF,
			});
			const request = server.introspectionRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.headers["authorization"]).toMatch(/^Basic /);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc7662-introspection-active-false-must-parse-as-inactive",
	"RFC7662: active=false parses as inactive",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: { body: { active: false } },
		});
		try {
			const result = await introspectToken({
				introspectionEndpoint: `${server.origin}/oauth/introspect`,
				token: "raw-token",
				fetchSettings: NO_SSRF,
			});
			expect(result.active).toBe(false);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc7662-introspection-missing-active-must-default-to-inactive",
	"RFC7662: missing active defaults to inactive",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: { body: { error: "invalid_token" } },
		});
		try {
			const result = await introspectToken({
				introspectionEndpoint: `${server.origin}/oauth/introspect`,
				token: "raw-token",
				fetchSettings: NO_SSRF,
			});
			expect(result.active).toBe(false);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc7662-introspection-standard-fields-must-round-trip",
	"RFC7662: standard fields round-trip in introspection response",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: {
				body: {
					active: true,
					scope: "read:data write:data",
					client_id: "client456",
					sub: "user123",
					token_type: "access_token",
					iss: "https://auth.example.com",
					aud: "https://api.example.com",
					exp: 1234567890,
					iat: 1234567800,
					jti: "token-id-123",
				},
			},
		});
		try {
			const result = await introspectToken({
				introspectionEndpoint: `${server.origin}/oauth/introspect`,
				token: "raw-token",
				fetchSettings: NO_SSRF,
			});
			expect(result.active).toBe(true);
			expect(result.scope).toBe("read:data write:data");
			expect(result.clientId).toBe("client456");
			expect(result.sub).toBe("user123");
			expect(result.tokenType).toBe("access_token");
			expect(result.iss).toBe("https://auth.example.com");
			expect(result.exp).toBe(1234567890);
			expect(result.iat).toBe(1234567800);
			expect(result.jti).toBe("token-id-123");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc7662-introspection-audience-must-parse-string-or-array",
	"RFC7662: introspection aud parses string or array",
	async () => {
		const keypair = await generateEs256Keypair();
		const server1 = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: {
				body: { active: true, aud: "https://api.example.com" },
			},
		});
		try {
			const stringResult = (await introspectToken({
				introspectionEndpoint: `${server1.origin}/oauth/introspect`,
				token: "raw-token",
				fetchSettings: NO_SSRF,
			})) as Record<string, unknown>;
			expect(stringResult.active).toBe(true);
			expect(stringResult.aud).toBe("https://api.example.com");
		} finally {
			await server1.close();
		}

		const server2 = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: {
				body: {
					active: true,
					aud: ["https://api.example.com", "https://other.example.com"],
				},
			},
		});
		try {
			const arrayResult = (await introspectToken({
				introspectionEndpoint: `${server2.origin}/oauth/introspect`,
				token: "raw-token",
				fetchSettings: NO_SSRF,
			})) as Record<string, unknown>;
			expect(arrayResult.active).toBe(true);
			expect(arrayResult.aud).toEqual([
				"https://api.example.com",
				"https://other.example.com",
			]);
		} finally {
			await server2.close();
		}
	},
);

// ---------------------------------------------------------------------------
// End-to-end introspection-backed revocation
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc7662-verifier-active-false-must-reject-token",
	"RFC7662: verifier rejects tokens when introspection says inactive",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: { body: { active: false } },
		});
		try {
			const client = await AuthplaneClient.create({
				issuer: server.origin,
				fetchSettings: NO_SSRF,
			});
			try {
				const resource = client.resource({
					resource: `${server.origin}/api`,
					scopes: ["read:data"],
					revocationChecker: IntrospectionRevocation.get(),
				});
				const token = await createTokenFactory(keypair)({
					iss: server.origin,
					aud: `${server.origin}/api`,
				});
				await expect(resource.verify(token)).rejects.toBeInstanceOf(
					TokenRevoked,
				);
			} finally {
				await client.close();
			}
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc7662-introspection-fail-open-policy-must-be-explicitly-tested",
	"RFC7662: fail-open policy explicitly tested",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			includeIntrospectionEndpoint: true,
			introspectionResponse: { status: 500, body: { error: "server_error" } },
		});
		try {
			const client = await AuthplaneClient.create({
				issuer: server.origin,
				fetchSettings: NO_SSRF,
			});
			try {
				const resource = client.resource({
					resource: `${server.origin}/api`,
					scopes: ["read:data"],
					revocationChecker: IntrospectionRevocation.get(),
				});
				const token = await createTokenFactory(keypair)({
					iss: server.origin,
					aud: `${server.origin}/api`,
				});
				const claims = await resource.verify(token);
				expect(claims.sub).toBe("user123");
			} finally {
				await client.close();
			}
		} finally {
			await server.close();
		}
	},
);

// ---------------------------------------------------------------------------
// Token exchange (RFC 8693)
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc8693-grant-type-must-be-token-exchange",
	"RFC8693: grant type is token-exchange",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: { body: EXCHANGE_SUCCESS_BODY },
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: { subjectToken: "subject" },
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.body.get("grant_type")).toBe(
				"urn:ietf:params:oauth:grant-type:token-exchange",
			);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-subject-token-is-required",
	"RFC8693: subject token is required",
	async () => {
		await expect(
			exchange({
				tokenEndpoint: "https://auth.example.com/oauth/token",
				exchange: { subjectToken: "" },
				authHeader: {},
				fetchSettings: NO_SSRF,
			}),
		).rejects.toThrow(/subject.?token/i);
	},
);

conformanceCase(
	"rfc8693-default-subject-token-type-is-access-token",
	"RFC8693: default subject token type is access token",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: { body: EXCHANGE_SUCCESS_BODY },
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: { subjectToken: "subject" },
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.body.get("subject_token_type")).toBe(
				"urn:ietf:params:oauth:token-type:access_token",
			);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-actor-token-type-defaults-when-actor-token-is-present",
	"RFC8693: actor token type defaults when actor token present",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: { body: EXCHANGE_SUCCESS_BODY },
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: { subjectToken: "subject", actorToken: "actor" },
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.body.get("actor_token")).toBe("actor");
			expect(request?.body.get("actor_token_type")).toBe(
				"urn:ietf:params:oauth:token-type:access_token",
			);
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-resource-parameter-must-be-sent-when-configured",
	"RFC8693: resource parameter emitted when configured",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: { body: EXCHANGE_SUCCESS_BODY },
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: {
					subjectToken: "subject",
					resources: ["https://mcp.example.com/"],
				},
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			expect(request?.body.get("resource")).toBe("https://mcp.example.com/");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-multiple-resource-parameters-must-be-emitted",
	"RFC8693: multiple resource parameters emitted",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: { body: EXCHANGE_SUCCESS_BODY },
		});
		try {
			await exchange({
				tokenEndpoint: `${server.origin}/oauth/token`,
				exchange: {
					subjectToken: "subject",
					resources: [
						"https://api-one.example.com",
						"https://api-two.example.com",
					],
				},
				authHeader: {},
				fetchSettings: NO_SSRF,
			});
			const request = server.tokenRequests.at(-1);
			expect(request).toBeDefined();
			const resources = request?.body.getAll("resource") ?? [];
			expect(resources).toHaveLength(2);
			expect(resources).toContain("https://api-one.example.com");
			expect(resources).toContain("https://api-two.example.com");
		} finally {
			await server.close();
		}
	},
);

conformanceCase(
	"rfc8693-error-mapping-invalid-grant",
	"RFC8693: invalid_grant errors are mapped correctly",
	async () => {
		const keypair = await generateEs256Keypair();
		const server = await createMockAsServer({
			keypair,
			tokenResponse: {
				status: 400,
				body: { error: "invalid_grant", error_description: "token expired" },
			},
		});
		try {
			await expect(
				exchange({
					tokenEndpoint: `${server.origin}/oauth/token`,
					exchange: { subjectToken: "subject" },
					authHeader: {},
					fetchSettings: NO_SSRF,
				}),
			).rejects.toBeInstanceOf(InvalidGrantError);
			await expect(
				exchange({
					tokenEndpoint: `${server.origin}/oauth/token`,
					exchange: { subjectToken: "subject" },
					authHeader: {},
					fetchSettings: NO_SSRF,
				}),
			).rejects.toThrow(/token expired/);
		} finally {
			await server.close();
		}
	},
);

// ---------------------------------------------------------------------------
// RFC 6750 — WWW-Authenticate error response helpers
// ---------------------------------------------------------------------------

conformanceCase(
	"rfc6750-error-response-realm-should-be-included",
	"RFC6750: error response SHOULD include realm",
	async () => {
		const realm = "https://api.example.com";
		const scenarios: Array<{ error: AuthplaneError; scheme: string }> = [
			{ error: new TokenExpired(), scheme: "Bearer" },
			{ error: new InvalidDPoPProof(), scheme: "DPoP" },
		];
		for (const { error, scheme } of scenarios) {
			const header = wwwAuthenticate(error, { realm });
			expect(header).toContain(`realm="${realm}"`);
			expect(header.startsWith(`${scheme} `)).toBe(true);
		}
	},
);

conformanceCase(
	"rfc6750-error-response-must-map-error-codes",
	"RFC6750: error response maps error codes",
	async () => {
		const scenarios: Array<{
			error: AuthplaneError;
			code: string;
			scheme: string;
		}> = [
			{ error: new TokenExpired(), code: "invalid_token", scheme: "Bearer" },
			{
				error: new InvalidSignature(),
				code: "invalid_token",
				scheme: "Bearer",
			},
			{
				error: new InsufficientScope(),
				code: "insufficient_scope",
				scheme: "Bearer",
			},
			{
				error: new InvalidDPoPProof(),
				code: "invalid_token",
				scheme: "DPoP",
			},
		];
		for (const { error, code, scheme } of scenarios) {
			const header = wwwAuthenticate(error);
			expect(header.startsWith(`${scheme} `)).toBe(true);
			expect(header).toContain(`error="${code}"`);
			expect(header).toMatch(/error_description="[^"]*"/);
		}
	},
);
