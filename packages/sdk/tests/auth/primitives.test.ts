import { afterEach, describe, expect, test, vi } from "vitest";
import {
	FetchSettings,
	InvalidClientError,
	clientCredentialsGrant,
	exchange,
	introspectToken,
	revokeToken,
} from "../../src/auth/index.js";
import { SSRFError } from "../../src/shared/ssrf.js";

function jsonResponse(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

describe("auth primitives", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	test("clientCredentialsGrant parses token response", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
			jsonResponse(200, {
				access_token: "at_123",
				token_type: "Bearer",
				expires_in: 60,
				scope: "tools/read",
			}),
		);
		const token = await clientCredentialsGrant({
			tokenEndpoint: "https://auth.example.com/oauth/token",
			scope: "tools/read",
			authHeader: { Authorization: "Basic x" },
			fetchSettings: new FetchSettings({ ssrfProtection: false }),
		});
		expect(token.accessToken).toBe("at_123");
		expect(token.tokenType).toBe("Bearer");
		expect(token.scope).toBe("tools/read");
	});

	test("exchange supports RFC8693 body and parses response", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
			jsonResponse(200, {
				access_token: "at_exchanged",
				token_type: "Bearer",
				expires_in: 120,
				issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
			}),
		);
		const token = await exchange({
			tokenEndpoint: "https://auth.example.com/oauth/token",
			exchange: {
				subjectToken: "subject_at",
				scope: "tools/write",
				resources: ["https://api.example.com/mcp"],
			},
			authHeader: { Authorization: "Basic x" },
			fetchSettings: new FetchSettings({ ssrfProtection: false }),
		});
		expect(token.accessToken).toBe("at_exchanged");
		expect(token.issuedTokenType).toBe(
			"urn:ietf:params:oauth:token-type:access_token",
		);
	});

	test("introspectToken parses active=false response", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
			jsonResponse(200, {
				active: false,
				scope: "tools/read",
				client_id: "client_1",
			}),
		);
		const info = await introspectToken({
			introspectionEndpoint: "https://auth.example.com/oauth/introspect",
			token: "at_123",
			authHeader: { Authorization: "Basic x" },
			fetchSettings: new FetchSettings({ ssrfProtection: false }),
		});
		expect(info.active).toBe(false);
		expect(info.clientId).toBe("client_1");
	});

	test("revokeToken resolves on 200", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(jsonResponse(200, {}));
		await expect(
			revokeToken({
				revocationEndpoint: "https://auth.example.com/oauth/revoke",
				token: "at_123",
				authHeader: { Authorization: "Basic x" },
				fetchSettings: new FetchSettings({ ssrfProtection: false }),
			}),
		).resolves.toBeUndefined();
	});

	test("revokeToken sends default token_type_hint=access_token", async () => {
		const fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValueOnce(jsonResponse(200, {}));
		await revokeToken({
			revocationEndpoint: "https://auth.example.com/oauth/revoke",
			token: "at_123",
			authHeader: { Authorization: "Basic x" },
			fetchSettings: new FetchSettings({ ssrfProtection: false }),
		});
		const body = String((fetchSpy.mock.calls[0]?.[1] as RequestInit).body);
		expect(body).toContain("token_type_hint=access_token");
	});

	test("revokeToken forwards tokenTypeHint override (refresh_token)", async () => {
		const fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValueOnce(jsonResponse(200, {}));
		await revokeToken({
			revocationEndpoint: "https://auth.example.com/oauth/revoke",
			token: "rt_xyz",
			authHeader: { Authorization: "Basic x" },
			fetchSettings: new FetchSettings({ ssrfProtection: false }),
			tokenTypeHint: "refresh_token",
		});
		const body = String((fetchSpy.mock.calls[0]?.[1] as RequestInit).body);
		expect(body).toContain("token_type_hint=refresh_token");
		expect(body).not.toContain("access_token");
	});

	test("clientCredentialsGrant maps OAuth errors", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
			jsonResponse(401, {
				error: "invalid_client",
				error_description: "bad credentials",
			}),
		);
		await expect(
			clientCredentialsGrant({
				tokenEndpoint: "https://auth.example.com/oauth/token",
				authHeader: { Authorization: "Basic x" },
				fetchSettings: new FetchSettings({ ssrfProtection: false }),
			}),
		).rejects.toBeInstanceOf(InvalidClientError);
	});

	test("clientCredentialsGrant retries once on DPoP nonce challenge", async () => {
		const fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						error: "use_dpop_nonce",
					}),
					{
						status: 400,
						headers: {
							"Content-Type": "application/json",
							"dpop-nonce": "nonce-1",
						},
					},
				),
			)
			.mockResolvedValueOnce(
				jsonResponse(200, {
					access_token: "at_retry",
					token_type: "DPoP",
					expires_in: 120,
				}),
			);
		const dpopProvider = {
			buildHeadersAsync: vi
				.fn()
				.mockResolvedValue({ dpop: "proof-jwt" } as Record<string, string>),
			noteNonce: vi.fn(),
		};

		const token = await clientCredentialsGrant({
			tokenEndpoint: "https://auth.example.com/oauth/token",
			authHeader: { Authorization: "Basic x" },
			fetchSettings: new FetchSettings({ ssrfProtection: false }),
			dpopProvider,
		});

		expect(token.accessToken).toBe("at_retry");
		expect(fetchSpy).toHaveBeenCalledTimes(2);
		expect(dpopProvider.noteNonce).toHaveBeenCalledWith(
			"https://auth.example.com/oauth/token",
			"nonce-1",
		);
	});

	test("ssrfProtection path blocks localhost by policy", async () => {
		await expect(
			clientCredentialsGrant({
				tokenEndpoint: "http://127.0.0.1:9000/oauth/token",
				authHeader: { Authorization: "Basic x" },
				fetchSettings: new FetchSettings({
					ssrfProtection: true,
					allowHttp: true,
					allowLocalhost: false,
					allowPrivateNetworks: false,
				}),
			}),
		).rejects.toBeInstanceOf(SSRFError);
	});
});
