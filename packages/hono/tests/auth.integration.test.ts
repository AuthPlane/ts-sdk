import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { serve } from "@hono/node-server";
import {
	AuthplaneClient,
	AuthplaneError,
	type AuthplaneResource,
	type DPoPReplayStore,
	httpStatus,
	InsufficientScope,
	VerifiedClaims,
	wwwAuthenticate,
} from "@authplane/sdk/core";
import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";

import { authplaneHonoAuth } from "../src/authplaneHonoAuth.js";
import { requireScope } from "../src/requireScope.js";
import type { HonoAuthVariables } from "../src/types.js";

/**
 * End-to-end integration tests for the `@authplane/hono` adapter.
 *
 * Unlike the per-module unit tests, these spin up a real HTTP server via
 * `@hono/node-server`, issue actual `fetch` requests over the loopback
 * interface, and assert the on-the-wire response. Two things this catches
 * that in-process `app.request` cannot:
 *
 * - The `DPoP` header really survives Node's `http` parser with its
 *   original casing / value.
 * - The middleware actually closes the response (no dangling handlers) when
 *   a 401 / 403 is returned — without that, real clients would hang.
 *
 * The `AuthplaneClient.create` call is still mocked so the tests don't
 * require network access to an OAuth server.
 */
describe("authplaneHonoAuth integration", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	async function withServer<T>(
		app: Hono<{ Variables: HonoAuthVariables }>,
		run: (baseUrl: string) => Promise<T>,
	): Promise<T> {
		const server = serve({ fetch: app.fetch, port: 0, createServer });
		try {
			const { port } = (
				server as import("node:http").Server
			).address() as AddressInfo;
			const baseUrl = `http://127.0.0.1:${port}`;
			return await run(baseUrl);
		} finally {
			await new Promise<void>((resolve, reject) => {
				(server as import("node:http").Server).close((err) =>
					err ? reject(err) : resolve(),
				);
			});
		}
	}

	function buildClaims(
		overrides: Partial<ConstructorParameters<typeof VerifiedClaims>[0]> = {},
	): VerifiedClaims {
		return new VerifiedClaims({
			sub: "user_123",
			clientId: "client_456",
			scopes: ["tools/add"],
			issuer: "https://auth.example.com",
			audience: ["https://api.example.com/mcp"],
			expiresAt: Math.floor(Date.now() / 1000) + 3_600,
			issuedAt: Math.floor(Date.now() / 1000) - 10,
			jti: "token_123",
			kid: "key_1",
			agentId: "",
			agentChain: [],
			notBefore: 0,
			raw: { sub: "user_123" },
			...overrides,
		});
	}

	function mockSdk(
		options: {
			verify?: ReturnType<typeof vi.fn>;
			prm?: Record<string, unknown>;
			prmDocumentUrl?: string;
		} = {},
	) {
		const verify = options.verify ?? vi.fn(async () => buildClaims());
		const prm = options.prm ?? {
			resource: "https://api.example.com/mcp",
			authorization_servers: ["https://auth.example.com"],
			scopes_supported: ["tools/add"],
			bearer_methods_supported: ["header"],
		};
		const prmDocumentUrl =
			options.prmDocumentUrl ??
			"https://api.example.com/.well-known/oauth-protected-resource/mcp";

		const resource = {
			verify,
			prmResponse: vi.fn(() => prm),
			prmDocumentUrl: vi.fn(() => prmDocumentUrl),
		} as unknown as AuthplaneResource;

		const client = {
			resource: vi.fn(() => resource),
		} as unknown as AuthplaneClient;

		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);
		return { verify, resource, client };
	}

	it("serves PRM, rejects unauthenticated requests with a proper 401, and accepts valid tokens", async () => {
		mockSdk();
		const auth = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
		});

		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get(
			auth.protectedResourceMetadataPath,
			auth.protectedResourceMetadataHandler,
		);
		app.use("/mcp", auth.bearerAuth);
		app.post("/mcp", (c) => {
			const info = c.get("auth");
			return c.json({
				ok: true,
				clientId: info.clientId,
				scopes: info.scopes,
			});
		});

		await withServer(app, async (baseUrl) => {
			const prmRes = await fetch(
				`${baseUrl}${auth.protectedResourceMetadataPath}`,
			);
			expect(prmRes.status).toBe(200);
			const prmBody = (await prmRes.json()) as { resource: string };
			expect(prmBody.resource).toBe("https://api.example.com/mcp");

			const unauthorized = await fetch(`${baseUrl}/mcp`, { method: "POST" });
			expect(unauthorized.status).toBe(401);
			const wwwAuth = unauthorized.headers.get("www-authenticate");
			expect(wwwAuth).toContain('error="invalid_token"');
			expect(wwwAuth).toContain(
				'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
			);

			const ok = await fetch(`${baseUrl}/mcp`, {
				method: "POST",
				headers: { Authorization: "Bearer valid_jwt" },
			});
			expect(ok.status).toBe(200);
			await expect(ok.json()).resolves.toEqual({
				ok: true,
				clientId: "client_456",
				scopes: ["tools/add"],
			});
		});
	});

	it("threads DPoP proofs through to the verifier over a real HTTP transport", async () => {
		const replayStore = {
			checkAndStore: vi.fn(async () => true),
		} as unknown as DPoPReplayStore;
		const { verify } = mockSdk();

		const auth = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
			replayStore,
		});

		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("/mcp", auth.bearerAuth);
		app.post("/mcp", (c) => c.json({ ok: true }));

		await withServer(app, async (baseUrl) => {
			const res = await fetch(`${baseUrl}/mcp`, {
				method: "POST",
				headers: {
					Authorization: "Bearer valid_jwt",
					DPoP: "eyJ.proof.value",
				},
			});
			expect(res.status).toBe(200);
		});

		expect(verify).toHaveBeenCalledTimes(1);
		// DPoPRequestContext is request-shape only — the replay store lives
		// on the resource via inboundDPoP and the SDK applies it on verify.
		const [token, { dpopRequest }] = verify.mock.calls[0] as [
			string,
			{
				dpopRequest: {
					method: string;
					url: string;
					proofs: readonly string[];
				};
			},
		];
		expect(token).toBe("valid_jwt");
		expect(dpopRequest.method).toBe("POST");
		// htu is anchored to the configured resource origin, not the
		// 127.0.0.1:<port> address the test server actually listens on.
		// That's the whole point of the resource-origin hardening.
		expect(dpopRequest.url).toBe("https://api.example.com/mcp");
		expect(dpopRequest.proofs).toEqual(["eyJ.proof.value"]);
	});

	it("returns 403 when requireScope is called inside a handler for a missing scope", async () => {
		const { verify } = mockSdk();
		verify.mockResolvedValue(buildClaims({ scopes: ["tools/echo"] }));

		const auth = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: [],
		});

		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("/mcp/*", auth.bearerAuth);
		app.post("/mcp/tools/add", (c) => {
			requireScope(c, "tools/add");
			return c.json({ ok: true });
		});
		app.onError((err, c) => {
			// Idiomatic opt-in error bridge: map any AuthplaneError thrown by
			// requireScope through core's httpStatus() + wwwAuthenticate().
			if (err instanceof AuthplaneError) {
				c.header("WWW-Authenticate", wwwAuthenticate(err));
				const code =
					err instanceof InsufficientScope
						? "insufficient_scope"
						: "invalid_token";
				const status = httpStatus(err) as 400 | 401 | 403 | 500 | 503;
				return c.json(
					{ error: code, error_description: err.message },
					status,
				);
			}
			return c.json({ error: "server_error" }, 500);
		});

		await withServer(app, async (baseUrl) => {
			const res = await fetch(`${baseUrl}/mcp/tools/add`, {
				method: "POST",
				headers: { Authorization: "Bearer valid_jwt" },
			});
			expect(res.status).toBe(403);
			await expect(res.json()).resolves.toEqual({
				error: "insufficient_scope",
				// requireScope delegates to core claims.requireScope when auth is
				// present, so the message names the missing scope AND the scopes
				// the token does carry.
				error_description:
					"Token missing required scope 'tools/add'. Token has scopes: tools/echo",
			});
		});
	});
});
