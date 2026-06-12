import { InsufficientScope, VerifiedClaims } from "@authplane/sdk/core";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { requireScope } from "../src/requireScope.js";
import type { HonoAuthVariables } from "../src/types.js";

function buildClaims(scopes: readonly string[]): VerifiedClaims {
	return new VerifiedClaims({
		sub: "user_123",
		clientId: "client_456",
		scopes: [...scopes],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: Math.floor(Date.now() / 1000) + 3_600,
		issuedAt: Math.floor(Date.now() / 1000),
		jti: "token_123",
		kid: "key_1",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: {},
	});
}

describe("requireScope", () => {
	it("is a no-op when the requested scope is present on the verified token", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("*", async (c, next) => {
			c.set("auth", buildClaims(["tools/add"]));
			await next();
		});
		let reached = false;
		app.get("/", (c) => {
			requireScope(c, "tools/add");
			reached = true;
			return c.json({ ok: true });
		});

		const res = await app.request("/");
		expect(reached).toBe(true);
		expect(res.status).toBe(200);
	});

	it("throws core InsufficientScope (delegated to claims.requireScope) when the scope is missing", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("*", async (c, next) => {
			c.set("auth", buildClaims(["tools/echo"]));
			await next();
		});
		app.get("/", (c) => {
			requireScope(c, "tools/add");
			return c.json({ ok: true });
		});

		let caught: unknown;
		app.onError((err, c) => {
			caught = err;
			return c.json({ captured: true }, 500);
		});

		await app.request("/");
		expect(caught).toBeInstanceOf(InsufficientScope);
		// Message comes from the canonical core helper so every adapter emits
		// the same wording — caller can see the missing scope AND the scopes
		// the token does carry.
		expect((caught as Error).message).toBe(
			"Token missing required scope 'tools/add'. Token has scopes: tools/echo",
		);
	});

	it("fails closed when bearerAuth never ran (no auth on context)", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", (c) => {
			requireScope(c, "tools/add");
			return c.json({ ok: true });
		});

		let caught: unknown;
		app.onError((err, c) => {
			caught = err;
			return c.json({ captured: true }, 500);
		});

		await app.request("/");
		expect(caught).toBeInstanceOf(InsufficientScope);
		expect((caught as Error).message).toBe(
			"Missing required scope: tools/add",
		);
	});
});
