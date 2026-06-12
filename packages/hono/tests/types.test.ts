import { VerifiedClaims } from "@authplane/sdk/core";
import { Hono } from "hono";
import { describe, expectTypeOf, it } from "vitest";

import type { HonoAuthVariables } from "../src/index.js";

const fixture = new VerifiedClaims({
	sub: "user-1",
	clientId: "client-1",
	scopes: ["tools/add"],
	issuer: "https://auth.example.com",
	audience: ["https://api.example.com/mcp"],
	expiresAt: 1_750_000_000,
	issuedAt: 1_749_999_000,
	jti: "jti-1",
	kid: "kid-1",
	agentId: "",
	agentChain: [],
	notBefore: 0,
	raw: { sub: "user-1" },
});

describe("HonoAuthVariables", () => {
	it("shapes c.get(\"auth\") / c.set(\"auth\", …)", () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();

		app.get("/typed", (c) => {
			const auth = c.get("auth");
			expectTypeOf(auth).toEqualTypeOf<VerifiedClaims>();
			return c.json({ sub: auth.sub });
		});

		app.use("*", (c, next) => {
			c.set("auth", fixture);
			// @ts-expect-error — string is not assignable to VerifiedClaims
			c.set("auth", "nope");
			return next();
		});
	});

	it("is structurally equivalent to { auth: VerifiedClaims }", () => {
		expectTypeOf<HonoAuthVariables>().toEqualTypeOf<{
			auth: VerifiedClaims;
		}>();
	});
});
