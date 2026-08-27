import type { ProtectedResourceMetadata } from "@authplane/sdk/core";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { protectedResourceMetadataHandler } from "../src/prmHandler.js";

function buildMetadata(
	overrides: Partial<ProtectedResourceMetadata> = {},
): ProtectedResourceMetadata {
	return {
		resource: "https://api.example.com/mcp",
		authorization_servers: ["https://auth.example.com"],
		resource_signing_alg_values_supported: ["RS256", "ES256"],
		scopes_supported: ["tools/add", "tools/echo"],
		bearer_methods_supported: ["header"],
		dpop_signing_alg_values_supported: ["RS256"],
		dpop_bound_access_tokens_required: false,
		...overrides,
	};
}

describe("protectedResourceMetadataHandler", () => {
	it("serves the RFC 9728 document as JSON at the mounted path", async () => {
		const metadata = buildMetadata();
		const app = new Hono();
		app.get(
			"/.well-known/oauth-protected-resource",
			protectedResourceMetadataHandler(metadata),
		);

		const response = await app.request("/.well-known/oauth-protected-resource");

		expect(response.status).toBe(200);
		expect(response.headers.get("content-type")).toMatch(/application\/json/);
		await expect(response.json()).resolves.toEqual(metadata);
	});

	it("does not require authentication — the handler is publicly reachable", async () => {
		// PRM is part of OAuth discovery; requiring bearer auth to fetch it
		// would create a bootstrapping loop. The handler itself has no auth
		// logic, so a request with no Authorization header still succeeds.
		const metadata = buildMetadata();
		const app = new Hono();
		app.get(
			"/.well-known/oauth-protected-resource",
			protectedResourceMetadataHandler(metadata),
		);

		const response = await app.request("/.well-known/oauth-protected-resource");

		expect(response.status).toBe(200);
	});

	it("serves the exact metadata object provided at construction", async () => {
		const metadata = buildMetadata({
			resource: "https://api.other.example.com/v1",
			authorization_servers: [
				"https://auth.other.example.com",
				"https://auth.backup.example.com",
			],
			dpop_bound_access_tokens_required: true,
		});
		const app = new Hono();
		app.get(
			"/.well-known/oauth-protected-resource",
			protectedResourceMetadataHandler(metadata),
		);

		const response = await app.request("/.well-known/oauth-protected-resource");

		await expect(response.json()).resolves.toEqual(metadata);
	});
});
