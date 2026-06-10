import { VerifiedClaims } from "@authplane/sdk/core";
import { describe, expect, it } from "vitest";

import {
	AUTH_INFO_REQUEST_KEY,
	defaultRequestAdapter,
} from "../../src/infrastructure/request-adapter.js";

function expressReq(overrides: Record<string, unknown> = {}) {
	return {
		method: "POST",
		originalUrl: "/math/add?mode=live",
		headers: {
			authorization: "Bearer abc",
			dpop: "proof-value",
		},
		...overrides,
	};
}

function fastifyReq(overrides: Record<string, unknown> = {}) {
	return {
		// Fastify's wrapper exposes the same fields on top-level + `raw`.
		method: "POST",
		headers: {
			authorization: "Bearer abc",
			dpop: "proof-value",
		},
		raw: {
			url: "/math/add?mode=live",
			headers: {
				authorization: "Bearer abc",
				dpop: "proof-value",
			},
			method: "post",
		},
		...overrides,
	};
}

describe("defaultRequestAdapter.getHeader", () => {
	it("reads case-insensitively on an Express-style request", () => {
		const req = expressReq();
		expect(defaultRequestAdapter.getHeader(req, "Authorization")).toBe(
			"Bearer abc",
		);
		expect(defaultRequestAdapter.getHeader(req, "AUTHORIZATION")).toBe(
			"Bearer abc",
		);
		expect(defaultRequestAdapter.getHeader(req, "DPoP")).toBe("proof-value");
	});

	it("falls back to request.raw.headers for Fastify-style requests", () => {
		const req = fastifyReq({ headers: {} });
		expect(defaultRequestAdapter.getHeader(req, "authorization")).toBe(
			"Bearer abc",
		);
	});

	it("returns undefined when the header is absent", () => {
		expect(defaultRequestAdapter.getHeader(expressReq({ headers: {} }), "authorization"))
			.toBeUndefined();
	});

	it("returns undefined for duplicate-named Authorization (Express)", () => {
		// Picking the first value would be a header-smuggling vector
		// (intermediaries disagree on which copy is canonical), and we want
		// the downstream BearerToken parser to treat the request as missing
		// the header. RFC 9449 §4.2 also forbids more than one DPoP header.
		const req = expressReq({
			headers: { authorization: ["Bearer a", "Bearer b"] },
		});
		expect(
			defaultRequestAdapter.getHeader(req, "authorization"),
		).toBeUndefined();
	});

	it("returns undefined for duplicate-named DPoP (Express)", () => {
		const req = expressReq({
			headers: { dpop: ["proof-a", "proof-b"] },
		});
		expect(defaultRequestAdapter.getHeader(req, "DPoP")).toBeUndefined();
	});

	it("returns undefined for duplicate-named Authorization (Fastify raw)", () => {
		const req = fastifyReq({
			headers: {},
			raw: {
				url: "/x",
				method: "post",
				headers: { authorization: ["Bearer a", "Bearer b"] },
			},
		});
		expect(
			defaultRequestAdapter.getHeader(req, "authorization"),
		).toBeUndefined();
	});

	it("returns undefined for duplicate-named DPoP (Fastify raw)", () => {
		const req = fastifyReq({
			headers: {},
			raw: {
				url: "/x",
				method: "post",
				headers: { dpop: ["proof-a", "proof-b"] },
			},
		});
		expect(defaultRequestAdapter.getHeader(req, "DPoP")).toBeUndefined();
	});

	it("returns undefined when the request has no headers at all", () => {
		expect(defaultRequestAdapter.getHeader({}, "authorization")).toBeUndefined();
	});
});

describe("defaultRequestAdapter.getHeaderValues", () => {
	it("returns a single string when the DPoP header arrives as a string", () => {
		const req = expressReq();
		expect(defaultRequestAdapter.getHeaderValues(req, "DPoP")).toBe(
			"proof-value",
		);
	});

	it("preserves the array shape for duplicate-named DPoP headers (Express)", () => {
		// `getHeader` collapses arrays to undefined for header-smuggling
		// protection; `getHeaderValues` must NOT — DPoP needs the multi-value
		// shape so the SDK can raise `MultipleDPoPProofs` (RFC 9449 §4.3).
		const req = expressReq({
			headers: { dpop: ["proof-a", "proof-b"] },
		});
		expect(defaultRequestAdapter.getHeaderValues(req, "DPoP")).toEqual([
			"proof-a",
			"proof-b",
		]);
	});

	it("preserves the array shape for duplicate-named DPoP headers (Fastify raw)", () => {
		const req = fastifyReq({
			headers: {},
			raw: {
				url: "/x",
				method: "post",
				headers: { dpop: ["proof-a", "proof-b"] },
			},
		});
		expect(defaultRequestAdapter.getHeaderValues(req, "DPoP")).toEqual([
			"proof-a",
			"proof-b",
		]);
	});

	it("returns undefined when the header is absent", () => {
		expect(
			defaultRequestAdapter.getHeaderValues(
				expressReq({ headers: {} }),
				"dpop",
			),
		).toBeUndefined();
	});
});

describe("defaultRequestAdapter.getMethod", () => {
	it("uppercases the Express method", () => {
		expect(defaultRequestAdapter.getMethod(expressReq({ method: "post" }))).toBe(
			"POST",
		);
	});

	it("falls back to request.raw.method for Fastify-style requests", () => {
		expect(defaultRequestAdapter.getMethod(fastifyReq({ method: undefined }))).toBe(
			"POST",
		);
	});

	it("defaults to POST when no method is exposed", () => {
		expect(defaultRequestAdapter.getMethod({})).toBe("POST");
	});
});

describe("defaultRequestAdapter.getPathAndQuery", () => {
	it("prefers req.originalUrl (Express)", () => {
		expect(
			defaultRequestAdapter.getPathAndQuery(
				expressReq({ originalUrl: "/a?b=1", url: "/ignored" }),
			),
		).toBe("/a?b=1");
	});

	it("uses req.url when originalUrl is missing", () => {
		expect(
			defaultRequestAdapter.getPathAndQuery({ url: "/just-url" }),
		).toBe("/just-url");
	});

	it("falls back to req.raw.url when neither originalUrl nor url is set", () => {
		expect(
			defaultRequestAdapter.getPathAndQuery({
				raw: { url: "/from-raw" },
			}),
		).toBe("/from-raw");
	});

	it("defaults to '/' when nothing is set", () => {
		expect(defaultRequestAdapter.getPathAndQuery({})).toBe("/");
	});
});

describe("defaultRequestAdapter auth-info stash round-trip", () => {
	const claims = new VerifiedClaims({
		sub: "s",
		clientId: "c",
		scopes: [],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: 0,
		issuedAt: 0,
		jti: "j",
		kid: "k",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: {},
	});

	it("stashAuthInfo writes to the documented symbol key", () => {
		const req: Record<symbol, unknown> = {};
		defaultRequestAdapter.stashAuthInfo(req, claims);
		// The @AuthInfo() parameter decorator reads this symbol key directly
		// (no round-trip through the adapter), so custom adapters must keep
		// the contract: write under AUTH_INFO_REQUEST_KEY or @AuthInfo()
		// silently returns undefined.
		expect(req[AUTH_INFO_REQUEST_KEY]).toBe(claims);
	});
});
