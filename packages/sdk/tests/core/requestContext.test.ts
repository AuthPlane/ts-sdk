import { describe, expect, it } from "vitest";

import {
	buildRequestUrl,
	extractDpopHeaderValues,
	pathAndQueryOf,
} from "../../src/core/requestContext.js";

describe("buildRequestUrl — htu pinned to the configured resource origin", () => {
	it("returns origin + path with no override hooks", () => {
		expect(
			buildRequestUrl({
				resourceOrigin: "https://api.example.com",
				pathAndQuery: "/mcp",
			}),
		).toBe("https://api.example.com/mcp");
	});

	it("preserves query strings exactly", () => {
		expect(
			buildRequestUrl({
				resourceOrigin: "https://api.example.com",
				pathAndQuery: "/mcp/tools/call?id=42&mode=live",
			}),
		).toBe("https://api.example.com/mcp/tools/call?id=42&mode=live");
	});

	it("honours a non-default port supplied via the configured resource", () => {
		expect(
			buildRequestUrl({
				resourceOrigin: "https://api.example.com:8443",
				pathAndQuery: "/mcp",
			}),
		).toBe("https://api.example.com:8443/mcp");
	});

	it("ensures a leading slash on a bare path", () => {
		expect(
			buildRequestUrl({
				resourceOrigin: "https://api.example.com",
				pathAndQuery: "mcp/tools",
			}),
		).toBe("https://api.example.com/mcp/tools");
	});

	it("strips a trailing slash from the resource origin (defensive)", () => {
		expect(
			buildRequestUrl({
				resourceOrigin: "https://api.example.com/",
				pathAndQuery: "/mcp",
			}),
		).toBe("https://api.example.com/mcp");
	});
});

describe("pathAndQueryOf", () => {
	it("extracts pathname + search from an absolute URL", () => {
		expect(pathAndQueryOf("https://api.example.com/mcp?x=1")).toBe("/mcp?x=1");
	});

	it("returns the root path for an authority-only URL", () => {
		expect(pathAndQueryOf("https://api.example.com")).toBe("/");
	});

	it("drops the fragment", () => {
		expect(pathAndQueryOf("https://api.example.com/mcp?x=1#frag")).toBe(
			"/mcp?x=1",
		);
	});

	it("throws a TypeError naming the helper and the offending input", () => {
		expect(() => pathAndQueryOf("not a url")).toThrow(TypeError);
		expect(() => pathAndQueryOf("not a url")).toThrow(
			/pathAndQueryOf: argument must be an absolute URL \(got "not a url"\)/u,
		);
	});
});

describe("extractDpopHeaderValues", () => {
	it("returns a single-entry array for a non-empty string header", () => {
		expect(extractDpopHeaderValues("eyJ.proof.value")).toEqual([
			"eyJ.proof.value",
		]);
	});

	it("returns an empty array when the header is absent", () => {
		expect(extractDpopHeaderValues(undefined)).toEqual([]);
	});

	it("returns an empty array when the header is the empty string", () => {
		expect(extractDpopHeaderValues("")).toEqual([]);
	});

	it("preserves every value for a multi-valued header (Node string[])", () => {
		// §4.3 detection happens in `buildDPoPRequestContext`; this helper
		// just normalises the wire shape, so duplicates must survive.
		expect(extractDpopHeaderValues(["proof-a", "proof-b"])).toEqual([
			"proof-a",
			"proof-b",
		]);
	});

	it("filters empty strings out of a multi-valued header", () => {
		expect(extractDpopHeaderValues(["", "proof-only"])).toEqual([
			"proof-only",
		]);
	});
});
