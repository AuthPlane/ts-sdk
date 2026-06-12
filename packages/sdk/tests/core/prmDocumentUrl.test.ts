import { describe, expect, it } from "vitest";
import {
	oauthProtectedResourceMetadataDocumentUrl,
	oauthProtectedResourceMetadataPath,
} from "../../src/core/prm.js";

describe("oauthProtectedResourceMetadataDocumentUrl (RFC 9728 §3.1)", () => {
	it("maps resource path under /.well-known/oauth-protected-resource", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://rs.example.com/mcp"),
		).toBe(
			"https://rs.example.com/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("uses empty suffix when resource path is /", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://rs.example.com/"),
		).toBe("https://rs.example.com/.well-known/oauth-protected-resource");
	});

	it("preserves nested resource paths", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl(
				"https://rs.example.com/api/v1/mcp/stream",
			),
		).toBe(
			"https://rs.example.com/.well-known/oauth-protected-resource/api/v1/mcp/stream",
		);
	});

	it("strips trailing slashes on the resource path", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://rs.example.com/mcp/"),
		).toBe(
			"https://rs.example.com/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("throws TypeError on an invalid URL", () => {
		expect(() =>
			oauthProtectedResourceMetadataDocumentUrl("not a url"),
		).toThrow(TypeError);
	});
});

describe("oauthProtectedResourceMetadataPath (RFC 9728 §3.1, path only)", () => {
	it("returns the bare .well-known path when the resource has no path", () => {
		expect(oauthProtectedResourceMetadataPath("https://rs.example.com")).toBe(
			"/.well-known/oauth-protected-resource",
		);
	});

	it("returns the bare .well-known path when the resource path is /", () => {
		expect(oauthProtectedResourceMetadataPath("https://rs.example.com/")).toBe(
			"/.well-known/oauth-protected-resource",
		);
	});

	it("appends the resource path", () => {
		expect(
			oauthProtectedResourceMetadataPath("https://rs.example.com/mcp"),
		).toBe("/.well-known/oauth-protected-resource/mcp");
	});

	it("strips a trailing slash on the resource path", () => {
		expect(
			oauthProtectedResourceMetadataPath("https://rs.example.com/mcp/"),
		).toBe("/.well-known/oauth-protected-resource/mcp");
	});

	it("preserves nested paths", () => {
		expect(
			oauthProtectedResourceMetadataPath("https://rs.example.com/a/b/c"),
		).toBe("/.well-known/oauth-protected-resource/a/b/c");
	});

	it("throws TypeError on an invalid URL", () => {
		expect(() => oauthProtectedResourceMetadataPath("not a url")).toThrow(
			TypeError,
		);
	});
});
