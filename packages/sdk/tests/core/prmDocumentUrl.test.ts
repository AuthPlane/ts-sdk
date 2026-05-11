import { describe, expect, it } from "vitest";
import { oauthProtectedResourceMetadataDocumentUrl } from "../../src/core/prm.js";

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
});
