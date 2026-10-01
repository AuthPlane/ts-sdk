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

	it("derives from protocol + host for a non-special scheme — never the literal 'null'", () => {
		// WHATWG `URL.origin` is the string "null" for any scheme outside its
		// special set, while the gate deliberately admits any scheme with a
		// host. The derivation must therefore anchor on `protocol` + `host`,
		// or the advertised URL would begin with `null/`.
		expect(
			oauthProtectedResourceMetadataDocumentUrl("mcp://api.example.com/mcp"),
		).toBe("mcp://api.example.com/.well-known/oauth-protected-resource/mcp");
		expect(
			oauthProtectedResourceMetadataPath("mcp://api.example.com/mcp"),
		).toBe("/.well-known/oauth-protected-resource/mcp");
	});

	it("derives distinct URLs for //mcp and /mcp — the path trim is trailing-only", () => {
		// Regression pin: `resourceMetadataSuffix` strips trailing slashes
		// only. RFC 9728 §3.1 speaks solely of the terminating slash, so
		// `https://api.example.com//mcp` is a different identifier from
		// `https://api.example.com/mcp` and must derive a different document
		// URL. A future tidy-up to a leading-and-trailing trim
		// (`/^\/+|\/+$/g`) would silently merge them.
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://api.example.com//mcp"),
		).toBe("https://api.example.com/.well-known/oauth-protected-resource//mcp");
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://api.example.com//mcp"),
		).not.toBe(
			oauthProtectedResourceMetadataDocumentUrl("https://api.example.com/mcp"),
		);
	});
});

describe("oauthProtectedResourceMetadataDocumentUrl query preservation (RFC 9728 §3)", () => {
	it("carries the resource query into the document URL, after the path", () => {
		// RFC 9728 §3: the well-known string is inserted "between the host
		// component and the path and/or query components, if any" — the query
		// is part of the identifier and survives the insertion.
		expect(
			oauthProtectedResourceMetadataDocumentUrl(
				"https://api.example.com/mcp?tenant=a",
			),
		).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
		);
	});

	it("appends a query directly after the well-known suffix when there is no path", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://api.example.com?x=1"),
		).toBe("https://api.example.com/.well-known/oauth-protected-resource?x=1");
	});

	it("removes the terminating slash following the host when a query is present (RFC 9728 §3.1)", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://api.example.com/?x=1"),
		).toBe("https://api.example.com/.well-known/oauth-protected-resource?x=1");
	});

	it("derives distinct URLs for identifiers differing only by query", () => {
		const a = oauthProtectedResourceMetadataDocumentUrl(
			"https://api.example.com/mcp?tenant=a",
		);
		const b = oauthProtectedResourceMetadataDocumentUrl(
			"https://api.example.com/mcp?tenant=b",
		);
		expect(a).not.toBe(b);
	});

	it("still strips a trailing path slash ahead of the query", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl(
				"https://api.example.com/mcp/?tenant=a",
			),
		).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
		);
	});

	it("treats a bare ? as no query", () => {
		// A trailing bare `?` carries no query bytes, so the derived document
		// URL is the query-less one. Pinned as documented behaviour: the
		// sibling issuer gate rejects a bare `?` (RFC 8414 §2), and this
		// asymmetry is deliberate — a bare `?` is not a fragment and carries
		// no bytes that could corrupt the challenge.
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://api.example.com/mcp?"),
		).toBe("https://api.example.com/.well-known/oauth-protected-resource/mcp");
	});

	it("carries a legal sub-delims query into the document URL byte-for-byte", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl(
				"https://api.example.com/mcp?a=b&c=(d)!$*+,;=:@/?x",
			),
		).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp?a=b&c=(d)!$*+,;=:@/?x",
		);
	});

	it("derives an accepted query without WHATWG re-encoding — ' stays '", () => {
		// `'` is a legal sub-delim, but WHATWG's special-scheme query
		// encode-set rewrites it to `%27` in `URL.search`. The derivation
		// splices the raw configured query, so the configured, served and
		// advertised identifiers are the same bytes.
		expect(
			oauthProtectedResourceMetadataDocumentUrl(
				"https://api.example.com/mcp?a='b",
			),
		).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp?a='b",
		);
	});

	it("rejects a query byte outside RFC 3986 §3.4 instead of corrupting the challenge", () => {
		// A raw `\` is out of the §3.4 grammar, and the header sanitiser
		// would blank it to a space inside the quoted-string
		// `resource_metadata` value — an advertised URL that no longer
		// round-trips to the configured identifier. Construction-time gate.
		expect(() =>
			oauthProtectedResourceMetadataDocumentUrl(
				"https://api.example.com/mcp?path=a\\b",
			),
		).toThrow(/RFC 3986 §3\.4/u);
	});

	it("rejects a fragment ahead of any query handling (RFC 8707 §2)", () => {
		// Ordering pin: the fragment gate runs before derivation looks at the
		// query, so a query-and-fragment identifier reports the fragment.
		expect(() =>
			oauthProtectedResourceMetadataDocumentUrl(
				"https://api.example.com/mcp?tenant=a#frag",
			),
		).toThrow(/RFC 8707 §2/u);
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

	it("excludes the resource query — routing stays path-keyed", () => {
		// The path helper feeds route registration, and routes cannot carry a
		// query. A request for the query-bearing document URL lands on this
		// same path with the query ignored; per-query documents are not
		// supported.
		expect(
			oauthProtectedResourceMetadataPath("https://rs.example.com/mcp?tenant=a"),
		).toBe("/.well-known/oauth-protected-resource/mcp");
	});
});
