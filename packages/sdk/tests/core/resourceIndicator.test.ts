import { describe, expect, it } from "vitest";

import {
	AuthplaneResource,
	buildPrm,
	oauthProtectedResourceMetadataDocumentUrl,
	oauthProtectedResourceMetadataPath,
	validateResourceIndicator,
} from "../../src/core/index.js";

/**
 * Build an `AuthplaneResource` with the client-owned collaborators stubbed out.
 *
 * The indicator gate runs first in the constructor, before anything touches the
 * metadata cache, the fetch settings or the JWKS accessor, so the stubs are
 * never dereferenced on the rejection path — and on the accepted path this
 * suite only reads `prmResponse()` / `prmDocumentUrl()`, which do not touch
 * them either. `InternalResourceOptions` is module-private, hence the cast.
 */
function buildResource(resource: string): AuthplaneResource {
	return new AuthplaneResource({
		resource,
		scopes: ["read"],
		issuer: "https://auth.example.com",
		metadataCache: {},
		fetchSettings: {},
		getJwksCache: () => ({}),
	} as unknown as ConstructorParameters<typeof AuthplaneResource>[0]);
}

describe("validateResourceIndicator (RFC 8707 §2)", () => {
	it("accepts identifiers without a fragment", () => {
		for (const resource of [
			"https://api.example.com",
			"https://api.example.com/",
			"https://api.example.com/mcp",
			"https://api.example.com/mcp/",
			"https://api.example.com/api/v1/mcp/stream",
			"https://api.example.com:8443/mcp",
			"https://[::1]:8443/mcp",
			// A query is legal (RFC 8707 §2 states the SHOULD NOT and its
			// exception in the same sentence) and preserved into the derived
			// document URL; this gate must not start swallowing one.
			"https://api.example.com/mcp?tenant=a",
			// Deliberate profile relaxation: `http` hosts stay accepted for
			// local development — the gate imposes no https-only narrowing.
			"http://localhost:8080/mcp",
		]) {
			expect(() => validateResourceIndicator(resource)).not.toThrow();
		}
	});

	it("rejects an identifier carrying a fragment", () => {
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp#frag"),
		).toThrow(TypeError);
	});

	it("rejects an identifier carrying a bare empty fragment", () => {
		// `#` alone is still a fragment delimiter, and `new URL(...).hash` is
		// the empty string for it — exactly the case a `hash`-based check
		// would wave through.
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp#"),
		).toThrow(TypeError);
	});

	it("cites the RFC in the message", () => {
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp#frag"),
		).toThrow(/must not contain a fragment component \(RFC 8707 §2\)/u);
	});

	it("does not echo the rejected fragment or a credential-shaped query", () => {
		// The fragment value is deliberately not a substring of the word
		// "fragment" in the message itself.
		const resource = "https://api.example.com/mcp?token=secret#anchorvalue";
		expect(() => validateResourceIndicator(resource)).toThrow(
			"https://api.example.com/mcp",
		);
		expect(() => validateResourceIndicator(resource)).not.toThrow("secret");
		expect(() => validateResourceIndicator(resource)).not.toThrow(
			"anchorvalue",
		);
	});

	it("does not echo userinfo embedded in the authority", () => {
		// The positive half is load-bearing: `not.toThrow(substring)` also
		// passes when the callback throws nothing at all, so on its own it
		// would go green with the gate deleted.
		expect(() =>
			validateResourceIndicator("https://svc:s3cr3t@api.example.com/mcp#f"),
		).toThrow("https://api.example.com/mcp");
		expect(() =>
			validateResourceIndicator("https://svc:s3cr3t@api.example.com/mcp#f"),
		).not.toThrow("s3cr3t");
	});

	it("does not echo userinfo on the fallback path either", () => {
		// The two shapes with no `origin` to redact through: `new URL` throws
		// on the scheme-relative one, and the other parses to the literal
		// `"null"` origin. Both land in `redactResourceIdentifier`'s
		// hand-rolled strip, which is the only place the redaction is not
		// delegated to the platform.
		for (const resource of [
			"//svc:s3cr3t@api.example.com/mcp#anchorvalue",
			"svc:s3cr3t@api.example.com#anchorvalue",
		]) {
			expect(() => validateResourceIndicator(resource)).toThrow(/RFC 8707 §2/u);
			expect(() => validateResourceIndicator(resource)).toThrow(
				"api.example.com",
			);
			expect(() => validateResourceIndicator(resource)).not.toThrow("s3cr3t");
		}
	});

	it("renders a blob: identifier once instead of doubling its origin", () => {
		// `blob:` has no authority of its own: `origin` comes from the inner
		// URL and `pathname` is that whole inner URL, so the parsed branch
		// would emit the authority twice and lift the inner `userinfo@` out of
		// the path.
		const resource = "blob:https://svc:s3cr3t@example.com/uuid#anchorvalue";
		expect(() => validateResourceIndicator(resource)).toThrow(
			"blob:https://example.com/uuid",
		);
		expect(() => validateResourceIndicator(resource)).not.toThrow("s3cr3t");
	});

	it("redacts userinfo in a scheme-relative authority", () => {
		// The redaction fallback's optional prefix is the authority marker, not
		// a scheme, precisely for this shape: `//user:pass@host/path` never
		// parses, so the parsed branch cannot do the stripping.
		expect(() =>
			validateResourceIndicator("//svc:s3cr3t@api.example.com/mcp"),
		).toThrow(TypeError);
		expect(() =>
			validateResourceIndicator("//svc:s3cr3t@api.example.com/mcp"),
		).not.toThrow("s3cr3t");
	});

	it("redacts an unparseable identifier without surfacing a parse failure", () => {
		// `redactResourceIdentifier`'s fallback: no valid URL to take an
		// `origin` from, so it truncates at the delimiter by hand and still
		// reports the RFC 8707 reason rather than urllib-style parse noise.
		expect(() => validateResourceIndicator("not a url#anchorvalue")).toThrow(
			/RFC 8707 §2/u,
		);
		expect(() =>
			validateResourceIndicator("not a url#anchorvalue"),
		).not.toThrow("anchorvalue");
	});

	it("redacts a non-special scheme, whose origin is the literal 'null'", () => {
		expect(() =>
			validateResourceIndicator("urn:example:api#anchorvalue"),
		).toThrow("urn:example:api");
		expect(() =>
			validateResourceIndicator("urn:example:api#anchorvalue"),
		).not.toThrow("null");
	});
});

describe("validateResourceIndicator query grammar (RFC 3986 §3.4)", () => {
	it("rejects a query byte outside the RFC 3986 §3.4 grammar", () => {
		// A raw `\` is a quoted-pair escape inside the `WWW-Authenticate`
		// quoted-string (RFC 9110 §11.2) — `sanitiseHeaderValue` would blank
		// it to a space, so the advertised document URL would no longer
		// round-trip to the configured identifier. Rejected at the same
		// boundary that rejects `#`.
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp?path=a\\b"),
		).toThrow(TypeError);
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp?path=a\\b"),
		).toThrow(/RFC 3986 §3\.4/u);
	});

	it("rejects a malformed percent-escape", () => {
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp?p=%zz"),
		).toThrow(/RFC 3986 §3\.4/u);
	});

	it("rejects the out-of-grammar octets [ ] | ^ ` { } — including bracketed params", () => {
		// RFC 3986 §3.4 excludes these from `query`, and WHATWG normalisation
		// leaves them raw in `URL.search`, so before this gate they reached
		// the challenge verbatim. `filter[tenant]=a` is the shape that will
		// actually reach an operator: bracketed query params are a common REST
		// convention, and they now fail at startup — percent-encode the
		// brackets instead.
		for (const query of [
			"filter[tenant]=a",
			"a=b|c",
			"a=b^c",
			"a=b`c",
			"a={b}",
		]) {
			expect(() =>
				validateResourceIndicator(`https://api.example.com/mcp?${query}`),
			).toThrow(/RFC 3986 §3\.4/u);
		}
	});

	it("rejects a raw space, quote or angle bracket even though WHATWG would encode them away", () => {
		// Deliberate flip from round 2 of review: these were previously pinned
		// as *accepted*, because the gate ran on the WHATWG-normalised
		// `URL.search`, which percent-encodes a space to `%20` (and `"` `<`
		// `>` similarly) before the check ever saw it. The resource identifier
		// is an identity compared byte-for-byte, so accepting `?a=b c` while
		// serving `?a=b c` in the PRM document and advertising `?a=b%20c` in
		// the challenge was the SDK silently deciding the operator meant a
		// different identifier than the one they typed. The gate now judges
		// the raw configured query, so these fail at construction instead.
		for (const resource of [
			"https://api.example.com/mcp?a=b c",
			'https://api.example.com/mcp?a=b"c',
			"https://api.example.com/mcp?a=b<c",
		]) {
			expect(() => validateResourceIndicator(resource)).toThrow(
				/RFC 3986 §3\.4/u,
			);
		}
	});

	it("gates the raw query of a non-special-scheme identifier", () => {
		// The gate runs on the raw configured string, so a scheme WHATWG does
		// not treat as special has its query judged the same way `https` does
		// — the fragment check already worked this way.
		expect(() =>
			validateResourceIndicator("mcp://api.example.com/mcp?a=b c"),
		).toThrow(/RFC 3986 §3\.4/u);
	});

	it("names the offending codepoint and its offset in the query", () => {
		// One byte of the query leaks — never the value. The offset is within
		// the query (0 = the first byte after `?`), so the startup failure is
		// a one-line fix instead of a guessing game.
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp?path=a\\b"),
		).toThrow('invalid character "\\\\" at offset 6');
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp?p=%zz"),
		).toThrow('malformed percent-escape "%zz" at offset 2');
	});

	it("does not echo the offending query in the message", () => {
		// The positive assertion keeps this from passing vacuously: the same
		// input must actually throw (with the citation) for the negative
		// substring check on the throw to mean anything.
		const resource = "https://api.example.com/mcp?token=s3cr3t\\x";
		expect(() => validateResourceIndicator(resource)).toThrow(
			/RFC 3986 §3\.4/u,
		);
		expect(() => validateResourceIndicator(resource)).not.toThrow("s3cr3t");
	});

	it("accepts a legal query carrying every sub-delim unchanged", () => {
		expect(() =>
			validateResourceIndicator(
				"https://api.example.com/mcp?a=b&c=(d)!$*+,;=:@/?x",
			),
		).not.toThrow();
	});

	it("gates AuthplaneResource construction", () => {
		expect(() =>
			buildResource("https://api.example.com/mcp?path=a\\b"),
		).toThrow(/RFC 3986 §3\.4/u);
	});
});

describe("validateResourceIndicator absolute-URL requirement (RFC 8707 §2)", () => {
	it("rejects a relative identifier", () => {
		expect(() => validateResourceIndicator("/mcp")).toThrow(TypeError);
		expect(() => validateResourceIndicator("/mcp")).toThrow(
			/must be an absolute URL with a scheme and a host \(RFC 8707 §2\)/u,
		);
	});

	it("rejects a scheme-relative identifier", () => {
		// `//api.example.com/mcp` parses with an authority but has no scheme
		// (RFC 3986 §4.3: absolute-URI = scheme ":" hier-part [ "?" query ]).
		// A guard phrased as "opaque or authority-less" would wrongly admit it.
		expect(() => validateResourceIndicator("//api.example.com/mcp")).toThrow(
			TypeError,
		);
		expect(() => validateResourceIndicator("//api.example.com/mcp")).toThrow(
			/must be an absolute URL with a scheme and a host/u,
		);
	});

	it("rejects an opaque identifier with a scheme but no host", () => {
		// Previously accepted as an "opaque audience string"; it derived the
		// garbage document URL
		// `null/.well-known/oauth-protected-resourceexample:api`. The host is
		// what RFC 9728 §3 inserts the well-known suffix after — no host, no
		// derivable metadata URL.
		expect(() => validateResourceIndicator("urn:example:api")).toThrow(
			TypeError,
		);
		expect(() => validateResourceIndicator("urn:example:api")).toThrow(
			/must be an absolute URL with a scheme and a host/u,
		);
	});

	it("rejects an authority-less absolute URI that WHATWG parses with a host", () => {
		// RFC 3986 `hier-part = path-rootless`: these carry no authority at
		// all. WHATWG invents one for a special scheme — `new URL` reports
		// `host === "example.com"` for the first — so a host read off the
		// parse would admit them, and the served `resource` member would be a
		// string no conformant client can insert the well-known suffix into
		// (RFC 9728 §3.3). The last one is the backslash spelling WHATWG
		// rewrites to forward slashes.
		for (const resource of [
			"https:example.com/mcp",
			"https:/example.com/mcp",
			"http:localhost:8080/mcp",
			"https:\\\\api.example.com\\mcp",
		]) {
			expect(() => validateResourceIndicator(resource)).toThrow(TypeError);
			expect(() => validateResourceIndicator(resource)).toThrow(
				/must be an absolute URL with a scheme and a host/u,
			);
		}
	});

	it("accepts an http host — deliberate relaxation for local development", () => {
		expect(() =>
			validateResourceIndicator("http://localhost:8080/mcp"),
		).not.toThrow();
	});

	it("accepts a non-special scheme with a host", () => {
		// The gate is scheme + host, not WHATWG-special-scheme: an identifier
		// like `mcp://api.example.com/mcp` satisfies RFC 8707 §2's absolute-URI
		// grammar and has the host RFC 9728 §3 inserts the suffix after. Its
		// WHATWG `origin` is the literal "null", which is why every derivation
		// builds from `protocol` + `host` instead.
		expect(() =>
			validateResourceIndicator("mcp://api.example.com/mcp"),
		).not.toThrow();
	});

	it("redacts userinfo in a non-special scheme to protocol + host", () => {
		// `URL.origin` is "null" here, so an origin-keyed redaction would fall
		// through; the host-keyed branch still strips the credential.
		expect(() =>
			validateResourceIndicator("mcp://svc:s3cr3t@api.example.com/mcp#f"),
		).toThrow("mcp://api.example.com/mcp");
		expect(() =>
			validateResourceIndicator("mcp://svc:s3cr3t@api.example.com/mcp#f"),
		).not.toThrow("s3cr3t");
	});

	it("does not echo a credential from a missing-colon or scheme-only typo", () => {
		// Neither shape parses with a usable authority, so both reach the raw
		// fallback — which must not require the `//` a well-formed authority
		// would carry before stripping through the `@`.
		for (const resource of [
			"https//svc:s3cr3t@api.example.com/mcp",
			"svc:s3cr3t@api.example.com/mcp",
		]) {
			expect(() => validateResourceIndicator(resource)).toThrow(TypeError);
			expect(() => validateResourceIndicator(resource)).not.toThrow("s3cr3t");
		}
	});

	it("reports the fragment first when an identifier is wrong in both ways", () => {
		// Ordering pin: the fragment check runs ahead of the absolute-URL
		// check, so a relative identifier carrying a fragment deterministically
		// reports the fragment. Without this, reordering the checks would
		// silently change which error a doubly-wrong config reports.
		expect(() => validateResourceIndicator("/mcp#frag")).toThrow(
			/must not contain a fragment component/u,
		);
		expect(() => validateResourceIndicator("//api.example.com/mcp#frag")).toThrow(
			/must not contain a fragment component/u,
		);
	});
});

describe("AuthplaneResource construction (RFC 8707 §2)", () => {
	it("rejects a fragment-bearing resource at construction", () => {
		expect(() => buildResource("https://api.example.com/mcp#frag")).toThrow(
			TypeError,
		);
		expect(() => buildResource("https://api.example.com/mcp#frag")).toThrow(
			/RFC 8707 §2/u,
		);
	});

	it("rejects a non-absolute resource at construction", () => {
		for (const resource of [
			"/mcp",
			"//api.example.com/mcp",
			"urn:example:api",
			// Authority-less, but WHATWG parses it with a host — the gate reads
			// the `//` off the raw string, so construction rejects it too.
			"https:example.com/mcp",
			"https:/example.com/mcp",
			"http:localhost:8080/mcp",
			"https:\\\\api.example.com\\mcp",
		]) {
			expect(() => buildResource(resource)).toThrow(TypeError);
			expect(() => buildResource(resource)).toThrow(
				/must be an absolute URL with a scheme and a host/u,
			);
		}
	});

	it("constructs normally for an http host", () => {
		const resource = buildResource("http://localhost:8080/mcp");
		expect(resource.prmDocumentUrl()).toBe(
			"http://localhost:8080/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("rejects before any other constructor validation runs", () => {
		// Ordering pin: the indicator gate is first, so an operator who got
		// both wrong is told about the identifier rather than about the
		// algorithm list. Without this, moving the gate below the
		// dangerous-algorithm check would silently change which error a
		// fragment-bearing config reports.
		expect(() =>
			new AuthplaneResource({
				resource: "https://api.example.com/mcp#frag",
				scopes: ["read"],
				allowedAlgorithms: ["HS256"],
				issuer: "https://auth.example.com",
				metadataCache: {},
				fetchSettings: {},
				getJwksCache: () => ({}),
			} as unknown as ConstructorParameters<typeof AuthplaneResource>[0]),
		).toThrow(/RFC 8707 §2/u);
	});

	it("leaves a fragment-free resource unaffected", () => {
		const resource = buildResource("https://api.example.com/mcp");
		expect(resource.prmResponse().resource).toBe("https://api.example.com/mcp");
		expect(resource.prmDocumentUrl()).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("leaves a query-bearing resource unaffected and preserves the query in derivation", () => {
		const resource = buildResource("https://api.example.com/mcp?tenant=a");
		expect(resource.prmResponse().resource).toBe(
			"https://api.example.com/mcp?tenant=a",
		);
		expect(resource.prmDocumentUrl()).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
		);
	});

	it("constructs with a non-special scheme and derives its document URL from protocol + host", () => {
		// End-to-end pin for the accepted set: the gate admits any scheme with
		// a host, and the derivation must not leak WHATWG's literal "null"
		// origin into the advertised URL.
		const resource = buildResource("mcp://api.example.com/mcp");
		expect(resource.prmResponse().resource).toBe("mcp://api.example.com/mcp");
		expect(resource.prmDocumentUrl()).toBe(
			"mcp://api.example.com/.well-known/oauth-protected-resource/mcp",
		);
	});
});

describe("PRM URL derivation rejects a fragment-bearing resource", () => {
	it("oauthProtectedResourceMetadataDocumentUrl throws instead of dropping it", () => {
		// Before the gate, `origin` + `pathname` silently produced the
		// no-fragment URL, so the served document's `resource` member and the
		// URL it was served at disagreed — which RFC 9728 §3.3 tells the
		// client to discard, with no server-side signal.
		expect(() =>
			oauthProtectedResourceMetadataDocumentUrl(
				"https://api.example.com/mcp#frag",
			),
		).toThrow(TypeError);
	});

	it("oauthProtectedResourceMetadataPath throws instead of dropping it", () => {
		expect(() =>
			oauthProtectedResourceMetadataPath("https://api.example.com/mcp#frag"),
		).toThrow(TypeError);
	});

	it("still derives fragment-free identifiers unchanged", () => {
		expect(
			oauthProtectedResourceMetadataDocumentUrl("https://api.example.com/mcp/"),
		).toBe("https://api.example.com/.well-known/oauth-protected-resource/mcp");
		expect(oauthProtectedResourceMetadataPath("https://api.example.com/mcp")).toBe(
			"/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("echoes the raw identifier when WHATWG would invent the authority", () => {
		// The gate rejects on the raw string; the message has to describe the raw
		// string too. For these four shapes WHATWG supplies the authority the gate
		// exists to deny, so echoing the parse showed the operator a string that is
		// an absolute URL with a scheme and a host — and that the gate accepts —
		// with the missing `//` removed on the way out.
		// The echo is quoted, so a backslash in the identifier reaches the
		// message as the `\\` escape `JSON.stringify` writes it as — the raw
		// byte is still what the operator configured, one escape away.
		for (const resource of [
			"https:example.com/mcp",
			"https:/example.com/mcp",
			"http:localhost:8080/mcp",
		]) {
			expect(() => validateResourceIndicator(resource)).toThrow(resource);
		}
		expect(() =>
			validateResourceIndicator("https:\\api.example.com\\mcp"),
		).toThrow("https:\\\\api.example.com\\\\mcp");
	});

	it("does not echo userinfo carried behind a single-slash scheme", () => {
		// The parsed branch used to mask this: routing the shape to the fallback
		// exposes that `^([^/?#]*\/\/)?[^/?#]*@` cannot cross the single `/`, so
		// the prefix alternative has to admit `scheme:/` as well.
		const resource = "https:/svc:s3cr3t@example.com/mcp";
		expect(() => validateResourceIndicator(resource)).toThrow(/RFC 8707 §2/u);
		expect(() => validateResourceIndicator(resource)).not.toThrow("s3cr3t");
	});

	it("does not let the scheme alternative swallow a username", () => {
		// `:\/` rather than `:\/*`: with `*`, `svc:pw@host` matches the scheme
		// alternative and the username survives as a `svc:` prefix — the leak the
		// superseded regex had.
		expect(() =>
			validateResourceIndicator("svc:s3cr3t@api.example.com"),
		).not.toThrow("s3cr3t");
		expect(() =>
			validateResourceIndicator("svc:s3cr3t@api.example.com"),
		).not.toThrow("svc:");
	});
});

describe("validateResourceIndicator userinfo requirement (RFC 9110 §4.2.4)", () => {
	it("rejects an identifier carrying userinfo", () => {
		const resource = "https://svc:s3cr3t@api.example.com/mcp";
		expect(() => validateResourceIndicator(resource)).toThrow(TypeError);
		expect(() => validateResourceIndicator(resource)).toThrow(
			/must not include a userinfo component/u,
		);
	});

	it("rejects a username-only userinfo", () => {
		expect(() =>
			validateResourceIndicator("https://svc@api.example.com/mcp"),
		).toThrow(/must not include a userinfo component/u);
	});

	it("rejects an empty userinfo, which is still a userinfo component", () => {
		expect(() =>
			validateResourceIndicator("https://@api.example.com/mcp"),
		).toThrow(/must not include a userinfo component/u);
	});

	it("cites the RFC in the message", () => {
		expect(() =>
			validateResourceIndicator("https://svc:s3cr3t@api.example.com/mcp"),
		).toThrow(/RFC 9110 §4\.2\.4/u);
	});

	it("does not echo the credential it rejects", () => {
		const resource = "https://svc:s3cr3t@api.example.com/mcp";
		expect(() => validateResourceIndicator(resource)).not.toThrow("s3cr3t");
		expect(() => validateResourceIndicator(resource)).not.toThrow("svc");
	});

	it("accepts a host carrying a port and an IPv6 literal", () => {
		expect(() =>
			validateResourceIndicator("https://api.example.com:8443/mcp"),
		).not.toThrow();
		expect(() =>
			validateResourceIndicator("https://[::1]:8443/mcp"),
		).not.toThrow();
	});

	it("does not mistake an @ in the path or the query for userinfo", () => {
		expect(() =>
			validateResourceIndicator("https://api.example.com/@handle"),
		).not.toThrow();
		expect(() =>
			validateResourceIndicator("https://api.example.com/mcp?to=a@b"),
		).not.toThrow();
	});

	it("gates the authority of a non-special scheme too", () => {
		expect(() =>
			validateResourceIndicator("mcp://svc:s3cr3t@api.example.com/mcp"),
		).toThrow(/must not include a userinfo component/u);
	});

	it("reports the fragment and the missing scheme ahead of the userinfo", () => {
		// Checked last of the four, so an identifier wrong in more than one way
		// reports the defect an operator fixes first.
		expect(() =>
			validateResourceIndicator("https://svc:s3cr3t@api.example.com/mcp#f"),
		).toThrow(/must not contain a fragment component/u);
		expect(() =>
			validateResourceIndicator("//svc:s3cr3t@api.example.com/mcp"),
		).toThrow(/must be an absolute URL with a scheme and a host/u);
	});

	it("gates AuthplaneResource construction", () => {
		expect(() =>
			buildResource("https://svc:s3cr3t@api.example.com/mcp"),
		).toThrow(/must not include a userinfo component/u);
	});
});

describe("the PRM document and its derived URL cannot disagree", () => {
	it("refuses an identifier whose derived URL would drop part of the resource member", () => {
		// `buildPrm` copies the identifier into `doc.resource`; every derivation
		// builds the document URL from scheme + host + path, which drops userinfo.
		// Admitting this shape would serve a document whose `resource` names a
		// different string than the URL it was fetched from — the RFC 9728 §3.3
		// mismatch a conformant client answers by discarding the document, leaving
		// the resource server looking unreachable rather than misconfigured.
		const resource = "https://svc:s3cr3t@api.example.com/mcp";
		expect(() =>
			buildPrm("https://auth.example.com", resource, ["read"]),
		).toThrow(/must not include a userinfo component/u);
		expect(() =>
			oauthProtectedResourceMetadataDocumentUrl(resource),
		).toThrow(/must not include a userinfo component/u);
		expect(() => oauthProtectedResourceMetadataPath(resource)).toThrow(
			/must not include a userinfo component/u,
		);
	});

	it("keeps the resource member reconcilable with the derived URL for every accepted shape", () => {
		for (const resource of [
			"https://api.example.com/mcp",
			"https://api.example.com/mcp?tenant=a",
			"http://localhost:8080/mcp",
			"mcp://api.example.com/mcp",
			"https://[::1]:8443/mcp",
		]) {
			const doc = buildPrm("https://auth.example.com", resource, ["read"]);
			expect(doc.resource).toBe(resource);
			const parsed = new URL(resource);
			// The document URL is built from the same scheme and authority the
			// `resource` member names, so a client can reconcile the two.
			expect(
				oauthProtectedResourceMetadataDocumentUrl(resource).startsWith(
					`${parsed.protocol}//${parsed.host}/`,
				),
			).toBe(true);
		}
	});
});
