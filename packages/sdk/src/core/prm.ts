import { ALLOWED_ALGORITHMS } from "./constants.js";

export interface ProtectedResourceMetadata {
	resource: string;
	authorization_servers: string[];
	bearer_methods_supported: string[];
	resource_signing_alg_values_supported: string[];
	scopes_supported: string[];
	dpop_signing_alg_values_supported?: string[];
	dpop_bound_access_tokens_required?: boolean;
}

export interface BuildPrmOptions {
	/**
	 * DPoP signing algorithms supported by this resource (RFC 9728 §2).
	 * When provided, `dpop_signing_alg_values_supported` is included in the output.
	 */
	dpopSigningAlgValuesSupported?: readonly string[];
	/**
	 * Whether DPoP-bound access tokens are always required
	 * (RFC 9728 §2 `dpop_bound_access_tokens_required`). Only included when
	 * `dpopSigningAlgValuesSupported` is provided.
	 */
	dpopBoundAccessTokensRequired?: boolean;
}

/**
 * Build OAuth Protected Resource Metadata (RFC 9728).
 *
 * This is typically served by resource servers (including MCP servers) so clients can discover:
 * - which authorization server(s) to use
 * - which signing algorithms are accepted
 * - which scopes the resource understands
 *
 * Both URL-shaped members are gated before they are copied into the document:
 * `resource` by `validateResourceIndicator` — the same check
 * `AuthplaneResource`'s constructor applies — and `issuer` by
 * `validateIssuerIdentifier`, which is the same gate `AuthplaneClient.create()`
 * runs when it derives the AS metadata URL.
 * This builder is exported and its documented use is to serve the document
 * directly, so it is a boundary in its own right: RFC 9728 §3.3 has a client
 * discard a document whose `resource` member is not the identifier it used to
 * reach the resource server, and every derivation in this module builds the
 * document URL from scheme + host + path, so an identifier carrying a
 * component that derivation drops would be served as a `resource` value no
 * client can reconcile with the URL it fetched. The resource server then looks
 * unreachable rather than misconfigured. Rejecting here turns that silent
 * interop failure into an error the operator can act on.
 *
 * Usage:
 *
 * ```ts
 * import { buildPrm } from "@authplane/sdk/core";
 *
 * const prm = buildPrm(
 *   "https://auth.example.com",
 *   "https://api.example.com",
 *   ["read", "write"],
 *   { dpopSigningAlgValuesSupported: ["ES256", "RS256"] },
 * );
 *
 * // return as JSON from your /.well-known/oauth-protected-resource endpoint
 * ```
 *
 * @throws TypeError when `issuer` is not a valid issuer identifier, or
 * `resource` is not a valid resource identifier.
 */
export function buildPrm(
	issuer: string,
	resource: string,
	scopes: readonly string[],
	options: BuildPrmOptions = {},
): ProtectedResourceMetadata {
	validateIssuerIdentifier(issuer);
	validateResourceIndicator(resource);
	const doc: ProtectedResourceMetadata = {
		resource,
		authorization_servers: [issuer],
		bearer_methods_supported: ["header"],
		resource_signing_alg_values_supported: [...ALLOWED_ALGORITHMS],
		scopes_supported: [...scopes],
	};
	if (options.dpopSigningAlgValuesSupported !== undefined) {
		doc.dpop_signing_alg_values_supported = [
			...options.dpopSigningAlgValuesSupported,
		];
		doc.dpop_bound_access_tokens_required =
			options.dpopBoundAccessTokensRequired ?? false;
	}
	return doc;
}

/**
 * RFC 3986 §3.1 scheme grammar followed by the authority's `//`, anchored.
 *
 * Shared by the gate and the redactor deliberately: the gate rejects on the raw
 * string, so the message has to describe the raw string too, and both need the
 * same notion of "carries an authority".
 */
const SCHEME_AND_AUTHORITY = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u;

/**
 * Render an identifier for an error message without echoing anything
 * credential-shaped. Shared by the resource and issuer gates: both reject on
 * the raw string, so both can be handed one carrying a credential, and the
 * shapes worth masking are the same either way.
 *
 * `URL.host` drops any `userinfo@` embedded in the
 * authority and `URL.pathname` excludes both the query and the fragment, so
 * neither a `?token=…` nor the rejected fragment itself reaches a startup log.
 *
 * Parses defensively: every caller is already on an error path handling a
 * malformed identifier, so letting `new URL` throw here would replace the RFC
 * citation the caller wrote with the platform's parse failure. The fallback
 * truncates at the first `?`/`#` and strips the first `userinfo@` by hand. The
 * parsed branch reads `protocol` and `host` rather than `origin`: `origin` is
 * the literal string `"null"` for a non-special scheme, and for `blob:` it is
 * borrowed from the inner URL while `pathname` is that whole inner URL, so
 * `origin + pathname` would print the authority twice and lift the inner
 * `userinfo@` back out of the path. An empty `host` is what sends both of those
 * to the fallback. The fallback's optional prefix is the authority marker, not
 * a scheme, so a scheme-relative `//user:pass@host/path` — unparseable, and
 * rejected by the absolute-URL gate — is stripped too.
 *
 * The parsed branch is taken only when the raw string carries `scheme://`. For
 * `https:example.com/mcp` and its three siblings WHATWG invents the authority
 * the gate exists to deny, so echoing the parse would show the operator a
 * string that is an absolute URL with a scheme and a host — and that the gate
 * accepts — with the missing `//`, the one actionable detail, removed on the
 * way out.
 *
 * The result is quoted and escaped through {@link quoteForMessage} on its way
 * out, once here rather than at each of the gates' throw sites. Both branches
 * can hand back a string carrying the bytes the whitespace axis rejects — the
 * fallback returns the raw prefix whenever the anchored `SCHEME_AND_AUTHORITY`
 * test fails, which is exactly what a leading control character causes — so
 * quoting at the call sites would mean getting it right at every one of them,
 * and every one added later. Callers therefore interpolate the result bare;
 * they must not wrap it in quotes of their own.
 */
function redactIdentifier(identifier: string): string {
	let redacted: string | undefined;
	try {
		const parsed = new URL(identifier);
		if (parsed.host !== "" && SCHEME_AND_AUTHORITY.test(identifier)) {
			redacted = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
		}
	} catch {
		// Unparseable — fall through to the raw truncation below.
	}
	if (redacted === undefined) {
		const beforeDelimiter = identifier.split(/[?#]/u)[0] ?? "";
		// Deliberately not anchored on a `scheme://` prefix. The shapes that reach
		// this branch carry no such prefix — `//svc:pw@api.example.com/mcp`
		// (scheme-relative, throws), `svc:pw@api.example.com` (no `//`), and now
		// `https:/svc:pw@example.com/mcp` (single slash, which the parsed branch no
		// longer masks) — so an anchored strip matches none of them and the
		// credential survives into the message. The second alternative is `:\/`
		// rather than `:\/*` on purpose: with `*`, `svc:pw@host` matches the scheme
		// alternative and the username survives as a `svc:` prefix. Stopping at the
		// first `@` inside the authority rather than the last one in the string
		// keeps a legitimate `@` in a path out of it.
		redacted = beforeDelimiter.replace(
			/^([^/?#]*\/\/|[A-Za-z][A-Za-z0-9+.-]*:\/)?[^/?#]*@/u,
			"$1",
		);
	}
	return quoteForMessage(redacted);
}

/**
 * Every codepoint {@link isWhitespaceOrControl} rejects, rendered as an escape
 * inside a quoted string.
 *
 * `JSON.stringify` alone does not cover the class: it escapes the C0 controls
 * but emits DEL, the C1 controls and the non-ASCII spaces (U+00A0, U+2028,
 * U+3000, U+FEFF and the rest) raw, so the two ranges beyond C0 would reach a
 * startup log as the invisible bytes they are. A raw space is deliberately left
 * as itself: the surrounding quotes already make it legible.
 */
function quoteForMessage(value: string): string {
	return JSON.stringify(value).replace(/[\u007f-\u009f]|\s/gu, (char) =>
		char === " "
			? char
			: `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
	);
}

/**
 * True for a character that is whitespace or a control, treated as one class.
 *
 * Three ranges, deliberately: the C0 controls and space (U+0000–U+0020), which
 * are the ones the WHATWG parser trims and strips; DEL and the C1 controls
 * (U+007F–U+009F), which it does not strip but silently percent-encodes; and
 * everything the Unicode `\s` class adds on top (U+00A0, U+1680, U+2000–U+200A,
 * U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF), which is likewise
 * percent-encoded. None of them is a URI character: RFC 3986 §2 builds every
 * component out of `unreserved`, `reserved` and `pct-encoded`, all of which are
 * printable ASCII, so no identifier that carries one is a URI in the first
 * place.
 *
 * Spelled as codepoint comparisons rather than a character class so the control
 * ranges are readable, since a regex literal would have to carry the escapes
 * themselves. `charCodeAt` rather than `codePointAt` so there is no `undefined`
 * to defend against: every codepoint named above is in the BMP, and the empty
 * string this is never called with yields `NaN`, which fails both comparisons.
 */
function isWhitespaceOrControl(char: string): boolean {
	const code = char.charCodeAt(0);
	return code <= 0x20 || (code >= 0x7f && code <= 0x9f) || /^\s$/u.test(char);
}

/**
 * Scan the raw identifier for the first whitespace or control character.
 * Returns a phrase naming the offending codepoint and its offset within the
 * identifier, or `undefined` when there is none.
 *
 * Same shape and the same reasoning as {@link findQueryGrammarOffence}: the
 * offending codepoint and where it sits is what turns an otherwise unactionable
 * startup failure into a one-line fix, while nothing else about the value
 * leaks. It matters more here than there, because the characters this rejects
 * are by definition the ones nothing renders — a tab, a CR or a stray NUL is
 * invisible in a message that merely quotes the string it came from. So is the
 * redacted echo the caller appends whenever the offending character leads the
 * identifier, which is why {@link redactIdentifier} quotes what it returns.
 */
function findWhitespaceOrControlOffence(
	identifier: string,
): string | undefined {
	for (let index = 0; index < identifier.length; index += 1) {
		const char = identifier.charAt(index);
		if (isWhitespaceOrControl(char)) {
			return `invalid character ${quoteForMessage(char)} at offset ${String(index)}`;
		}
	}
	return undefined;
}

/**
 * RFC 3986 §3.4 `query` production, one character at a time:
 * `query = *( pchar / "/" / "?" )`, where
 * `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`. Spelled out:
 * `A-Za-z0-9 -._~ ! $ & ' ( ) * + , ; = : @ / ?` plus well-formed `%XX`
 * escapes (checked separately below). Everything else is out of grammar —
 * notably `[`, `]`, `|`, `^`, `\`, `` ` ``, `{`, `}`, and a raw space, `"`,
 * `<` or `>`.
 */
const RFC3986_QUERY_CHAR = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?]$/u;

const WELL_FORMED_PCT_ESCAPE = /^%[0-9A-Fa-f]{2}$/u;

/**
 * Scan `query` (leading `?` already removed) for the first octet outside the
 * RFC 3986 §3.4 `query` grammar. Returns a phrase naming the offending
 * codepoint (or malformed escape) and its offset within the query, or
 * `undefined` when the query is in-grammar. Reporting the single offending
 * byte and where it sits turns an otherwise unactionable startup failure into
 * a one-line fix, while the query's value stays out of the log.
 */
function findQueryGrammarOffence(query: string): string | undefined {
	for (let index = 0; index < query.length; index += 1) {
		const char = query.charAt(index);
		if (char === "%") {
			const pctEscape = query.slice(index, index + 3);
			if (!WELL_FORMED_PCT_ESCAPE.test(pctEscape)) {
				return `malformed percent-escape ${JSON.stringify(pctEscape)} at offset ${String(index)}`;
			}
			index += 2;
		} else if (!RFC3986_QUERY_CHAR.test(char)) {
			return `invalid character ${JSON.stringify(char)} at offset ${String(index)}`;
		}
	}
	return undefined;
}

/**
 * True when the identifier's authority carries a userinfo component. Shared by
 * the resource and issuer gates — the authority grammar it reads is the same
 * for both.
 *
 * Read off the raw string like the sibling gates, not off a parsed `URL`: the
 * authority is everything between the `//` that opens it and the first `/`,
 * `?` or `#` that closes it, and an unescaped `@` delimits userinfo there and
 * appears nowhere else in an authority (RFC 3986 §3.2). So a host with a port
 * (`https://api.example.com:8443/mcp`) and an IPv6 literal
 * (`https://[::1]:8443/mcp`) both pass, an `@` in the path
 * (`https://api.example.com/@handle`) is not mistaken for one, and an
 * identifier with no authority at all (`urn:example:api`) is not this gate's
 * business. An empty userinfo (`https://@api.example.com/mcp`) is still a
 * userinfo component and is reported.
 */
function hasUserinfoComponent(identifier: string): boolean {
	const schemeAndAuthority = SCHEME_AND_AUTHORITY.exec(identifier);
	if (schemeAndAuthority === null) {
		return false;
	}
	const authorityStart = schemeAndAuthority[0].length;
	let authorityEnd = identifier.length;
	for (let index = authorityStart; index < identifier.length; index += 1) {
		const char = identifier.charAt(index);
		if (char === "/" || char === "?" || char === "#") {
			authorityEnd = index;
			break;
		}
	}
	return identifier.lastIndexOf("@", authorityEnd - 1) >= authorityStart;
}

/**
 * Reject a resource indicator that carries a URI fragment, is not an absolute
 * URL with a scheme and a host, or carries a query that is not a valid
 * RFC 3986 §3.4 `query` production.
 *
 * Fragment — RFC 8707 §2: "The URI MUST NOT include a fragment component."
 * RFC 9728 §1.2 says the same of the resource identifier — "a URL that uses
 * the https scheme and has no fragment component".
 *
 * The fragment check is on the raw string, not on a parsed `URL`: `URL` splits
 * the fragment off into `hash`, and every derivation in this module is built
 * from scheme + host + `pathname` (+ `search`), so a fragment is silently dropped
 * rather than rejected. What that produces is a PRM document whose `resource`
 * member carries a fragment while the document is served at the URL derived
 * without one — and RFC 9728 §3.3 requires a client that sees that mismatch to
 * discard the document. Rejecting at construction turns a silent interop
 * failure into a startup error the operator can act on. It also runs first, so
 * an identifier that is wrong in both ways deterministically reports the
 * fragment.
 *
 * Absolute URL — the scheme requirement is RFC 8707 §2: the resource parameter
 * "MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]", whose
 * grammar is `absolute-URI = scheme ":" hier-part [ "?" query ]`. The host
 * requirement is RFC 9728 §3: the well-known suffix is inserted after the host
 * component — no host, no derivable metadata URL. Both halves are checked
 * explicitly on the raw string rather than inferred from parseability. The
 * scheme, because a scheme-relative `//api.example.com/mcp` carries an
 * authority, and a guard phrased as "opaque or authority-less" would wrongly
 * admit it. The authority's `//`, for the mirror-image reason: WHATWG invents
 * an authority for a special scheme, so `new URL("https:example.com/mcp").host`
 * is `"example.com"` for an identifier RFC 3986 gives no authority at all
 * (`hier-part = path-rootless`). Reading the host off the parse would admit an
 * identifier this gate's own message says it rejects — and one whose served
 * `resource` member no conformant RFC 3986 client can turn back into the
 * advertised document URL, since there is no authority to insert the
 * well-known suffix after, so RFC 9728 §3.3 has it discard the document. That
 * is the same silent-interop failure the fragment rationale above describes,
 * reached from the other side. This gate used
 * to be fragment-only, on the argument that an opaque audience string worked
 * for `AuthplaneResource.verify()`; that position no longer holds — an opaque
 * value like `urn:example:api` (scheme but no host) previously derived the
 * garbage document URL `null/.well-known/oauth-protected-resourceexample:api`,
 * and RFC 9728 §3 has no way to derive a metadata URL from an identifier with
 * no host.
 *
 * Query — gated on the RAW query: the substring of the configured string
 * after the first `?` (a fragment is rejected above, so the query runs to the
 * end of the string). The resource identifier is an identity, compared
 * byte-for-byte, so the gate judges the bytes the operator configured — not
 * the WHATWG-normalised `URL.search`, which percent-encodes a space, `"`, `<`
 * or `>` on the way through `new URL` and would have the SDK silently decide
 * the operator meant a different identifier than the one they typed. Rejected:
 * any query octet outside `pchar / "/" / "?"` — notably `[`, `]`, `|`, `^`,
 * `\`, `` ` ``, `{`, `}`, and a raw space, `"`, `<` or `>` — and malformed
 * `%` escapes. The grammar admits every sub-delim, so a legal query passes
 * byte-for-byte, and the derivations below splice the same raw query, so the
 * configured, served and advertised identifiers stay the same bytes. It runs
 * after the absolute-URL gate, so the ordering is deterministic: fragment,
 * then absoluteness, then query.
 *
 * The grammar matters here because the query is carried, as configured, into
 * the quoted-string `resource_metadata` parameter of the `WWW-Authenticate`
 * challenge, where a `"` terminates the quoted-string and a `\` starts a
 * quoted-pair (RFC 9110 §11.2), and any other out-of-grammar byte makes the
 * advertised URL unparseable for a conformant client — the same
 * silent-wrong-derivation class the fragment gate exists to eliminate, so the
 * query is gated at the same boundary. That quoted-string argument is about
 * the query, which this module splices raw; the path half of the URL is not
 * gated here, because WHATWG normalisation percent-encodes the
 * quoted-string-terminating bytes out of `pathname` before any derivation
 * reads it.
 *
 * Userinfo — RFC 9110 §4.2.4 deprecates a userinfo component in an `http` or
 * `https` URI and directs a recipient to reject a URI carrying one, and RFC
 * 3986 §3.2.1 notes that it routinely holds a credential in clear text. The
 * stakes here are higher than for a request target that merely gets logged:
 * this identifier is stored verbatim, published as the `resource` member of
 * the Protected Resource Metadata document RFC 9728 §3 serves to
 * unauthenticated callers, and spliced into the `resource_metadata` parameter
 * of the 401 `WWW-Authenticate` challenge — so a credential in the userinfo
 * would be handed to every client that asks. Rejecting at construction is what
 * makes that guarantee: eliding the userinfo at each sink only covers the sinks
 * that remember to, and every sink added later has to remember again. It also
 * closes the second half of the mismatch this module exists to prevent —
 * every derivation builds the document URL from scheme + host + path, which
 * drops userinfo, so an accepted identifier carrying it would be served as a
 * `resource` value naming a different string than the URL it was fetched from,
 * the RFC 9728 §3.3 mismatch a conformant client answers by discarding the
 * document. Checked last of the four, so an identifier that is also
 * scheme-relative reports the missing scheme first.
 *
 * The `http` scheme remains accepted — a deliberate profile relaxation for
 * local development (`http://localhost:8080/mcp`); this gate imposes no
 * https-only narrowing.
 *
 * Throws `TypeError`, matching the sibling issuer guard in
 * `core/fetching/metadataUrl.ts` and the platform's own convention for an
 * argument of the wrong shape (`new URL("nope")` throws `TypeError` too). It is
 * deliberately *not* an `AuthplaneError`: that hierarchy is the
 * token-verification taxonomy consumed by `httpStatus()` and
 * `wwwAuthenticate()`, and a configuration error found at construction must not
 * be representable as a challenge on a request path.
 *
 * @throws TypeError when `resource` carries a fragment component, is not an
 * absolute URL with a scheme and a host, carries a query component that is not
 * a valid RFC 3986 §3.4 `query`, or carries a userinfo component in its
 * authority.
 */
export function validateResourceIndicator(resource: string): void {
	if (resource.includes("#")) {
		throw new TypeError(
			`resource indicator must not contain a fragment component (RFC 8707 §2): ${redactIdentifier(resource)}`,
		);
	}
	// RFC 3986 §3.1 scheme grammar followed by the authority's `//`, anchored:
	// rejects a relative `/mcp` and a scheme-relative `//api.example.com/mcp`
	// alike. The `//` is load-bearing on the RAW string and must not be
	// "simplified" back onto `parsed.host` — WHATWG invents an authority for a
	// special scheme (`http`, `https`, `ws`, `wss`, `ftp`, `file`), so
	// `https:example.com/mcp`, `https:/example.com/mcp` and
	// `https:\\api.example.com\mcp` all parse to a non-empty `host` they have
	// no authority to give (see the docstring above).
	const hasSchemeAndAuthority = SCHEME_AND_AUTHORITY.test(resource);
	let parsed: URL | undefined;
	if (hasSchemeAndAuthority) {
		try {
			parsed = new URL(resource);
		} catch {
			// Carries a scheme and an authority marker but does not parse —
			// rejected below.
		}
	}
	if (parsed === undefined || parsed.host === "") {
		throw new TypeError(
			`resource identifier must be an absolute URL with a scheme and a host (RFC 8707 §2): ${redactIdentifier(resource)}`,
		);
	}
	const queryStart = resource.indexOf("?");
	if (queryStart !== -1) {
		const offence = findQueryGrammarOffence(resource.slice(queryStart + 1));
		if (offence !== undefined) {
			throw new TypeError(
				`resource indicator query must be a valid RFC 3986 §3.4 query (pchar / "/" / "?" and well-formed %XX escapes) — ${offence}: ${redactIdentifier(resource)}`,
			);
		}
	}
	// Last of the four, so an identifier that is also scheme-relative or
	// fragment-bearing is reported for that instead — the defect an operator
	// fixes first.
	if (hasUserinfoComponent(resource)) {
		throw new TypeError(
			`resource identifier must not include a userinfo component in its authority (RFC 9110 §4.2.4): ${redactIdentifier(resource)}`,
		);
	}
}

/**
 * Report the first octet in `url` that cannot survive the quoted-string it is
 * advertised in: a double quote closes it, a backslash is a quoted-pair escape
 * a conforming client unescapes into a different URL (RFC 9110 §5.6.4), and
 * whitespace or a C0 control is not a URI character at all (RFC 3986 §2).
 *
 * Returns a description for the message, or `undefined` when the string is
 * clean.
 */
function findQuotedStringOffence(url: string): string | undefined {
	for (const char of url) {
		if (char === '"') {
			return "a literal double quote";
		}
		if (char === "\\") {
			return "a literal backslash";
		}
		const code = char.codePointAt(0) ?? 0;
		// Everything outside printable ASCII, not just the C0 range and DEL. RFC
		// 3986 §2 limits a URI to a fixed ASCII repertoire, and this value is
		// never re-derived — it is stored and advertised exactly as typed — so
		// nothing downstream percent-encodes it the way WHATWG normalisation does
		// for the resource identifier's path. A raw `ü` would otherwise be
		// advertised as a byte sequence that is not a URI, and Node rejects a
		// header value above U+00FF outright, turning the 401 into a 500. An IDN
		// host has to be given in punycode, which is what RFC 3986 requires.
		if (code <= 0x20 || code >= 0x7f) {
			return `the non-URI octet U+${code.toString(16).toUpperCase().padStart(4, "0")}`;
		}
		// The ASCII specials RFC 3986 excludes from every component. The query is
		// already held to its own grammar four lines down, so without these the
		// same octet was refused in `?q=a|b` and accepted in `/prm|x`.
		if ("<>`{}|^".includes(char)) {
			return `the non-URI character ${JSON.stringify(char)}`;
		}
	}
	return undefined;
}

/**
 * Reject a Protected Resource Metadata document URL that carries a fragment,
 * is not an absolute URL with a scheme and a host, carries a query that is not
 * a valid RFC 3986 §3.4 `query`, or carries a userinfo component in its
 * authority.
 *
 * This gates the *override* — the URL an operator configures when the metadata
 * document is not served by this resource server (see
 * `AuthplaneResourceOptions.resourceMetadataUrl`). The derived URL needs no
 * gate: it is built here from an identifier the resource gate already vouched
 * for. A configured one is a third URL-shaped input with the same sinks as the
 * other two — it is spliced into the quoted-string `resource_metadata`
 * parameter of the `WWW-Authenticate` challenge (RFC 9110 §11.2) and published
 * to unauthenticated clients — so it is held to the same requirements, for the
 * reasons argued on {@link validateResourceIndicator} and {@link
 * validateIssuerIdentifier}.
 *
 * A fragment is rejected because RFC 9728 §3.3 has the client fetch this URL
 * and compare the document it gets back; a fragment is never sent to the
 * server, so it could only mislead. A query is allowed and gated by grammar
 * rather than rejected outright: the derived URL carries the resource
 * identifier's query through (RFC 9728 §3), so an override must be able to
 * express the same document.
 *
 * The scheme is narrowed to `http`/`https`, which the identifier and issuer
 * gates do not do: those two values are *compared*, this one is
 * *dereferenced* — RFC 9728 §3.2 has the client fetch it with an HTTP GET, so
 * any other scheme names a document no client can retrieve. `http` itself
 * remains accepted, the same deliberate profile relaxation the issuer and
 * resource gates make for local development.
 *
 * The whole raw string is also scanned for the octets that break the
 * quoted-string it is spliced into (`"` and `\`) and for whitespace and C0
 * controls. The identifier gate can skip that scan because WHATWG
 * normalisation percent-encodes those bytes out of `pathname` before any
 * derivation reads them; this value is never re-derived — it is stored and
 * advertised exactly as typed — so the premise does not hold for it. Without
 * the scan the challenge sanitiser would silently replace the offending byte
 * and advertise a well-formed challenge naming an unfetchable URL.
 *
 * @throws TypeError when `url` carries a fragment component, is not an
 * absolute URL with a scheme and a host, uses a scheme other than `http` or
 * `https`, carries a query component that is not a valid RFC 3986 §3.4
 * `query`, holds a `"`, a `\`, whitespace or a C0 control anywhere, or
 * carries a userinfo component in its authority.
 */
export function validateResourceMetadataUrl(url: string): void {
	if (url.includes("#")) {
		throw new TypeError(
			`resource metadata URL must not contain a fragment component (RFC 9728 §3.3): '${redactIdentifier(url)}'`,
		);
	}
	const hasSchemeAndAuthority = SCHEME_AND_AUTHORITY.test(url);
	let parsed: URL | undefined;
	if (hasSchemeAndAuthority) {
		try {
			parsed = new URL(url);
		} catch {
			// Carries a scheme and an authority marker but does not parse —
			// rejected below.
		}
	}
	if (parsed === undefined || parsed.host === "") {
		throw new TypeError(
			`resource metadata URL must be an absolute URL with a scheme and a host (RFC 9728 §3): '${redactIdentifier(url)}'`,
		);
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		throw new TypeError(
			`resource metadata URL must use the http or https scheme — RFC 9728 §3.2 has the client dereference it with an HTTP GET: '${redactIdentifier(url)}'`,
		);
	}
	const brokenOctet = findQuotedStringOffence(url);
	if (brokenOctet !== undefined) {
		throw new TypeError(
			`resource metadata URL must not contain ${brokenOctet} — the value is advertised verbatim in the quoted-string \`resource_metadata\` parameter of the WWW-Authenticate challenge (RFC 9110 §5.6.4, §11.2): '${redactIdentifier(url)}'`,
		);
	}
	const queryStart = url.indexOf("?");
	if (queryStart !== -1) {
		const offence = findQueryGrammarOffence(url.slice(queryStart + 1));
		if (offence !== undefined) {
			throw new TypeError(
				`resource metadata URL query must be a valid RFC 3986 §3.4 query (pchar / "/" / "?" and well-formed %XX escapes) — ${offence}: '${redactIdentifier(url)}'`,
			);
		}
	}
	if (hasUserinfoComponent(url)) {
		throw new TypeError(
			`resource metadata URL must not include a userinfo component in its authority (RFC 9110 §4.2.4): '${redactIdentifier(url)}'`,
		);
	}
}

/**
 * Reject an issuer identifier that carries a query or fragment component,
 * contains whitespace or a control character, is not an absolute URL with a
 * scheme and a host, or carries a userinfo component in its authority.
 *
 * The issuer is the other URL-shaped member of the PRM document, and it is
 * published under the same conditions as `resource`: {@link buildPrm} copies
 * it straight into `authorization_servers`, and that document is served to
 * unauthenticated callers. So this gate exists for the same reason its
 * resource-side sibling does, and the sharpest case is the one it shares —
 * an issuer carrying `user:password@` would otherwise be disclosed verbatim
 * to anyone who fetches the document.
 *
 * Query and fragment — RFC 8414 §2: the issuer identifier is "a URL that uses
 * the https scheme and has no query or fragment components". Both are gated on
 * the raw string and rejected symmetrically, because a bare `?` or `#` is
 * still a delimiter and must not survive into the derived `.well-known` URL.
 * Neither is silently discarded: that reconciliation would let a malformed
 * identifier resolve to a document it does not actually name, and RFC 8414
 * §3.3 then has the client reject the metadata for an `issuer` mismatch.
 *
 * Whitespace and control characters — RFC 3986 §2 builds every URI component
 * out of `unreserved`, `reserved` and `pct-encoded`, none of which is either,
 * so an identifier carrying one is not a URI. The WHATWG parser does not reject
 * them, it silently *cleans* them: it trims leading and trailing C0-or-space,
 * removes every tab, CR and LF anywhere in the input, and percent-encodes the
 * rest — so `"https://auth.example.com\n"` and `"https://auth.exa\tmple.com"`
 * both parse with a non-empty host and cleared every check below, which all
 * read the parse. What survived was the split this module exists to prevent,
 * read from the issuer side: the raw string is published verbatim in
 * `authorization_servers` and stored byte-for-byte as the expected `iss`
 * (RFC 8414 §3.3 compares it for identity), while `buildMetadataUrl` derives
 * the `.well-known` location from the cleaned parse. A trailing newline in an
 * environment variable is the realistic trigger, and what it produces is every
 * token rejected on an `iss` comparison against a value that looks identical in
 * a log.
 *
 * It runs second, immediately after the query/fragment check and ahead of
 * everything that parses, for two reasons. Soundness: the checks below all read
 * the parse, and none of them can be trusted about a string the parser is going
 * to alter underneath them — an identifier must be whitespace-free before "what
 * does this parse to" is a question worth asking. Attribution: a leading space
 * or control was already rejected, but by accident and under the wrong name —
 * it fails the anchored `SCHEME_AND_AUTHORITY` test and was reported as not
 * being an absolute URL, sending an operator to re-check a scheme and a host
 * that were both there. Placing the check here makes every position of the
 * offending byte report the same defect with the same offset.
 *
 * Absolute URL — the same two requirements the resource gate applies, read off
 * the clauses that govern the issuer. The scheme is RFC 8414 §2 (the issuer is
 * a URL). The host is RFC 8414 §3.1, which derives the metadata location by
 * inserting `/.well-known/oauth-authorization-server` between the host and the
 * issuer's path: with no host there is nothing for that insertion to anchor to,
 * and the derivation yields a string no client can fetch. The `//` is checked
 * on the raw string for the reason spelled out on {@link
 * validateResourceIndicator} — WHATWG invents an authority for a special
 * scheme, so `https:auth.example.com` parses with a host it was never given.
 *
 * An invalid port needs no check of its own here: WHATWG
 * `new URL` rejects `https://auth.example.com:80O` (letter O) and every other
 * unparseable port at construction, so `parsed` stays `undefined` and the
 * absolute-URL branch below reports it. Pinned by a test rather than duplicated
 * as a redundant check.
 *
 * Userinfo — RFC 9110 §4.2.4: "a sender MUST NOT generate the userinfo
 * subcomponent" in an http(s) URI. Checked last, so an issuer that is also
 * scheme-relative or query-bearing reports that first — the defect an operator
 * fixes first.
 *
 * The `http` scheme remains accepted, the same deliberate profile relaxation
 * the resource gate makes for local development; this gate imposes no
 * https-only narrowing even though RFC 8414 §2 would support one.
 *
 * Throws `TypeError` for the reasons given on {@link validateResourceIndicator}
 * — a configuration error found at construction must not be representable as a
 * challenge on a request path.
 *
 * @throws TypeError when `issuer` carries a query or fragment component,
 * contains whitespace or a control character, is not an absolute URL with a
 * scheme and a host, or carries a userinfo component in its authority.
 */
export function validateIssuerIdentifier(issuer: string): void {
	if (issuer.includes("?") || issuer.includes("#")) {
		throw new TypeError(
			`issuer identifier must not contain a query or fragment component (RFC 8414 §2): ${redactIdentifier(issuer)}`,
		);
	}
	// Second of the four, ahead of everything that parses — see the docstring
	// for why the order is load-bearing rather than incidental. The echo is
	// redacted like every other and quoted by `redactIdentifier` itself, which
	// matters most here: the offending byte is by definition one nothing
	// renders, and for a leading one the redaction falls back to the raw prefix.
	const whitespaceOffence = findWhitespaceOrControlOffence(issuer);
	if (whitespaceOffence !== undefined) {
		throw new TypeError(
			`issuer identifier must not contain whitespace or control characters (RFC 3986 §2, RFC 8414 §3.3) — ${whitespaceOffence}: ${redactIdentifier(issuer)}`,
		);
	}
	const hasSchemeAndAuthority = SCHEME_AND_AUTHORITY.test(issuer);
	let parsed: URL | undefined;
	if (hasSchemeAndAuthority) {
		try {
			parsed = new URL(issuer);
		} catch {
			// Carries a scheme and an authority marker but does not parse —
			// rejected below.
		}
	}
	if (parsed === undefined || parsed.host === "") {
		throw new TypeError(
			`issuer identifier must be an absolute URL with a scheme and a host (RFC 8414 §2, §3.1): ${redactIdentifier(issuer)}`,
		);
	}
	if (hasUserinfoComponent(issuer)) {
		throw new TypeError(
			`issuer identifier must not include a userinfo component in its authority (RFC 9110 §4.2.4): ${redactIdentifier(issuer)}`,
		);
	}
}

function parseResourceUrl(resource: string): URL {
	// Defensive backstop, not the authoritative gate — `AuthplaneResource`'s
	// constructor runs the same check, and it is what stops a misconfigured
	// deployment from starting. This call is still load-bearing because both
	// public callers below are reachable without ever building a resource: the
	// NestJS module calls `oauthProtectedResourceMetadataPath()` at module
	// registration, and `prmDocumentUrl()` feeds the `resource_metadata`
	// parameter of an RFC 9728 challenge — i.e. a 401 response path, the worst
	// place to first discover a configuration error.
	validateResourceIndicator(resource);
	// `validateResourceIndicator` only returns for an identifier that already
	// parsed as an absolute URL, so this construction cannot throw.
	return new URL(resource);
}

function resourceMetadataSuffix(parsed: URL): string {
	return parsed.pathname.replace(/\/+$/u, "");
}

/**
 * The query component of `resource` exactly as configured, `?` included, or
 * the empty string when there is none. Read from the raw string rather than
 * WHATWG `URL.search` because the derived document URL must carry the
 * operator's bytes: `URL.search` percent-encodes `'` to `%27` on a special
 * scheme even though `'` is a legal sub-delim, which would advertise an
 * identifier the operator never configured. Callers run after
 * {@link validateResourceIndicator}, so the substring is already in-grammar
 * and fragment-free. A bare trailing `?` is treated as no query.
 */
function rawResourceQuery(resource: string): string {
	const queryStart = resource.indexOf("?");
	if (queryStart === -1 || queryStart === resource.length - 1) {
		return "";
	}
	return resource.slice(queryStart);
}

/**
 * RFC 9728 §3.1 — absolute URL of the Protected Resource Metadata document for `resource`.
 *
 * RFC 9728 §3 forms the URL by inserting the well-known string "between the
 * host component and the path and/or query components, if any" — so a query
 * on the resource identifier is carried into the document URL, after the
 * inserted path suffix:
 *
 * - `https://api.example.com/mcp?tenant=a` →
 *   `https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a`
 * - `https://api.example.com?x=1` →
 *   `https://api.example.com/.well-known/oauth-protected-resource?x=1`
 *
 * A query is legal in a resource identifier: RFC 8707 §2 states the SHOULD NOT
 * and its exception in the same sentence — "...it is recognized that there are
 * cases that make a query component a useful and necessary part of the
 * resource parameter" — and RFC 9728 §1.2 carries that forward.
 *
 * Trailing slashes on the resource path are dropped (RFC 9728 §3.1 removes the
 * terminating "/" following the host when a path or query component is
 * present), so `https://api.example.com/mcp/` and `https://api.example.com/mcp`
 * yield the same document URL. That removal is also what makes
 * `https://api.example.com/?x=1` derive the same URL as
 * `https://api.example.com?x=1` — the bare-host form has no terminating slash
 * to remove in the first place, so for it the suffix simply lands directly
 * after the host with the query following.
 *
 * The query is carried byte-for-byte as configured — an accepted query is
 * in-grammar already (see {@link validateResourceIndicator}), so it is never
 * re-encoded on the way into the document URL. A bare `?` with nothing after
 * it is treated as no query: `https://api.example.com/mcp?` derives the
 * query-less document URL.
 *
 * @throws TypeError when `resource` is not a valid absolute URL, or carries a
 * fragment component (RFC 8707 §2 — see {@link validateResourceIndicator}).
 */
export function oauthProtectedResourceMetadataDocumentUrl(
	resource: string,
): string {
	const parsed = parseResourceUrl(resource);
	// `protocol` + `host`, not `origin`: WHATWG `URL.origin` is the literal
	// string "null" for every scheme outside its special set, and the gate
	// deliberately admits any scheme with a host (`mcp://api.example.com/mcp`
	// must derive `mcp://api.example.com/.well-known/…`, not `null/…`).
	return `${parsed.protocol}//${parsed.host}/.well-known/oauth-protected-resource${resourceMetadataSuffix(parsed)}${rawResourceQuery(resource)}`;
}

/**
 * RFC 9728 §3.1 — path (no origin) of the Protected Resource Metadata
 * document for `resource`. Useful when registering the route on a framework
 * that requires a literal path at module-registration time (e.g. the NestJS
 * dynamic module) before any HTTP client has been instantiated.
 *
 * Deliberately excludes the resource identifier's query component, unlike
 * {@link oauthProtectedResourceMetadataDocumentUrl}: this value is a route
 * registration, and routing is path-keyed — a request for the query-bearing
 * document URL reaches this same route with the query ignored. Serving
 * distinct documents per query value is not supported.
 *
 * @throws TypeError when `resource` is not a valid absolute URL, or carries a
 * fragment component (RFC 8707 §2 — see {@link validateResourceIndicator}).
 */
export function oauthProtectedResourceMetadataPath(resource: string): string {
	const parsed = parseResourceUrl(resource);
	return `/.well-known/oauth-protected-resource${resourceMetadataSuffix(parsed)}`;
}
