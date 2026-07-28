/**
 * Shared handling for resource and issuer identifiers.
 *
 * RFC 8414 §3.3 and RFC 9728 §3.3 require the advertised issuer/resource to be
 * identical to the configured value — a simple string comparison, not RFC 3986
 * equivalence. The SDK therefore never rewrites an identifier: well-known URLs
 * are formed by inserting the well-known path segment between the authority and
 * the identifier's path (a pure string insertion, RFC 8414 §3 / RFC 9728 §3),
 * and validation rejects structurally unusable identifiers instead of
 * repairing them.
 */

/**
 * Validate that `value` is an absolute http(s) URL with an authority and no
 * fragment (RFC 8707 §2 forbids fragments in resource identifiers). Returns
 * `value` unchanged — trailing slashes, host case, and explicit ports are all
 * legal identifier variations and are preserved verbatim.
 *
 * @throws TypeError when the identifier is structurally invalid.
 */
export function assertHttpIdentifier(value: string, label: string): string {
	let parsed: URL;
	try {
		parsed = new URL(value);
	} catch (cause) {
		throw new TypeError(
			`${label} is not a valid URL (got ${JSON.stringify(value)})`,
			{ cause },
		);
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		throw new TypeError(
			`${label} must be an http or https URL (got ${JSON.stringify(value)})`,
		);
	}
	// WHATWG accepts scheme-relative forms like "https:example.com"; the RFC
	// 3986 absolute-URI form used for identifiers requires an explicit
	// authority, and splitHttpIdentifier relies on it.
	if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//u.test(value)) {
		throw new TypeError(
			`${label} must include an authority ("//") (got ${JSON.stringify(value)})`,
		);
	}
	if (value.includes("#")) {
		throw new TypeError(
			`${label} must not contain a fragment (got ${JSON.stringify(value)})`,
		);
	}
	return value;
}

/**
 * Split a validated absolute http(s) identifier into the part before the path
 * (scheme + authority, verbatim) and its path component (verbatim). Query and
 * fragment are excluded from both.
 *
 * WHATWG `URL` cannot be used for this: it serialises an empty path as "/" and
 * rewrites path bytes, either of which would break the RFC 8414 §3 /
 * RFC 9728 §3 insertion rule that the derived well-known URL preserves the
 * identifier exactly.
 */
export function splitHttpIdentifier(identifier: string): {
	base: string;
	path: string;
} {
	const authorityStart = identifier.indexOf("://") + 3;
	const rest = identifier.slice(authorityStart);
	const authorityEnd = rest.search(/[/?#]/u);
	if (authorityEnd === -1) {
		return { base: identifier, path: "" };
	}
	const base = identifier.slice(0, authorityStart + authorityEnd);
	if (rest[authorityEnd] !== "/") {
		return { base, path: "" };
	}
	const pathAndAfter = rest.slice(authorityEnd);
	const queryOrFragment = pathAndAfter.search(/[?#]/u);
	return {
		base,
		path:
			queryOrFragment === -1
				? pathAndAfter
				: pathAndAfter.slice(0, queryOrFragment),
	};
}
