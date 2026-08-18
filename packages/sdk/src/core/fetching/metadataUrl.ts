/** Build RFC 8414 metadata URL from issuer. */
export function buildMetadataUrl(issuer: string): string {
	const parsed = new URL(issuer);

	// RFC 8414 §2: the issuer identifier MUST NOT contain a query or fragment
	// component. Gate on the raw issuer string and reject BOTH symmetrically —
	// a bare `?` (empty query) or `#` (empty fragment) is still a query/fragment
	// delimiter and must not survive into the derived `.well-known` URL. We do
	// not silently discard either component: that reconciliation would let a
	// malformed identifier resolve to a document it does not actually name.
	if (issuer.includes("?") || issuer.includes("#")) {
		// Log only the scheme, host, and path so a credential-shaped query
		// (e.g. `?token=...`) never lands in startup logs. We rebuild from
		// `protocol`/`host`/`pathname` rather than `origin` because `origin`
		// is the literal string `"null"` for a non-special scheme (e.g.
		// `foo://bar/t?x=1`), which would render a degenerate `'null/t'`.
		throw new TypeError(
			`issuer identifier must not contain a query or fragment component (RFC 8414 §2): '${parsed.protocol}//${parsed.host}${parsed.pathname}'`,
		);
	}

	// Derivation (RFC 8414 §3.1): the terminating slash of the issuer path is
	// dropped when building the `.well-known` URL. This is a location-building
	// operation and is distinct from issuer identity comparison.
	const path = parsed.pathname.replace(/^\/+|\/+$/g, "");

	if (path) {
		parsed.pathname = `/.well-known/oauth-authorization-server/${path}`;
	} else {
		parsed.pathname = "/.well-known/oauth-authorization-server";
	}

	return parsed.toString();
}
