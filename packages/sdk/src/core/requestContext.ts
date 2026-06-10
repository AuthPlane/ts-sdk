/**
 * Input options for {@link buildRequestUrl}.
 *
 * The `htu` URL the DPoP verifier matches against is pinned to the
 * operator-configured **resource origin** — never the request's `Host`
 * header, `X-Forwarded-Proto`, or `X-Forwarded-Host`. Letting an intermediary
 * (or a directly-reachable client) influence `htu` neuters RFC 9449
 * cross-endpoint anti-replay because a proof minted for one endpoint would
 * verify against another. Only the path + query of the request is taken from
 * the inbound `req`; the scheme and authority always come from the canonical
 * resource URL the resource server was configured with.
 */
export interface BuildRequestUrlParams {
	/**
	 * Path + query portion of the inbound request (e.g. `"/mcp/tools/call?id=42"`).
	 * Must start with `/`; if it doesn't, one is prepended.
	 */
	readonly pathAndQuery: string;
	/**
	 * The origin (scheme + authority) of the configured resource URL — e.g.
	 * `"https://api.example.com"`. Use `new URL(resource).origin`.
	 */
	readonly resourceOrigin: string;
}

/**
 * Return the effective request URL the DPoP verifier should use for `htu`
 * matching. Always anchored to {@link BuildRequestUrlParams.resourceOrigin};
 * the request only contributes its path + query.
 */
export function buildRequestUrl(params: BuildRequestUrlParams): string {
	const path = params.pathAndQuery.startsWith("/")
		? params.pathAndQuery
		: `/${params.pathAndQuery}`;
	const origin = params.resourceOrigin.replace(/\/+$/u, "");
	return `${origin}${path}`;
}

/**
 * Extract the path + query portion of an absolute URL string (typically the
 * raw inbound request URL). The fragment, if any, is discarded — DPoP `htu`
 * matching is on path + query only.
 *
 * @throws TypeError when `absoluteUrl` is not a parseable absolute URL. The
 *   message names the helper and quotes the offending input so a stack trace
 *   in an adapter (`bearerAuth` / `AuthplaneAuthGuard`) points at the bad
 *   request-URL field instead of a bare `Invalid URL` from `new URL()`.
 */
export function pathAndQueryOf(absoluteUrl: string): string {
	let url: URL;
	try {
		url = new URL(absoluteUrl);
	} catch (cause) {
		throw new TypeError(
			`pathAndQueryOf: argument must be an absolute URL (got ${JSON.stringify(absoluteUrl)})`,
			{ cause },
		);
	}
	return `${url.pathname}${url.search}`;
}

/**
 * Normalise a raw `DPoP` header into the list of values the §4.3 boundary
 * in {@link buildDPoPRequestContext} expects.
 *
 * Accepts the Node-style `string | readonly string[] | undefined` shape
 * adapters get back from `req.headers` (single header → string, multiple
 * headers → array, missing → undefined). Returns `[]` when no header is
 * present so callers can branch on length rather than discriminating
 * between absence and emptiness. The factory itself enforces RFC 9449
 * §4.3 #1 (no more than one DPoP header) — this helper just normalises
 * the wire shape.
 *
 * Whitespace-only entries are dropped. The array shape is preserved so a
 * malformed multi-header request surfaces as `MultipleDPoPProofs` at the
 * factory rather than being silently coerced to "no proof".
 */
export function extractDpopHeaderValues(
	dpopHeader: string | readonly string[] | undefined,
): readonly string[] {
	if (dpopHeader === undefined) return [];
	if (Array.isArray(dpopHeader)) {
		return dpopHeader.filter(
			(item): item is string => typeof item === "string" && item.length > 0,
		);
	}
	// After undefined + array narrowing the only remaining shape is `string`;
	// the cast pacifies TS, whose `Array.isArray` predicate doesn't refine
	// `readonly string[]` away.
	const proof = dpopHeader as string;
	if (proof.length === 0) return [];
	return [proof];
}
