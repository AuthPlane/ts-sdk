/** Build RFC 8414 metadata URL from issuer. */
export function buildMetadataUrl(issuer: string): string {
	const parsed = new URL(issuer);
	const path = parsed.pathname.replace(/^\/+|\/+$/g, "");

	if (path) {
		parsed.pathname = `/.well-known/oauth-authorization-server/${path}`;
	} else {
		parsed.pathname = "/.well-known/oauth-authorization-server";
	}
	parsed.search = "";
	parsed.hash = "";

	return parsed.toString();
}
