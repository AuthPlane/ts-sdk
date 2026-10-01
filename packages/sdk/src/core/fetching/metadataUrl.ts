import { validateIssuerIdentifier } from "../prm.js";

/** Build RFC 8414 metadata URL from issuer. */
export function buildMetadataUrl(issuer: string): string {
	// One gate, shared with the PRM builder. This function used to carry its own
	// inline query/fragment check, which left `buildPrm` — the other place an
	// issuer is consumed — with no check at all, and let the two drift. The
	// shared gate is a superset of what was here: it still rejects a query or a
	// fragment (RFC 8414 §2), and it additionally rejects an issuer that is not
	// an absolute URL with a scheme and a host, or that carries userinfo. Both
	// additions are reachable from here — the derivation below sets `pathname`
	// on the parsed URL and returns it, so a host-less issuer produced a string
	// no client could fetch, and a `user:pw@` issuer was carried verbatim into
	// the fetch target.
	validateIssuerIdentifier(issuer);
	const parsed = new URL(issuer);

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
