import {
	assertHttpIdentifier,
	splitHttpIdentifier,
} from "../identifiers.js";

/**
 * Build the RFC 8414 metadata URL from the issuer identifier.
 *
 * RFC 8414 §3 forms the URL by inserting `/.well-known/oauth-authorization-server`
 * between the authority and path of the issuer — a pure string insertion that
 * preserves the issuer's path exactly (including any trailing slash).
 */
export function buildMetadataUrl(issuer: string): string {
	const { base, path } = splitHttpIdentifier(
		assertHttpIdentifier(issuer, "issuer"),
	);
	return `${base}/.well-known/oauth-authorization-server${path}`;
}
