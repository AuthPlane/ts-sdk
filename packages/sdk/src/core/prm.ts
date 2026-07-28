import { ALLOWED_ALGORITHMS } from "./constants.js";
import { assertHttpIdentifier, splitHttpIdentifier } from "./identifiers.js";

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
 * Usage:
 *
 * ```ts
 * import { buildPrm } from "@authplane/core";
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
 */
export function buildPrm(
	issuer: string,
	resource: string,
	scopes: readonly string[],
	options: BuildPrmOptions = {},
): ProtectedResourceMetadata {
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
 * RFC 9728 §3.1 — absolute URL of the Protected Resource Metadata document for `resource`.
 *
 * Formed by inserting `/.well-known/oauth-protected-resource` between the
 * authority and path of the resource identifier (RFC 9728 §3) — a pure string
 * insertion that preserves the path exactly, so `https://api.example.com/mcp/`
 * and `https://api.example.com/mcp` yield distinct document URLs.
 */
export function oauthProtectedResourceMetadataDocumentUrl(
	resource: string,
): string {
	const { base, path } = splitHttpIdentifier(
		assertHttpIdentifier(resource, "resource"),
	);
	return `${base}/.well-known/oauth-protected-resource${path}`;
}

/**
 * RFC 9728 §3.1 — path (no origin) of the Protected Resource Metadata
 * document for `resource`. Useful when registering the route on a framework
 * that requires a literal path at module-registration time (e.g. the NestJS
 * dynamic module) before any HTTP client has been instantiated.
 *
 * @throws TypeError when `resource` is not a valid absolute URL.
 */
export function oauthProtectedResourceMetadataPath(resource: string): string {
	const { path } = splitHttpIdentifier(
		assertHttpIdentifier(resource, "resource"),
	);
	return `/.well-known/oauth-protected-resource${path}`;
}
