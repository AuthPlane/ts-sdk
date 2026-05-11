/**
 * Authplane TypeScript SDK — JWT access token validation and OAuth AS integration helpers.
 *
 * Main entry points:
 *
 * - `AuthplaneResource`: validate JWT access tokens for your resource server (JWKS + discovery via AuthplaneClient).
 * - `VerifiedClaims`: immutable container returned by `verifier.verify()` with helpers like `requireScope()`.
 * - `FetchSettings`: outbound fetch hardening (SSRF protection, timeouts, allowlists).
 * - `IntrospectionRevocation`: marker to enable RFC 7662 revocation checking via introspection.
 * - `buildPrm` / `oauthProtectedResourceMetadataDocumentUrl` / `AuthplaneResource.prmDocumentUrl()`: RFC 9728 PRM JSON and document URL for MCP/resource servers.
 *
 * Quick start:
 *
 * ```ts
 * import { AuthplaneClient } from "@authplane/sdk/core";
 *
 * const client = await AuthplaneClient.create({
 *   issuer: "https://auth.example.com",
 * });
 *
 * const resource = client.resource({
 *   resource: "https://api.example.com",
 *   scopes: ["read"],
 * });
 *
 * const claims = await resource.verify(incomingToken);
 * claims.requireScope("read");
 * ```
 */

export * from "../auth/fetchSettings.js";
export {
	type IntrospectionConfig,
	type IntrospectionResponse,
	IntrospectionRevocation,
	introspectToken,
} from "../auth/introspection.js";
export * from "../auth/oauth/clientCredentials.js";
export * from "../auth/oauth/revocation.js";
export * from "../auth/oauth/tokenExchange.js";
export * from "../auth/oauth/types.js";
export * from "./authProvider.js";
export * from "./cache.js";
export * from "./circuitBreaker.js";
export * from "./claims.js";
export * from "./client.js";
export * from "./constants.js";
export type { ASCredentials } from "./credentials.js";
export * from "./credentials.js";
export * from "./dpop.js";
export * from "./errors.js";
export * from "./prm.js";
export {
	AuthplaneResource,
	type AuthplaneResourceOptions,
	type RevocationChecker,
} from "./resource.js";
