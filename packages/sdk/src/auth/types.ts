/**
 * Client credentials for AS-facing operations (introspection, token exchange).
 * Same shape as the core `ASCredentials` type.
 */
export interface ASCredentials {
	clientId: string;
	clientSecret: string;
}
