import type { ASCredentials } from "./credentials.js";

/**
 * Pluggable authentication for AS-facing OAuth operations (token, introspect,
 * revoke, exchange). Implementations return the HTTP headers to attach to the
 * request — typically `Authorization`, but any headers required by the auth
 * scheme (mTLS-aware gateways, `private_key_jwt` client assertions, etc.) are
 * allowed.
 *
 * Parity with Python's `authplane.auth_provider.AuthProvider`.
 */
export interface AuthProvider {
	authHeaders(): Record<string, string>;
}

/**
 * RFC 6749 §2.3.1 HTTP Basic Auth from `client_id` + `client_secret`. Default
 * `AuthProvider` implementation; used when callers pass raw `ASCredentials`.
 */
export class ClientCredentialsProvider implements AuthProvider {
	private readonly headers: Record<string, string>;

	public constructor(clientId: string, clientSecret: string) {
		const encodedId = encodeURIComponent(clientId);
		const encodedSecret = encodeURIComponent(clientSecret);
		const encoded = Buffer.from(`${encodedId}:${encodedSecret}`).toString(
			"base64",
		);
		this.headers = { Authorization: `Basic ${encoded}` };
	}

	public authHeaders(): Record<string, string> {
		return this.headers;
	}
}

export function isAuthProvider(value: unknown): value is AuthProvider {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof (value as { authHeaders?: unknown }).authHeaders === "function"
	);
}

export function toAuthProvider(
	auth: AuthProvider | ASCredentials | undefined,
): AuthProvider | undefined {
	if (auth === undefined) {
		return undefined;
	}
	if (isAuthProvider(auth)) {
		return auth;
	}
	return new ClientCredentialsProvider(auth.clientId, auth.clientSecret);
}
