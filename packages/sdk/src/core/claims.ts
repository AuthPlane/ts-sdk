import type { VerifiedDPoPProof } from "./dpop.js";
import { InsufficientScope } from "./errors.js";

export interface VerifiedClaimsInput {
	sub: string;
	clientId: string;
	scopes: string[];
	issuer: string;
	audience: string[];
	expiresAt: number;
	issuedAt: number;
	jti: string;
	kid: string;
	/**
	 * Authplane extension: agent identifier.
	 * Defaults to empty string when not present.
	 */
	agentId: string;
	/**
	 * Authplane extension: agent chain identifiers (if present).
	 * Defaults to an empty list.
	 */
	agentChain: readonly string[];
	/**
	 * Authplane extension: token "not before" (nbf).
	 * Defaults to 0 when not present.
	 */
	notBefore: number;
	raw: Record<string, unknown>;
	dpopProof?: VerifiedDPoPProof | undefined;
}

/**
 * Immutable container for validated JWT access token claims.
 *
 * Returned by `AuthplaneResource.verify()` after successful token validation.
 * All fields have been cryptographically verified and structurally validated.
 *
 * Fields:
 *
 * - `sub`: subject identifier (user ID)
 * - `clientId`: OAuth 2.1 client identifier
 * - `scopes`: list of granted scopes (always an array)
 * - `issuer`: token issuer (matches configured issuer)
 * - `audience`: token audiences (always an array; contains the configured resource)
 * - `expiresAt`: expiration timestamp (Unix epoch seconds)
 * - `issuedAt`: issuance timestamp (Unix epoch seconds)
 * - `jti`: JWT ID (unique token identifier)
 * - `kid`: key ID used to sign the token
 * - `raw`: full decoded JWT payload
 * - Authplane extensions:
 *   - `agentId`: value of `agent_id` (default: "")
 *   - `agentChain`: value of `agent_chain` (default: [])
 *   - `notBefore`: value of `nbf` (default: 0)
 */
export class VerifiedClaims {
	public readonly sub: string;
	public readonly clientId: string;
	public readonly scopes: readonly string[];
	public readonly issuer: string;
	/** Token audience(s) — always an array; contains the configured resource. */
	public readonly audience: readonly string[];
	public readonly expiresAt: number;
	public readonly issuedAt: number;
	public readonly jti: string;
	public readonly kid: string;
	public readonly agentId: string;
	public readonly agentChain: readonly string[];
	public readonly notBefore: number;
	public readonly raw: Readonly<Record<string, unknown>>;
	public readonly dpopProof: VerifiedDPoPProof | undefined;

	public constructor(input: VerifiedClaimsInput) {
		this.sub = input.sub;
		this.clientId = input.clientId;
		this.scopes = Object.freeze([...input.scopes]);
		this.issuer = input.issuer;
		this.audience = Object.freeze([...input.audience]);
		this.expiresAt = input.expiresAt;
		this.issuedAt = input.issuedAt;
		this.jti = input.jti;
		this.kid = input.kid;
		this.agentId = input.agentId;
		this.agentChain = Object.freeze([...input.agentChain]);
		this.notBefore = input.notBefore;
		this.raw = Object.freeze({ ...input.raw });
		this.dpopProof = input.dpopProof;
	}

	public hasScope(scope: string): boolean {
		return this.scopes.includes(scope);
	}

	public requireScope(scope: string): void {
		if (!this.hasScope(scope)) {
			throw new InsufficientScope(
				`Token missing required scope '${scope}'. Token has scopes: ${this.scopes.join(", ")}`,
			);
		}
	}

	/**
	 * AND-style multi-scope check: throws {@link InsufficientScope} unless the
	 * token carries every scope in `required`. Empty input is a no-op (no
	 * scopes required = always satisfied).
	 *
	 * Adapter middleware (`@authplane/hono` `bearerAuth`, `@authplane/nestjs`
	 * `AuthplaneAuthGuard`) calls this so the union check has one canonical
	 * implementation across the SDK. The thrown error names the missing
	 * scope(s) and the scopes the token does carry — adapters surface this
	 * verbatim in `error_description`, so a client can see why the request
	 * was rejected without a separate log lookup.
	 */
	public requireScopes(required: readonly string[]): void {
		if (required.length === 0) return;
		const missing = required.filter((scope) => !this.hasScope(scope));
		if (missing.length === 0) return;
		const quoted = missing.map((scope) => `'${scope}'`).join(", ");
		const present = this.scopes.length > 0 ? this.scopes.join(", ") : "(none)";
		throw new InsufficientScope(
			`Token missing required scope${missing.length > 1 ? "s" : ""} ${quoted}. Token has scopes: ${present}`,
		);
	}

	public hasClaim(key: string, value?: unknown): boolean {
		if (!(key in this.raw)) {
			return false;
		}
		if (value === undefined) {
			return true;
		}
		return this.raw[key] === value;
	}

	/**
	 * RFC 8693 §4.1 `act` claim — the immediate actor when the token was
	 * obtained via token exchange. Returns `undefined` when absent. Nested
	 * `act` claims form the full delegation chain.
	 */
	public get act(): Readonly<Record<string, unknown>> | undefined {
		const value = this.raw.act;
		return isPlainObject(value) ? value : undefined;
	}

	/**
	 * RFC 8693 §4.4 `may_act` claim — identifies parties permitted to act on
	 * behalf of the token subject. Returns `undefined` when absent.
	 */
	public get mayAct(): Readonly<Record<string, unknown>> | undefined {
		const value = this.raw.may_act;
		return isPlainObject(value) ? value : undefined;
	}
}

function isPlainObject(
	value: unknown,
): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
