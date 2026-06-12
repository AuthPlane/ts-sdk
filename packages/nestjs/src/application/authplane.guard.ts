import {
	type CanActivate,
	type ExecutionContext,
	Inject,
	Injectable,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";

import {
	type AuthplaneResource,
	buildDPoPRequestContext,
	buildRequestUrl,
	type DPoPRequestContext,
	extractBearerToken,
	extractDpopHeaderValues,
	type VerifiedClaims,
} from "@authplane/sdk/core";

import {
	type RequestAdapter,
	REQUIRED_SCOPES_REQUEST_KEY,
} from "../infrastructure/request-adapter.js";
import type { AuthplaneModuleOptions } from "../module/authplane.options.js";
import {
	AUTHPLANE_MODULE_OPTIONS,
	AUTHPLANE_REQUEST_ADAPTER,
	AUTHPLANE_TOKEN_VERIFIER,
} from "../module/authplane.tokens.js";
import {
	METADATA_KEY_REQUIRED_SCOPES,
	METADATA_KEY_SKIP_AUTH,
} from "./metadata-keys.js";

/**
 * NestJS `CanActivate` implementation enforcing Authplane-issued bearer
 * tokens on every guarded handler.
 *
 * Contract — mirrors `bearerAuth` from `@authplane/hono`:
 *
 * 1. Extract the access token from the `Authorization` header via the
 *    injected {@link RequestAdapter}. RFC 6750 §2.1 is applied
 *    case-insensitively and the RFC 9449 `DPoP` scheme is also accepted.
 * 2. If a `DPoP` header is present, build a {@link DPoPRequestContext}
 *    with the reconstructed `htu` URL and thread it into the verifier.
 *    The replay store and other DPoP knobs are configured on the resource
 *    via `AuthplaneResourceOptions.inboundDPoP`.
 * 3. Call {@link AuthplaneResource.verify}. Core enforces expiry with the
 *    configured `clockSkewSeconds` tolerance.
 * 4. Merge module-level `requiredScopes` with route-level `@RequireScopes(...)`
 *    metadata read via `Reflector#getAllAndMerge` and enforce the union.
 * 5. Stash the resulting {@link VerifiedClaims} on the request via the
 *    adapter's `stashAuthInfo`; downstream handlers read it via `@AuthInfo()`.
 *
 * On failure the guard throws — `AuthplaneExceptionFilter` translates those
 * exceptions into RFC 6750 §3 responses.
 */
@Injectable()
export class AuthplaneAuthGuard implements CanActivate {
	private readonly resourceOrigin: string;

	public constructor(
		@Inject(AUTHPLANE_TOKEN_VERIFIER)
		private readonly verifier: AuthplaneResource,
		@Inject(AUTHPLANE_MODULE_OPTIONS)
		private readonly options: AuthplaneModuleOptions,
		@Inject(AUTHPLANE_REQUEST_ADAPTER)
		private readonly requestAdapter: RequestAdapter,
		@Inject(Reflector)
		private readonly reflector: Reflector,
	) {
		try {
			this.resourceOrigin = new URL(this.options.resource).origin;
		} catch (cause) {
			// Mirror core `parseResourceUrl` in `@authplane/sdk/core/prm.ts`:
			// a non-URL `resource` is a programmer-supplied-type violation, so
			// surface it as `TypeError` with the inner `URL` failure preserved
			// on `.cause` instead of a bare `Error`.
			throw new TypeError(
				`AuthplaneModule: 'resource' must be an absolute URL (got ${JSON.stringify(this.options.resource)})`,
				{ cause },
			);
		}
	}

	public async canActivate(context: ExecutionContext): Promise<boolean> {
		if (this.isSkipAuth(context)) {
			return true;
		}
		const req = context.switchToHttp().getRequest();
		const token = extractBearerToken(
			this.requestAdapter.getHeader(req, "authorization"),
		);

		const dpopRequest = this.buildDpopRequestContext(req);
		const claims = await this.verifier.verify(token, { dpopRequest });

		const requiredScopes = this.resolveRequiredScopes(context);
		this.enforceRequiredScopes(req, claims, requiredScopes);

		this.requestAdapter.stashAuthInfo(req, claims);
		return true;
	}

	private buildDpopRequestContext(
		req: unknown,
	): DPoPRequestContext | undefined {
		// `getHeader` collapses arrays to `undefined` for header-smuggling
		// protection, which would silently swallow a hand-built `dpop:
		// string[]` shape (Node `req.rawHeaders`, manually-constructed
		// fixtures). `getHeaderValues` preserves both shapes the SDK can
		// encounter: the comma-folded single string that
		// `http.IncomingMessage.headers` produces for two-`DPoP`-headers
		// requests on the wire (Node only arrays a fixed allow-list like
		// `set-cookie`), and the literal `string[]` from raw-headers /
		// custom adapters. The core factory's comma-split catches the
		// folded form so `MultipleDPoPProofs` (RFC 9449 §4.3 #1) fires
		// either way; the exception filter routes that as `DPoP
		// error="invalid_dpop_proof"` per §7.1.
		const dpopHeaderValues = extractDpopHeaderValues(
			this.requestAdapter.getHeaderValues(req, "dpop"),
		);
		if (dpopHeaderValues.length === 0) return undefined;

		const url = buildRequestUrl({
			pathAndQuery: this.requestAdapter.getPathAndQuery(req),
			resourceOrigin: this.resourceOrigin,
		});

		return buildDPoPRequestContext({
			method: this.requestAdapter.getMethod(req),
			url,
			dpopHeaderValues,
		});
	}

	private isSkipAuth(context: ExecutionContext): boolean {
		return (
			this.reflector.getAllAndOverride<boolean>(METADATA_KEY_SKIP_AUTH, [
				context.getHandler(),
				context.getClass(),
			]) === true
		);
	}

	private resolveRequiredScopes(context: ExecutionContext): readonly string[] {
		const moduleScopes =
			this.options.requiredScopes ?? this.options.scopes ?? [];
		const routeScopes =
			this.reflector.getAllAndMerge<readonly string[]>(
				METADATA_KEY_REQUIRED_SCOPES,
				[context.getHandler(), context.getClass()],
			) ?? [];
		if (routeScopes.length === 0) return moduleScopes;
		if (moduleScopes.length === 0) return routeScopes;
		// Dedupe — module + route frequently overlap (e.g. requiredScopes
		// defaults to `scopes` and a route is also annotated). Without dedup
		// the WWW-Authenticate challenge would emit `scope="x x"`.
		const seen = new Set<string>();
		const union: string[] = [];
		for (const scope of moduleScopes) {
			if (!seen.has(scope)) {
				seen.add(scope);
				union.push(scope);
			}
		}
		for (const scope of routeScopes) {
			if (!seen.has(scope)) {
				seen.add(scope);
				union.push(scope);
			}
		}
		return union;
	}

	/**
	 * Delegate the AND-style scope check to core `claims.requireScopes(...)`
	 * — the single canonical membership test across every adapter. On
	 * failure, stash the merged scope list on the request before re-throwing
	 * so the exception filter can populate the `scope="…"` parameter on the
	 * `WWW-Authenticate` challenge (core's `InsufficientScope` only carries
	 * the message, and the route-level `@RequireScopes(...)` union is
	 * invisible to the filter otherwise). The stash is set only on the
	 * failure path so user code reading the symbol on the happy path keeps
	 * seeing `undefined`.
	 */
	private enforceRequiredScopes(
		req: unknown,
		claims: VerifiedClaims,
		requiredScopes: readonly string[],
	): void {
		try {
			claims.requireScopes(requiredScopes);
		} catch (err) {
			(req as Record<symbol, unknown>)[REQUIRED_SCOPES_REQUEST_KEY] =
				requiredScopes;
			throw err;
		}
	}
}
