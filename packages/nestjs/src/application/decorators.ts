import {
	type ExecutionContext,
	SetMetadata,
	createParamDecorator,
} from "@nestjs/common";

import type { VerifiedClaims } from "@authplane/sdk/core";

import { AUTH_INFO_REQUEST_KEY } from "../infrastructure/request-adapter.js";
import {
	METADATA_KEY_REQUIRED_SCOPES,
	METADATA_KEY_SKIP_AUTH,
} from "./metadata-keys.js";

/**
 * Method/class decorator attaching required-scope metadata read by the
 * {@link AuthplaneAuthGuard} at request time.
 *
 * The guard merges module-level `requiredScopes` with the union of every
 * `@RequireScopes(...)` found on the handler AND its declaring controller
 * via `Reflector#getAllAndMerge`, so stacking class + method annotations
 * is safe (duplicates don't change behaviour).
 *
 * Cross-adapter note:
 *
 *   @authplane/mcp      requireScope(scope, authInfo)  // function, scope first
 *   @authplane/hono     requireScope(c, scope)         // function, context first
 *   @authplane/nestjs   @RequireScopes('x', 'y')       // decorator read via Reflector
 *
 * Same concept, three different call shapes — check the signature when
 * switching adapters.
 *
 * @example
 * ```ts
 * @UseGuards(AuthplaneAuthGuard)
 * @Controller("math")
 * export class MathController {
 *   @Post("add")
 *   @RequireScopes("tools/add")
 *   add(): number { return 1; }
 * }
 * ```
 */
export const RequireScopes = (
	...scopes: readonly string[]
): ClassDecorator & MethodDecorator =>
	SetMetadata(METADATA_KEY_REQUIRED_SCOPES, [...scopes]);

/**
 * Method/class decorator marking a handler (or an entire controller) as
 * public — the {@link AuthplaneAuthGuard} will skip verification entirely
 * when it sees `authplane:skipAuth = true` on the handler or its class.
 *
 * Handy for health-check endpoints and the PRM controller, which must be
 * reachable without a token.
 *
 * @example
 * ```ts
 * @SkipAuth()
 * @Get("healthz")
 * health(): string { return "ok"; }
 * ```
 */
export const SkipAuth = (): ClassDecorator & MethodDecorator =>
	SetMetadata(METADATA_KEY_SKIP_AUTH, true);

/**
 * Extract the verified {@link VerifiedClaims} the guard previously stashed on
 * the request. Exposed separately from the decorator so tests (and advanced
 * compositions) can read it without bootstrapping a full NestJS app.
 */
function extractAuthInfo(
	_data: unknown,
	context: ExecutionContext,
): VerifiedClaims | undefined {
	const req = context.switchToHttp().getRequest();
	if (req === null || req === undefined) return undefined;
	return (req as Record<symbol, unknown>)[AUTH_INFO_REQUEST_KEY] as
		| VerifiedClaims
		| undefined;
}

/**
 * Parameter decorator that injects the verified {@link VerifiedClaims} into a
 * controller handler.
 *
 * **Type-honesty note.** The extractor returns `VerifiedClaims | undefined`:
 * when the guard is skipped (e.g. `@SkipAuth()` or the guard isn't attached
 * to the route), no auth info has been stashed and `undefined` comes back.
 * NestJS's parameter decorators carry no runtime type information, so the
 * value's type depends entirely on how the handler annotates its parameter.
 * Annotate as `VerifiedClaims | undefined` on handlers that may run without
 * the guard; only annotate as `VerifiedClaims` when the guard is statically
 * guaranteed to have run successfully.
 *
 * @example Guarded handler — guaranteed authenticated:
 * ```ts
 * @UseGuards(AuthplaneAuthGuard)
 * @Post("who-am-i")
 * whoami(@AuthInfo() auth: VerifiedClaims) {
 *   return { sub: auth.sub };
 * }
 * ```
 *
 * @example Skip-auth handler — auth may be absent:
 * ```ts
 * @SkipAuth()
 * @Get("healthz")
 * health(@AuthInfo() auth: VerifiedClaims | undefined) {
 *   return { signedIn: auth !== undefined };
 * }
 * ```
 */
export const AuthInfo = createParamDecorator(extractAuthInfo);

// Expose the underlying extractor on the decorator factory so tests and
// adapter internals can invoke it without having to bootstrap a full app.
Object.defineProperty(AuthInfo, "__authplaneExtractor", {
	value: extractAuthInfo,
	enumerable: false,
	writable: false,
	configurable: false,
});
