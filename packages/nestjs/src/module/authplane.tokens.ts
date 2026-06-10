/**
 * Dependency-injection tokens used throughout `@authplane/nestjs`.
 *
 * Every provider the module publishes is keyed by one of these symbols — we
 * use `Symbol.for(...)` so that duplicate copies of the package in a
 * monorepo resolve to the same token at runtime (NestJS stores providers by
 * reference, not by name).
 *
 * Downstream consumers never need to import these directly; they are
 * surfaced so advanced use-cases (for example, swapping the
 * {@link RequestAdapter} in a test) can grab the exact provider by token.
 */

/** DI token for the shared `AuthplaneClient` singleton. */
export const AUTHPLANE_CLIENT = Symbol.for("authplane/nestjs/client");

/** DI token for the per-resource `AuthplaneResource` verifier. */
export const AUTHPLANE_RESOURCE = Symbol.for("authplane/nestjs/resource");

/**
 * DI token that resolves to the same `AuthplaneResource` as
 * {@link AUTHPLANE_RESOURCE}. Kept as a separate symbol so tests can replace
 * the verifier with `{ provide: AUTHPLANE_TOKEN_VERIFIER, useValue: mock }`
 * without touching the resource provider.
 */
export const AUTHPLANE_TOKEN_VERIFIER = Symbol.for(
	"authplane/nestjs/tokenVerifier",
);

/** DI token carrying the user-supplied {@link AuthplaneModuleOptions}. */
export const AUTHPLANE_MODULE_OPTIONS = Symbol.for("authplane/nestjs/options");

/** DI token for the request-adapter anti-corruption layer. */
export const AUTHPLANE_REQUEST_ADAPTER = Symbol.for(
	"authplane/nestjs/requestAdapter",
);
