import type { VerifiedClaims } from "@authplane/sdk/core";

/**
 * Symbol under which {@link AuthplaneAuthGuard} stashes verified claims on
 * the platform request. The `@AuthInfo()` parameter decorator reads from the
 * same symbol.
 *
 * Intentionally module-local (`Symbol()`, not `Symbol.for(...)`). The global
 * registry would let two parallel copies of `@authplane/nestjs` — or any
 * unrelated package — collide on the request stash slot.
 */
export const AUTH_INFO_REQUEST_KEY: unique symbol = Symbol(
	"authplane/nestjs/authInfo",
);

/**
 * Symbol under which the guard stashes the merged required-scopes list before
 * throwing `InsufficientScope`. The exception filter reads it to populate the
 * `scope="…"` parameter on the `WWW-Authenticate` challenge — the route-level
 * `@RequireScopes(...)` union is known to the guard (via `Reflector`) but not
 * to the filter, so the request-stash is the channel.
 */
export const REQUIRED_SCOPES_REQUEST_KEY: unique symbol = Symbol(
	"authplane/nestjs/requiredScopes",
);

/**
 * Anti-corruption layer between the NestJS/Node transport world and the rest
 * of this adapter.
 *
 * `ExecutionContext.switchToHttp().getRequest()` returns different shapes
 * depending on which transport is active:
 *
 * - `@nestjs/platform-express` → an `express.Request` (headers lowercased by
 *   Node, `originalUrl` is path-only, methods uppercased by convention).
 * - `@nestjs/platform-fastify` → a `FastifyRequest` with the underlying Node
 *   request reachable at `request.raw` (headers lowercased, `raw.url`
 *   path-only).
 *
 * Wrap those differences behind a small interface so the guard never touches
 * `req.headers[…]` directly — every downstream concern reads through this
 * port. The `any` casts are confined to this file.
 */
export interface RequestAdapter {
	/** Read a header value case-insensitively; returns `undefined` when absent. */
	getHeader(req: unknown, name: string): string | undefined;
	/**
	 * Read a header case-insensitively, preserving the multi-value shape.
	 * Returns `string | readonly string[] | undefined` so the caller can
	 * distinguish a single-valued header from a duplicate-named one.
	 *
	 * Used exclusively for the `DPoP` header: RFC 9449 §4.3 #1 requires
	 * resources to reject requests carrying more than one `DPoP` header,
	 * and the core `buildDPoPRequestContext` factory needs the
	 * pre-collapsed shape to detect the violation. Every other header
	 * (Authorization, etc.) goes through `getHeader`, which intentionally
	 * collapses arrays to `undefined` for header-smuggling protection.
	 */
	getHeaderValues(
		req: unknown,
		name: string,
	): string | readonly string[] | undefined;
	/**
	 * HTTP method in uppercase. Defaults to `"POST"` when the transport does
	 * not expose a method — chosen because the documented bearer-protected
	 * surface is JSON-RPC `POST` (MCP servers, the canonical consumer of
	 * this adapter). A custom transport that flows non-POST requests
	 * through the guard MUST override this method; otherwise the DPoP `htm`
	 * claim will mismatch the actual request method and proofs will fail to
	 * verify with `DPoPBindingMismatch` rather than a clearer "method
	 * missing" signal.
	 */
	getMethod(req: unknown): string;
	/**
	 * Path + query string (Express `originalUrl`, Fastify `raw.url`). Defaults
	 * to `"/"` when the transport does not expose one.
	 */
	getPathAndQuery(req: unknown): string;
	/**
	 * Stash the verified claims on the request so the `@AuthInfo()` parameter
	 * decorator can later read them back. Implementations **must** write under
	 * `AUTH_INFO_REQUEST_KEY`; the decorator reads the symbol directly and
	 * never round-trips through this interface.
	 */
	stashAuthInfo(req: unknown, info: VerifiedClaims): void;
}

type HeaderBag = Record<string, string | readonly string[] | undefined>;

function findInBag(
	bag: HeaderBag | undefined,
	lower: string,
): string | readonly string[] | undefined {
	if (!bag) return undefined;
	if (lower in bag) return bag[lower];
	for (const key of Object.keys(bag)) {
		if (key.toLowerCase() === lower) return bag[key];
	}
	return undefined;
}

function readHeader(
	req: unknown,
	name: string,
): string | readonly string[] | undefined {
	const lower = name.toLowerCase();
	const direct = (req as { headers?: HeaderBag } | null)?.headers;
	const directHit = findInBag(direct, lower);
	if (directHit !== undefined) return directHit;
	const raw = (req as { raw?: { headers?: HeaderBag } } | null)?.raw?.headers;
	return findInBag(raw, lower);
}

/**
 * Default {@link RequestAdapter} that covers both `@nestjs/platform-express`
 * and `@nestjs/platform-fastify`. Applications that need to add a new
 * transport (or tweak how headers are read) can substitute their own via the
 * module options.
 */
export const defaultRequestAdapter: RequestAdapter = {
	getHeader(req, name) {
		const value = readHeader(req, name);
		// Duplicate-named headers are returned as `undefined` for non-DPoP
		// callers: intermediaries disagree on which copy is canonical and
		// that ambiguity is a known header-smuggling shape. DPoP needs the
		// multi-value shape to enforce RFC 9449 §4.3 #1 — that path
		// reads through `getHeaderValues` instead.
		if (Array.isArray(value)) return undefined;
		return typeof value === "string" ? value : undefined;
	},

	getHeaderValues(req, name) {
		return readHeader(req, name);
	},

	getMethod(req) {
		const direct = (req as { method?: unknown } | null)?.method;
		const raw = (req as { raw?: { method?: unknown } } | null)?.raw?.method;
		const method = typeof direct === "string" ? direct : raw;
		return typeof method === "string" ? method.toUpperCase() : "POST";
	},

	getPathAndQuery(req) {
		const r = req as {
			originalUrl?: unknown;
			url?: unknown;
			raw?: { url?: unknown };
		} | null;
		const candidate = r?.originalUrl ?? r?.url ?? r?.raw?.url;
		return typeof candidate === "string" && candidate.length > 0
			? candidate
			: "/";
	},

	stashAuthInfo(req, info) {
		(req as Record<symbol, unknown>)[AUTH_INFO_REQUEST_KEY] = info;
	},
};
