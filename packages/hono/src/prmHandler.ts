import type { ProtectedResourceMetadata } from "@authplane/sdk/core";
import type { Handler } from "hono";

/**
 * Build a Hono route handler that serves the RFC 9728 Protected Resource
 * Metadata document as JSON.
 *
 * The handler is intentionally content-only: no authentication, no caching,
 * no conditional responses — those belong in the calling application if they
 * are needed. Mount it at the `oauth-protected-resource` path derived from
 * the resource URL (typically `/.well-known/oauth-protected-resource`):
 *
 * ```ts
 * import { authplaneHonoAuth } from "@authplane/hono";
 *
 * const { protectedResourceMetadataPath, protectedResourceMetadataHandler } =
 *   await authplaneHonoAuth({ … });
 *
 * app.get(protectedResourceMetadataPath, protectedResourceMetadataHandler);
 * ```
 *
 * The metadata argument is captured by reference at construction time, so
 * callers that need to rotate the payload should rebuild the handler.
 */
export function protectedResourceMetadataHandler(
	metadata: ProtectedResourceMetadata,
): Handler {
	return (c) => c.json(metadata);
}
