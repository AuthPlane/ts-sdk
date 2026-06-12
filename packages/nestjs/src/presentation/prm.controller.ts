import { Controller, Get, Inject, type Type } from "@nestjs/common";

import type {
	AuthplaneResource,
	ProtectedResourceMetadata,
} from "@authplane/sdk/core";

import { SkipAuth } from "../application/decorators.js";
import { AUTHPLANE_RESOURCE } from "../module/authplane.tokens.js";

/**
 * Build a controller class that serves the RFC 9728 Protected Resource
 * Metadata document at a statically-known path.
 *
 * NestJS expects literal route strings on `@Controller` / `@Get`, but the
 * PRM path is derived from the protected resource's URL at module setup
 * time. To keep the guarantee of a static path AND let the module pick the
 * path dynamically, {@link AuthplaneModule.forRootAsync} calls this factory
 * during registration to mint a fresh controller class with the path baked
 * in.
 *
 * The controller is marked `@SkipAuth()` so the guard does not require a
 * bearer token for the discovery endpoint — PRM is meant to be reachable
 * without credentials (RFC 9728 §5).
 *
 * @param path Pathname portion of the PRM URL (for example
 *   `"/.well-known/oauth-protected-resource/mcp"`).
 * @returns A `Type<unknown>` compatible with `@Module({ controllers: [...] })`.
 */
export function buildPrmController(path: string): Type<unknown> {
	@Controller()
	class AuthplanePrmController {
		public constructor(
			@Inject(AUTHPLANE_RESOURCE)
			private readonly resource: AuthplaneResource,
		) {}

		@Get(path)
		@SkipAuth()
		public serve(): ProtectedResourceMetadata {
			return this.resource.prmResponse();
		}
	}
	return AuthplanePrmController;
}
