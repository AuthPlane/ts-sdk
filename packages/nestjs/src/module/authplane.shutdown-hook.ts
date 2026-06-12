import { Inject, Injectable, type OnApplicationShutdown } from "@nestjs/common";

import type { AuthplaneClient } from "@authplane/sdk/core";

import { AUTHPLANE_CLIENT } from "./authplane.tokens.js";

/**
 * NestJS lifecycle hook that closes the shared {@link AuthplaneClient}
 * when the application shuts down.
 *
 * `client.close()` releases the background refreshers (JWKS + AS metadata)
 * and any HTTP-pool resources the underlying fetcher holds. Without it,
 * Node will keep the event loop alive, so Nest apps would hang on SIGTERM
 * in containerised deployments.
 *
 * Note: `verifier.close()` is a no-op in the core SDK — always call
 * `client.close()` for real cleanup. This hook centralises that rule so
 * applications never have to remember it themselves (cross-adapter
 * lesson #3).
 */
@Injectable()
export class AuthplaneShutdownHook implements OnApplicationShutdown {
	public constructor(
		@Inject(AUTHPLANE_CLIENT)
		private readonly client: AuthplaneClient,
	) {}

	public async onApplicationShutdown(): Promise<void> {
		await this.client.close();
	}
}
