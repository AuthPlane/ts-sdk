import {
	type ArgumentsHost,
	Catch,
	type ExceptionFilter,
	Inject,
	Injectable,
	Logger,
} from "@nestjs/common";

import {
	AuthplaneError,
	type AuthplaneResource,
	httpStatus,
	InsufficientScope,
	wwwAuthenticate,
} from "@authplane/sdk/core";

import { REQUIRED_SCOPES_REQUEST_KEY } from "../infrastructure/request-adapter.js";
import type { AuthplaneModuleOptions } from "../module/authplane.options.js";
import {
	AUTHPLANE_MODULE_OPTIONS,
	AUTHPLANE_RESOURCE,
} from "../module/authplane.tokens.js";

/**
 * Translates Authplane core errors into RFC 6750 §3 responses.
 *
 * Only {@link AuthplaneError} subclasses are claimed by this filter —
 * unrelated exceptions (e.g. user-thrown `HttpException`) keep flowing
 * through NestJS's default exception handling. Mounting this filter
 * globally is safe; it does **not** swallow everything.
 *
 * Response shape:
 *
 * - {@link InsufficientScope}   → 403 + `WWW-Authenticate: Bearer …` with `scope="…"`
 * - Everything else (TokenMissing, InvalidSignature, TokenExpired, …)
 *                                → 401 + `WWW-Authenticate: Bearer …`
 * - `DPoPError` subclasses (except `DPoPNotSupported`) emit `DPoP …` instead
 *   of `Bearer …`; the scheme switch is handled by core `wwwAuthenticate()`.
 * - `JWKSFetchError` / `MetadataFetchError` map to 503 via core `httpStatus()`.
 *
 * Bridges Express (`res.setHeader` / `res.status().json()`) and Fastify
 * (`reply.header` / `reply.code().send()`) transparently.
 */
@Injectable()
@Catch(AuthplaneError)
export class AuthplaneExceptionFilter implements ExceptionFilter {
	private readonly logger = new Logger("AuthplaneExceptionFilter");
	private prmUrlWarned = false;

	public constructor(
		@Inject(AUTHPLANE_MODULE_OPTIONS)
		private readonly options: AuthplaneModuleOptions,
		@Inject(AUTHPLANE_RESOURCE)
		private readonly resource: AuthplaneResource,
	) {}

	public catch(exception: AuthplaneError, host: ArgumentsHost): void {
		const http = host.switchToHttp();
		const req = http.getRequest();
		const reply = http.getResponse();

		const wwwAuthenticateOptions: Parameters<typeof wwwAuthenticate>[1] = {};
		if (this.options.resource) {
			wwwAuthenticateOptions.realm = this.options.resource;
		}
		const prmUrl = this.safePrmUrl();
		if (prmUrl) {
			wwwAuthenticateOptions.resourceMetadataUrl = prmUrl;
		}
		if (exception instanceof InsufficientScope) {
			const scopes = this.resolveRequiredScopes(req);
			if (scopes.length > 0) {
				wwwAuthenticateOptions.scope = scopes;
			}
		}
		const header = wwwAuthenticate(exception, wwwAuthenticateOptions);

		const errorCode =
			exception instanceof InsufficientScope
				? "insufficient_scope"
				: "invalid_token";

		setHeader(reply, "WWW-Authenticate", header);
		sendJson(reply, httpStatus(exception), {
			error: errorCode,
			error_description: exception.message,
		});
	}

	/**
	 * Prefer scopes stashed by the guard on the request — those already reflect
	 * the full merge of module-level `requiredScopes` with route-level
	 * `@RequireScopes(...)`. Fall back to module-level scopes when the request
	 * carries no stash (e.g. a third party threw `InsufficientScope` directly).
	 */
	private resolveRequiredScopes(req: unknown): readonly string[] {
		const stash = (req as Record<symbol, unknown> | null)?.[
			REQUIRED_SCOPES_REQUEST_KEY
		];
		if (Array.isArray(stash) && stash.length > 0) {
			return stash as readonly string[];
		}
		return this.options.requiredScopes ?? this.options.scopes ?? [];
	}

	/**
	 * Best-effort PRM document URL for the `resource_metadata=` challenge
	 * parameter. Falls back to omitting the parameter if the resource cannot
	 * compute one — the challenge itself stays well-formed (RFC 9728 §5.1
	 * makes `resource_metadata` optional). The first failure is logged at
	 * `warn` because it almost always means a misconfigured `resource` URL
	 * and the operator would otherwise only discover it when a client fails
	 * to bootstrap discovery; subsequent failures are silent so a sustained
	 * misconfig doesn't flood the log.
	 */
	private safePrmUrl(): string | undefined {
		try {
			return this.resource.prmDocumentUrl();
		} catch (err) {
			if (!this.prmUrlWarned) {
				this.prmUrlWarned = true;
				this.logger.warn(
					`prmDocumentUrl() threw — omitting resource_metadata from WWW-Authenticate. Check the configured 'resource' URL: ${err instanceof Error ? err.message : String(err)}`,
				);
			}
			return undefined;
		}
	}
}

function setHeader(reply: unknown, name: string, value: string): void {
	if (!reply || typeof reply !== "object") return;
	const r = reply as {
		setHeader?: (name: string, value: string) => unknown;
		header?: (name: string, value: string) => unknown;
	};
	if (typeof r.setHeader === "function") {
		r.setHeader(name, value);
		return;
	}
	if (typeof r.header === "function") {
		r.header(name, value);
	}
}

function sendJson(reply: unknown, status: number, body: unknown): void {
	if (!reply || typeof reply !== "object") return;
	const r = reply as {
		status?: (code: number) => { json?: (body: unknown) => unknown };
		json?: (body: unknown) => unknown;
		code?: (code: number) => { send?: (body: unknown) => unknown };
		send?: (body: unknown) => unknown;
	};
	// Fastify exposes both `code()` and `send()`; its `status()` historically
	// returned `void` so chaining `.json()` off it silently no-ops. Probe the
	// Fastify pair first before falling back to Express's `status().json()`.
	if (typeof r.code === "function" && typeof r.send === "function") {
		const chained = r.code(status);
		if (chained && typeof chained.send === "function") {
			chained.send(body);
			return;
		}
		r.send(body);
		return;
	}
	if (typeof r.status === "function") {
		const chained = r.status(status);
		if (chained && typeof chained.json === "function") {
			chained.json(body);
		}
	}
}
