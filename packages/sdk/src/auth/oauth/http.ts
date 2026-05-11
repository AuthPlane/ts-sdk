import { ssrfSafePostWithStatus } from "../../shared/ssrf.js";
import type { DPoPProvider } from "../dpop.js";
import type { FetchSettings } from "../fetchSettings.js";

export interface FormPostResponse {
	statusCode: number;
	body: Record<string, unknown>;
	headers: Record<string, string>;
}

function normalizeHeaders(
	headers: Headers | Record<string, string>,
): Record<string, string> {
	if (headers instanceof Headers) {
		const out: Record<string, string> = {};
		for (const [k, v] of headers.entries()) {
			out[k.toLowerCase()] = v;
		}
		return out;
	}
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(headers)) {
		out[k.toLowerCase()] = v;
	}
	return out;
}

function buildUrlSearchParams(
	formData: Record<string, string> | ReadonlyArray<[string, string]>,
): URLSearchParams {
	return Array.isArray(formData)
		? new URLSearchParams(Array.from(formData))
		: new URLSearchParams(formData as Record<string, string>);
}

export async function formPost(options: {
	url: string;
	formData: Record<string, string> | ReadonlyArray<[string, string]>;
	fetchSettings: FetchSettings;
	extraHeaders?: Record<string, string> | undefined;
	dpopProvider?: DPoPProvider | undefined;
	dpopAccessToken?: string | undefined;
}): Promise<FormPostResponse> {
	const baseHeaders = { ...(options.extraHeaders ?? {}) };

	const send = async (
		headers: Record<string, string>,
	): Promise<FormPostResponse> => {
		if (options.fetchSettings.ssrfProtection) {
			const response = await ssrfSafePostWithStatus(options.url, {
				formData: options.formData,
				extraHeaders: headers,
				allowHttp: options.fetchSettings.allowHttp,
				allowLocalhost: options.fetchSettings.allowLocalhost,
				allowPrivateNetworks: options.fetchSettings.allowPrivateNetworks,
				timeoutSeconds: options.fetchSettings.timeoutSeconds,
			});
			return {
				statusCode: response.statusCode,
				body: response.body,
				headers: normalizeHeaders(response.headers),
			};
		}

		const reqHeaders: Record<string, string> = {
			Accept: "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
			...headers,
		};
		const response = await fetch(options.url, {
			method: "POST",
			headers: reqHeaders,
			body: buildUrlSearchParams(options.formData).toString(),
			signal: AbortSignal.timeout(options.fetchSettings.timeoutSeconds * 1000),
		});
		const text = await response.text();
		let body: Record<string, unknown> = {};
		try {
			body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
		} catch {
			body = {};
		}
		return {
			statusCode: response.status,
			body,
			headers: normalizeHeaders(response.headers),
		};
	};

	const headersForAttempt = async (): Promise<Record<string, string>> => {
		const headers = { ...baseHeaders };
		if (options.dpopProvider) {
			const dpopHeaders = await options.dpopProvider.buildHeadersAsync(
				"POST",
				options.url,
				{
					accessToken: options.dpopAccessToken ?? "",
				},
			);
			Object.assign(headers, dpopHeaders);
		}
		return headers;
	};

	let response = await send(await headersForAttempt());

	if (!options.dpopProvider) {
		return response;
	}

	const nonce = response.headers["dpop-nonce"];
	if (nonce) {
		options.dpopProvider.noteNonce(options.url, nonce);
	}
	const err =
		typeof response.body.error === "string" ? response.body.error : "";
	if (nonce && err === "use_dpop_nonce") {
		response = await send(await headersForAttempt());
	}
	return response;
}
