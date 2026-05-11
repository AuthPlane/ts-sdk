import { JWKS_MAX_SIZE_BYTES } from "../constants.js";
import { parseExpiresAt } from "./cacheHeaders.js";
import type { FetchResult } from "./fetchResult.js";
import { FetchSettings } from "./fetchSettings.js";
import { ssrfSafeFetch } from "./ssrf.js";

function headersToObject(headers: Headers): Record<string, string> {
	const values: Record<string, string> = {};
	for (const [key, value] of headers.entries()) {
		values[key.toLowerCase()] = value;
	}
	return values;
}

export class DocumentFetcher<TDocument extends Record<string, unknown>> {
	private readonly url: string;
	private readonly settings: FetchSettings;
	private readonly maxSize: number;

	public constructor(
		url: string,
		options: {
			settings?: FetchSettings;
			maxSize?: number;
		} = {},
	) {
		this.url = url;
		this.settings = options.settings ?? new FetchSettings();
		this.maxSize = options.maxSize ?? JWKS_MAX_SIZE_BYTES;
	}

	public async fetch(): Promise<FetchResult<TDocument>> {
		if (this.settings.ssrfProtection) {
			const response = await ssrfSafeFetch(this.url, {
				allowHttp: this.settings.allowHttp,
				allowLocalhost: this.settings.allowLocalhost,
				allowPrivateNetworks: this.settings.allowPrivateNetworks,
				maxSize: this.maxSize,
				timeoutSeconds: this.settings.timeoutSeconds,
			});
			return {
				document: response.body as TDocument,
				expiresAt: parseExpiresAt(response.headers),
			};
		}

		const timeout = AbortSignal.timeout(this.settings.timeoutSeconds * 1000);
		const response = await fetch(this.url, {
			method: "GET",
			redirect: "manual",
			signal: timeout,
		});

		if (response.status >= 300 && response.status < 400) {
			throw new Error(`Redirects are not allowed (status ${response.status}).`);
		}
		if (!response.ok) {
			throw new Error(`HTTP request failed with status ${response.status}.`);
		}

		const contentLength = response.headers.get("content-length");
		if (contentLength) {
			const parsedLength = Number.parseInt(contentLength, 10);
			if (Number.isFinite(parsedLength) && parsedLength > this.maxSize) {
				throw new Error(
					`Response too large: ${parsedLength} bytes (max ${this.maxSize}).`,
				);
			}
		}

		const text = await response.text();
		if (Buffer.byteLength(text, "utf-8") > this.maxSize) {
			throw new Error(
				`Response too large: body exceeded ${this.maxSize} bytes limit.`,
			);
		}

		const body = JSON.parse(text) as TDocument;
		const headers = headersToObject(response.headers);
		return {
			document: body,
			expiresAt: parseExpiresAt(headers),
		};
	}
}
