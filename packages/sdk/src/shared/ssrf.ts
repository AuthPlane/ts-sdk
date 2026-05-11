import { lookup } from "node:dns/promises";
import type { IncomingHttpHeaders } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import * as ipaddr from "ipaddr.js";

const DEFAULT_MAX_SIZE = 65_536;
const DEFAULT_TIMEOUT_SECONDS = 10;

const ALWAYS_BLOCKED = new BlockList();
ALWAYS_BLOCKED.addSubnet("169.254.0.0", 16, "ipv4");
ALWAYS_BLOCKED.addSubnet("224.0.0.0", 4, "ipv4");
ALWAYS_BLOCKED.addSubnet("240.0.0.0", 4, "ipv4");
ALWAYS_BLOCKED.addSubnet("0.0.0.0", 8, "ipv4");
ALWAYS_BLOCKED.addSubnet("::", 128, "ipv6");
ALWAYS_BLOCKED.addSubnet("fe80::", 10, "ipv6");
ALWAYS_BLOCKED.addSubnet("ff00::", 8, "ipv6");

const LOOPBACK = new BlockList();
LOOPBACK.addSubnet("127.0.0.0", 8, "ipv4");
LOOPBACK.addSubnet("::1", 128, "ipv6");

const PRIVATE_NETWORKS = new BlockList();
PRIVATE_NETWORKS.addSubnet("10.0.0.0", 8, "ipv4");
PRIVATE_NETWORKS.addSubnet("172.16.0.0", 12, "ipv4");
PRIVATE_NETWORKS.addSubnet("192.168.0.0", 16, "ipv4");
PRIVATE_NETWORKS.addSubnet("100.64.0.0", 10, "ipv4");
PRIVATE_NETWORKS.addSubnet("fc00::", 7, "ipv6");

export class SSRFError extends Error {
	public constructor(message: string) {
		super(message);
		this.name = "SSRFError";
	}
}

export interface ValidatedUrl {
	originalUrl: string;
	hostname: string;
	port: number;
	path: string;
	resolvedIps: string[];
	protocol: "http:" | "https:";
}

export interface HttpResponse {
	body: Record<string, unknown>;
	headers: Record<string, string>;
}

export interface HttpResponseWithStatus extends HttpResponse {
	statusCode: number;
}

function normalizeHeaders(
	headers: IncomingHttpHeaders,
): Record<string, string> {
	const result: Record<string, string> = {};
	for (const [key, value] of Object.entries(headers)) {
		if (typeof value === "string") {
			result[key.toLowerCase()] = value;
			continue;
		}
		if (Array.isArray(value)) {
			result[key.toLowerCase()] = value.join(", ");
		}
	}
	return result;
}

export function formatIpForUrl(ip: string): string {
	return isIP(ip) === 6 ? `[${ip}]` : ip;
}

function blockListMatches(blockList: BlockList, ip: string): boolean {
	const family = isIP(ip);
	if (family === 4) {
		return blockList.check(ip, "ipv4");
	}
	if (family === 6) {
		return blockList.check(ip, "ipv6");
	}
	return false;
}

function parseEmbeddedIpv4FromMappedIpv6(ip: string): string | undefined {
	const match = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
	if (!match) {
		return undefined;
	}
	const mapped = match[1];
	if (mapped === undefined) {
		return undefined;
	}
	return isIP(mapped) === 4 ? mapped : undefined;
}

function parseEmbeddedIpv4From6to4(ip: string): string | undefined {
	const normalized = ip.toLowerCase();
	const match = normalized.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(:|$)/);
	if (!match) {
		return undefined;
	}
	const firstHex = match[1];
	const secondHex = match[2];
	if (firstHex === undefined || secondHex === undefined) {
		return undefined;
	}
	const first = Number.parseInt(firstHex, 16);
	const second = Number.parseInt(secondHex, 16);
	if (!Number.isFinite(first) || !Number.isFinite(second)) {
		return undefined;
	}
	const octets = [
		(first >> 8) & 0xff,
		first & 0xff,
		(second >> 8) & 0xff,
		second & 0xff,
	];
	return octets.join(".");
}

function parseEmbeddedIpv4FromTeredo(ip: string):
	| {
			server: string;
			client: string;
	  }
	| undefined {
	let parsed: ipaddr.IPv6;
	try {
		const addr = ipaddr.parse(ip);
		if (!(addr instanceof ipaddr.IPv6)) {
			return undefined;
		}
		parsed = addr;
	} catch {
		return undefined;
	}

	if (parsed.range() !== "teredo") {
		return undefined;
	}

	const bytes = parsed.toByteArray();
	if (bytes.length !== 16) {
		return undefined;
	}

	const server0 = bytes[4];
	const server1 = bytes[5];
	const server2 = bytes[6];
	const server3 = bytes[7];
	const client0 = bytes[12];
	const client1 = bytes[13];
	const client2 = bytes[14];
	const client3 = bytes[15];
	if (
		server0 === undefined ||
		server1 === undefined ||
		server2 === undefined ||
		server3 === undefined ||
		client0 === undefined ||
		client1 === undefined ||
		client2 === undefined ||
		client3 === undefined
	) {
		return undefined;
	}

	const server = `${server0}.${server1}.${server2}.${server3}`;
	const client = `${0xff ^ client0}.${0xff ^ client1}.${0xff ^ client2}.${0xff ^ client3}`;

	if (isIP(server) !== 4 || isIP(client) !== 4) {
		return undefined;
	}

	return { server, client };
}

function isAlwaysBlockedByRange(parsed: ipaddr.IPv4 | ipaddr.IPv6): boolean {
	const range = parsed.range();
	return (
		range === "linkLocal" ||
		range === "multicast" ||
		range === "unspecified" ||
		range === "reserved" ||
		range === "broadcast"
	);
}

function isLoopbackRange(parsed: ipaddr.IPv4 | ipaddr.IPv6): boolean {
	return parsed.range() === "loopback";
}

function isPrivateRange(parsed: ipaddr.IPv4 | ipaddr.IPv6): boolean {
	const range = parsed.range();
	return range === "private" || range === "uniqueLocal";
}

function isGloballyRoutable(parsed: ipaddr.IPv4 | ipaddr.IPv6): boolean {
	return parsed.range() === "unicast";
}

export function isIpAllowed(
	ip: string,
	options: {
		allowLocalhost?: boolean | undefined;
		allowPrivateNetworks?: boolean | undefined;
	} = {},
): boolean {
	let parsed: ipaddr.IPv4 | ipaddr.IPv6;
	try {
		parsed = ipaddr.parse(ip);
	} catch {
		return false;
	}

	if (blockListMatches(ALWAYS_BLOCKED, ip)) {
		return false;
	}

	if (isAlwaysBlockedByRange(parsed)) {
		return false;
	}

	if (parsed.kind() === "ipv6") {
		const mappedIpv4 = parseEmbeddedIpv4FromMappedIpv6(ip);
		if (mappedIpv4) {
			return isIpAllowed(mappedIpv4, options);
		}

		const sixToFourIpv4 = parseEmbeddedIpv4From6to4(ip);
		if (sixToFourIpv4) {
			return isIpAllowed(sixToFourIpv4, options);
		}

		const teredoIpv4 = parseEmbeddedIpv4FromTeredo(ip);
		if (teredoIpv4) {
			return (
				isIpAllowed(teredoIpv4.server, options) &&
				isIpAllowed(teredoIpv4.client, options)
			);
		}
	}

	if (isLoopbackRange(parsed) || blockListMatches(LOOPBACK, ip)) {
		return options.allowLocalhost ?? false;
	}

	if (isPrivateRange(parsed) || blockListMatches(PRIVATE_NETWORKS, ip)) {
		return options.allowPrivateNetworks ?? false;
	}

	if (!isGloballyRoutable(parsed)) {
		return false;
	}

	return true;
}

export async function resolveHostname(hostname: string): Promise<string[]> {
	try {
		const results = await lookup(hostname, { all: true, verbatim: true });
		const uniqueIps = Array.from(new Set(results.map((item) => item.address)));
		if (uniqueIps.length === 0) {
			throw new SSRFError(
				`DNS resolution returned no addresses for ${hostname}`,
			);
		}
		return uniqueIps;
	} catch (error) {
		if (error instanceof SSRFError) {
			throw error;
		}
		const reason =
			error instanceof Error ? error.message : "unknown DNS resolution error";
		throw new SSRFError(`DNS resolution failed for ${hostname}: ${reason}`);
	}
}

export async function validateUrl(
	url: string,
	options: {
		allowHttp?: boolean | undefined;
		allowLocalhost?: boolean | undefined;
		allowPrivateNetworks?: boolean | undefined;
	} = {},
): Promise<ValidatedUrl> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch (error) {
		const reason = error instanceof Error ? error.message : "invalid URL";
		throw new SSRFError(`Invalid URL: ${reason}`);
	}

	if (options.allowHttp) {
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
			throw new SSRFError(
				`URL must use HTTP or HTTPS, got: ${parsed.protocol}`,
			);
		}
	} else if (parsed.protocol !== "https:") {
		throw new SSRFError(`URL must use HTTPS, got: ${parsed.protocol}`);
	}

	if (!parsed.hostname) {
		throw new SSRFError("URL must have a host");
	}

	const protocol = parsed.protocol as "http:" | "https:";
	const port = parsed.port
		? Number.parseInt(parsed.port, 10)
		: protocol === "https:"
			? 443
			: 80;
	const resolvedIps = await resolveHostname(parsed.hostname);

	const blocked = resolvedIps.filter(
		(ip) =>
			!isIpAllowed(ip, {
				allowLocalhost: options.allowLocalhost ?? undefined,
				allowPrivateNetworks: options.allowPrivateNetworks ?? undefined,
			}),
	);

	if (blocked.length > 0) {
		throw new SSRFError(
			`URL resolves to blocked IP address(es): ${blocked.join(", ")}.`,
		);
	}

	return {
		originalUrl: url,
		hostname: parsed.hostname,
		port,
		path: `${parsed.pathname}${parsed.search}`,
		resolvedIps,
		protocol,
	};
}

interface PinnedFetchOptions {
	maxSize: number;
	timeoutSeconds: number;
	method?: "GET" | "POST";
	body?: string | undefined;
	extraHeaders?: Record<string, string> | undefined;
}

interface PinnedFetchOptionsWithStatus extends PinnedFetchOptions {
	allowNon2xx: true;
}

async function fetchWithPinnedIp(
	validatedUrl: ValidatedUrl,
	pinnedIp: string,
	options: PinnedFetchOptions,
): Promise<HttpResponse> {
	const requestFn =
		validatedUrl.protocol === "https:" ? httpsRequest : httpRequest;
	const url = `${validatedUrl.protocol}//${formatIpForUrl(pinnedIp)}:${validatedUrl.port}${validatedUrl.path}`;
	const method = options.method ?? "GET";

	const headers: Record<string, string> = {
		Host: validatedUrl.hostname,
		...options.extraHeaders,
	};
	if (options.body !== undefined) {
		headers["Content-Length"] = Buffer.byteLength(
			options.body,
			"utf-8",
		).toString();
	}

	return await new Promise<HttpResponse>((resolve, reject) => {
		const req = requestFn(
			url,
			{
				method,
				headers,
				...(validatedUrl.protocol === "https:"
					? {
							rejectUnauthorized: true,
							servername: validatedUrl.hostname,
						}
					: {}),
			},
			(res) => {
				const statusCode = res.statusCode ?? 0;
				if (statusCode >= 300 && statusCode < 400) {
					reject(
						new SSRFError(
							`Redirects are not allowed for SSRF-safe fetches (${statusCode}).`,
						),
					);
					req.destroy();
					return;
				}

				if (statusCode < 200 || statusCode >= 300) {
					reject(new Error(`HTTP request failed with status ${statusCode}`));
					req.destroy();
					return;
				}

				const contentLengthHeader = res.headers["content-length"];
				if (typeof contentLengthHeader === "string") {
					const contentLength = Number.parseInt(contentLengthHeader, 10);
					if (
						Number.isFinite(contentLength) &&
						contentLength > options.maxSize
					) {
						reject(
							new SSRFError(
								`Response too large: ${contentLength} bytes (max ${options.maxSize}).`,
							),
						);
						req.destroy();
						return;
					}
				}

				const chunks: Buffer[] = [];
				let totalSize = 0;
				res.on("data", (chunk: Buffer) => {
					totalSize += chunk.length;
					if (totalSize > options.maxSize) {
						reject(
							new SSRFError(
								`Response too large: streaming exceeded ${options.maxSize} bytes limit.`,
							),
						);
						req.destroy();
						return;
					}
					chunks.push(chunk);
				});

				res.on("end", () => {
					try {
						const text = Buffer.concat(chunks).toString("utf-8");
						const parsed = JSON.parse(text) as Record<string, unknown>;
						resolve({ body: parsed, headers: normalizeHeaders(res.headers) });
					} catch (error) {
						const reason =
							error instanceof Error ? error.message : "invalid JSON";
						reject(new Error(`Failed to parse JSON response: ${reason}`));
					}
				});
			},
		);

		req.on("error", reject);
		req.setTimeout(options.timeoutSeconds * 1000, () => {
			req.destroy(new Error("Request timeout"));
		});
		if (options.body !== undefined) {
			req.write(options.body);
		}
		req.end();
	});
}

async function fetchWithPinnedIpWithStatus(
	validatedUrl: ValidatedUrl,
	pinnedIp: string,
	options: PinnedFetchOptionsWithStatus,
): Promise<HttpResponseWithStatus> {
	const requestFn =
		validatedUrl.protocol === "https:" ? httpsRequest : httpRequest;
	const url = `${validatedUrl.protocol}//${formatIpForUrl(pinnedIp)}:${validatedUrl.port}${validatedUrl.path}`;
	const method = options.method ?? "GET";

	const headers: Record<string, string> = {
		Host: validatedUrl.hostname,
		...options.extraHeaders,
	};
	if (options.body !== undefined) {
		headers["Content-Length"] = Buffer.byteLength(
			options.body,
			"utf-8",
		).toString();
	}

	return await new Promise<HttpResponseWithStatus>((resolve, reject) => {
		const req = requestFn(
			url,
			{
				method,
				headers,
				...(validatedUrl.protocol === "https:"
					? {
							rejectUnauthorized: true,
							servername: validatedUrl.hostname,
						}
					: {}),
			},
			(res) => {
				const statusCode = res.statusCode ?? 0;
				if (statusCode >= 300 && statusCode < 400) {
					reject(
						new SSRFError(
							`Redirects are not allowed for SSRF-safe fetches (${statusCode}).`,
						),
					);
					req.destroy();
					return;
				}

				const contentLengthHeader = res.headers["content-length"];
				if (typeof contentLengthHeader === "string") {
					const contentLength = Number.parseInt(contentLengthHeader, 10);
					if (
						Number.isFinite(contentLength) &&
						contentLength > options.maxSize
					) {
						reject(
							new SSRFError(
								`Response too large: ${contentLength} bytes (max ${options.maxSize}).`,
							),
						);
						req.destroy();
						return;
					}
				}

				const chunks: Buffer[] = [];
				let totalSize = 0;
				res.on("data", (chunk: Buffer) => {
					totalSize += chunk.length;
					if (totalSize > options.maxSize) {
						reject(
							new SSRFError(
								`Response too large: streaming exceeded ${options.maxSize} bytes limit.`,
							),
						);
						req.destroy();
						return;
					}
					chunks.push(chunk);
				});

				res.on("end", () => {
					try {
						const text = Buffer.concat(chunks).toString("utf-8");
						const parsed = JSON.parse(text) as Record<string, unknown>;
						resolve({
							statusCode,
							body: parsed,
							headers: normalizeHeaders(res.headers),
						});
					} catch (error) {
						const reason =
							error instanceof Error ? error.message : "invalid JSON";
						reject(new Error(`Failed to parse JSON response: ${reason}`));
					}
				});
			},
		);

		req.on("error", reject);
		req.setTimeout(options.timeoutSeconds * 1000, () => {
			req.destroy(new Error("Request timeout"));
		});
		if (options.body !== undefined) {
			req.write(options.body);
		}
		req.end();
	});
}

export async function ssrfSafeFetch(
	url: string,
	options: {
		allowHttp?: boolean;
		allowLocalhost?: boolean;
		allowPrivateNetworks?: boolean;
		maxSize?: number;
		timeoutSeconds?: number;
	} = {},
): Promise<HttpResponse> {
	const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
	const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;

	const validatedUrl = await validateUrl(url, {
		allowHttp: options.allowHttp,
		allowLocalhost: options.allowLocalhost,
		allowPrivateNetworks: options.allowPrivateNetworks,
	});

	let lastError: Error | undefined;
	for (const ip of validatedUrl.resolvedIps) {
		try {
			return await fetchWithPinnedIp(validatedUrl, ip, {
				maxSize,
				timeoutSeconds,
			});
		} catch (error) {
			lastError = error instanceof Error ? error : new Error(String(error));
		}
	}

	throw lastError ?? new SSRFError(`Failed to fetch ${url}.`);
}

export async function ssrfSafePost(
	url: string,
	options: {
		formData?:
			| Record<string, string>
			| ReadonlyArray<[string, string]>
			| URLSearchParams
			| undefined;
		extraHeaders?: Record<string, string> | undefined;
		allowHttp?: boolean | undefined;
		allowLocalhost?: boolean | undefined;
		allowPrivateNetworks?: boolean | undefined;
		maxSize?: number | undefined;
		timeoutSeconds?: number | undefined;
	} = {},
): Promise<HttpResponse> {
	const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
	const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;

	const validatedUrl = await validateUrl(url, {
		allowHttp: options.allowHttp,
		allowLocalhost: options.allowLocalhost,
		allowPrivateNetworks: options.allowPrivateNetworks,
	});

	const body = options.formData
		? options.formData instanceof URLSearchParams
			? options.formData.toString()
			: Array.isArray(options.formData)
				? new URLSearchParams(Array.from(options.formData)).toString()
				: new URLSearchParams(
						options.formData as Record<string, string>,
					).toString()
		: undefined;
	const extraHeaders: Record<string, string> = {
		Accept: "application/json",
		...options.extraHeaders,
	};
	if (body !== undefined) {
		extraHeaders["Content-Type"] = "application/x-www-form-urlencoded";
	}

	let lastError: Error | undefined;
	for (const ip of validatedUrl.resolvedIps) {
		try {
			return await fetchWithPinnedIp(validatedUrl, ip, {
				maxSize,
				timeoutSeconds,
				method: "POST",
				body,
				extraHeaders,
			});
		} catch (error) {
			lastError = error instanceof Error ? error : new Error(String(error));
		}
	}

	throw lastError ?? new SSRFError(`Failed to POST to ${url}.`);
}

export async function ssrfSafePostWithStatus(
	url: string,
	options: {
		formData?:
			| Record<string, string>
			| ReadonlyArray<[string, string]>
			| URLSearchParams
			| undefined;
		extraHeaders?: Record<string, string> | undefined;
		allowHttp?: boolean | undefined;
		allowLocalhost?: boolean | undefined;
		allowPrivateNetworks?: boolean | undefined;
		maxSize?: number | undefined;
		timeoutSeconds?: number | undefined;
	} = {},
): Promise<HttpResponseWithStatus> {
	const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
	const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;

	const validatedUrl = await validateUrl(url, {
		allowHttp: options.allowHttp,
		allowLocalhost: options.allowLocalhost,
		allowPrivateNetworks: options.allowPrivateNetworks,
	});

	const body = options.formData
		? options.formData instanceof URLSearchParams
			? options.formData.toString()
			: Array.isArray(options.formData)
				? new URLSearchParams(Array.from(options.formData)).toString()
				: new URLSearchParams(
						options.formData as Record<string, string>,
					).toString()
		: undefined;
	const extraHeaders: Record<string, string> = {
		Accept: "application/json",
		...options.extraHeaders,
	};
	if (body !== undefined) {
		extraHeaders["Content-Type"] = "application/x-www-form-urlencoded";
	}

	let lastError: Error | undefined;
	for (const ip of validatedUrl.resolvedIps) {
		try {
			return await fetchWithPinnedIpWithStatus(validatedUrl, ip, {
				allowNon2xx: true,
				maxSize,
				timeoutSeconds,
				method: "POST",
				body,
				extraHeaders,
			});
		} catch (error) {
			lastError = error instanceof Error ? error : new Error(String(error));
		}
	}

	throw lastError ?? new SSRFError(`Failed to POST to ${url}.`);
}
