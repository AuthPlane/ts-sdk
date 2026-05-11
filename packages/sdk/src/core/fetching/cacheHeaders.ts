function parseCacheControlMaxAge(cacheControl: string): number | undefined {
	const parts = cacheControl
		.split(",")
		.map((part) => part.trim().toLowerCase());
	for (const part of parts) {
		if (!part.startsWith("max-age=")) {
			continue;
		}
		const value = Number.parseInt(part.slice("max-age=".length), 10);
		if (Number.isFinite(value) && value >= 0) {
			return value;
		}
	}
	return undefined;
}

export function parseExpiresAt(
	headers: Record<string, string>,
): number | undefined {
	const cacheControl = headers["cache-control"];
	if (cacheControl) {
		const maxAge = parseCacheControlMaxAge(cacheControl);
		if (maxAge !== undefined) {
			return Math.floor(Date.now() / 1000) + maxAge;
		}
	}

	const expires = headers.expires;
	if (expires) {
		const asDate = new Date(expires);
		if (!Number.isNaN(asDate.getTime())) {
			return Math.floor(asDate.getTime() / 1000);
		}
	}

	return undefined;
}
