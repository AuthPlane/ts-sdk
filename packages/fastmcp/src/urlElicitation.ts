import { randomUUID } from "node:crypto";
import { UrlElicitationRequiredError } from "@modelcontextprotocol/sdk/types.js";
import { ConsentRequiredError } from "@authplane/sdk/core";

/**
 * Maps a `ConsentRequiredError` with a `consentUrl` to an MCP
 * `UrlElicitationRequiredError` (-32042). Returns `null` for any
 * other error or when `consentUrl` is absent.
 */
export function toUrlElicitationRequiredError(
	error: unknown,
	options?: { createElicitationId?: () => string },
): UrlElicitationRequiredError | null {
	if (!(error instanceof ConsentRequiredError) || !error.consentUrl) {
		return null;
	}
	const elicitationId = options?.createElicitationId?.() ?? randomUUID();
	return new UrlElicitationRequiredError(
		[
			{
				mode: "url",
				url: error.consentUrl,
				elicitationId,
				message: error.describe(),
			},
		],
		error.message,
	);
}
