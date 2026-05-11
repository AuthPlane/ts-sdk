import {
	AuthError,
	InvalidClientError,
	UnauthorizedClientError,
} from "../auth/errors.js";
import { SSRFError } from "./fetching/ssrf.js";

/** OAuth `error` codes where the AS responded correctly — do not trip the breaker. */
const OAUTH_ERRORS_NO_CIRCUIT = new Set([
	"consent_required",
	"interaction_required",
	"invalid_grant",
	"invalid_scope",
	"invalid_dpop_proof",
	"invalid_request",
	"unsupported_grant_type",
]);

/**
 * Whether an exception from token/revoke/exchange should count as a circuit
 * failure (Python `AuthplaneClient._handle_failure` semantics, extended for
 * OAuth 4xx vs misconfiguration).
 */
export function shouldTripCircuit(error: unknown): boolean {
	if (error instanceof SSRFError) {
		return false;
	}

	if (!(error instanceof AuthError)) {
		return true;
	}

	if (error.statusCode !== null && error.statusCode >= 500) {
		return true;
	}

	if (
		error instanceof InvalidClientError ||
		error instanceof UnauthorizedClientError
	) {
		return true;
	}

	if (OAUTH_ERRORS_NO_CIRCUIT.has(error.code)) {
		return false;
	}

	if (error.statusCode !== null && error.statusCode < 500) {
		return false;
	}

	return true;
}
