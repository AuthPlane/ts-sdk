import {
	JWKSFetchError,
	MetadataFetchError,
	MissingMetadataEndpoint,
} from "../errors.js";
import type { FetchResult } from "./fetchResult.js";

/**
 * `forceUpstream` is set when the caller could not be satisfied from cache and
 * a stale upstream answer would therefore be wrong — a JWKS `kid` miss is the
 * case that matters, since the URI to fetch from is itself read from another
 * cache. A proactive background refresh does not set it.
 */
type Fetcher<TDocument extends Record<string, unknown>> = (
	forceUpstream: boolean,
) => Promise<FetchResult<TDocument>>;

export class DocumentCache<TDocument extends Record<string, unknown>> {
	/**
	 * Default minimum interval between fetch attempts after a failed one.
	 * Shared across the SDKs: the effective floor is
	 * `max(1, min(failureBackoffSeconds, refreshSeconds))` — the `min` so a
	 * cache asked to refresh every 5 seconds is not pinned to a 30-second
	 * retry floor, the `max` so the floor never collapses to zero and an
	 * unreachable upstream cannot be re-attempted on every call.
	 * `refreshSeconds: 0` ("re-read every time") opts out of the floor
	 * entirely, consistent with the forced-read floor in
	 * `MetadataCache.admitForcedRead()`.
	 */
	private static readonly DEFAULT_FAILURE_BACKOFF_SECONDS = 30;

	private readonly fetcher: Fetcher<TDocument>;
	private readonly refreshSeconds: number;
	private readonly failureBackoffSeconds: number;
	private readonly errorFactory: (message: string) => Error;
	/** "JWKS" or "metadata" — for log messages. */
	private readonly documentType: string;

	private cache: TDocument | undefined;
	private cacheTimeSeconds = 0;
	private serverExpiresAt: number | undefined;
	private lastFailureSeconds: number | undefined;
	private lastFailureError: unknown;
	private failureFloorWarned = false;
	private fetchInFlight: Promise<TDocument> | undefined;
	private fetchInFlightForced = false;
	private refreshInFlight: Promise<void> | undefined;
	// Two fetches run concurrently by design: a forced caller deliberately does
	// not join a non-forced fetch already in flight. `startedSequence` orders
	// them by start; `committedSequence` records the newest that has reached the
	// cache, so a slower earlier fetch cannot overwrite a newer document.
	private startedSequence = 0;
	private committedSequence = 0;

	public constructor(
		fetcher: Fetcher<TDocument>,
		options: {
			refreshSeconds: number;
			failureBackoffSeconds?: number | undefined;
			errorFactory?: (message: string) => Error;
			documentType?: string;
		},
	) {
		this.fetcher = fetcher;
		this.refreshSeconds = options.refreshSeconds;
		// Non-finite values fall back to the default rather than into the clamp:
		// `min`/`max` propagate `NaN`, and a `NaN` floor compares false in the
		// refusal check — the unbounded retry behaviour this floor exists to
		// prevent, reachable from `Number(process.env.X)` on an unset variable.
		const requestedBackoff =
			options.failureBackoffSeconds ??
			DocumentCache.DEFAULT_FAILURE_BACKOFF_SECONDS;
		const backoff = Number.isFinite(requestedBackoff)
			? requestedBackoff
			: DocumentCache.DEFAULT_FAILURE_BACKOFF_SECONDS;
		const refresh = Number.isFinite(options.refreshSeconds)
			? options.refreshSeconds
			: Number.POSITIVE_INFINITY;
		// `refreshSeconds: 0` means "re-read every time" and opts out of the
		// failure floor the same way it opts out of the forced-read floor in
		// `admitForcedRead()` — clamping it to 1 would quietly give the opt-out
		// a floor the docs say it does not have.
		this.failureBackoffSeconds =
			refresh <= 0 ? 0 : Math.max(1, Math.min(backoff, refresh));
		this.errorFactory =
			options.errorFactory ?? ((message) => new JWKSFetchError(message));
		this.documentType = options.documentType ?? "Document";
	}

	private effectiveExpiresAt(): number {
		const localExpiry = this.cacheTimeSeconds + this.refreshSeconds;
		// A server expiry at or before the moment the document was cached is no
		// preference at all, not a shorter TTL: `Cache-Control: max-age=0` and an
		// `Expires:` header already in the past both arrive here as a zero or
		// negative TTL, and mining either into the local expiry leaves the
		// document expired on every read. `get()` then takes the synchronous
		// re-fetch path on every call — and this cache is read on the verification
		// path, before any signature is checked, so an unauthenticated caller
		// drives one upstream fetch per request. Ignored here so the configured
		// interval governs. `no-store` / `no-cache` never reach this: they carry no
		// `max-age`, so the header parser reports no server expiry at all.
		if (
			this.serverExpiresAt === undefined ||
			this.serverExpiresAt <= this.cacheTimeSeconds
		) {
			return localExpiry;
		}
		return Math.min(localExpiry, this.serverExpiresAt);
	}

	private shouldRefreshInBackground(nowSeconds: number): boolean {
		if (!this.cache) {
			return false;
		}
		const expiry = this.effectiveExpiresAt();
		const ttl = expiry - this.cacheTimeSeconds;
		if (ttl <= 0) {
			return false;
		}
		return nowSeconds - this.cacheTimeSeconds >= ttl * 0.8;
	}

	private triggerBackgroundRefresh(): void {
		if (this.refreshInFlight) {
			return;
		}
		// Bypasses this cache's TTL but not the upstream one: a proactive refresh
		// is not evidence that anything upstream is stale.
		this.refreshInFlight = this.fetchAndUpdate(false)
			.then(() => {})
			.catch(() => {})
			.finally(() => {
				this.refreshInFlight = undefined;
			});
	}

	private failureFloorRemainingSeconds(): number {
		if (this.lastFailureSeconds === undefined) {
			return 0;
		}
		return (
			this.failureBackoffSeconds -
			(Math.floor(Date.now() / 1000) - this.lastFailureSeconds)
		);
	}

	/**
	 * True while the failure floor holds — no fetch attempt can start before it
	 * elapses. Exposed to subclasses so a budget stamped ahead of an attempt
	 * (`MetadataCache.admitForcedRead()`) is not spent on a read the floor is
	 * going to refuse anyway.
	 */
	protected isWithinFailureFloor(): boolean {
		return this.failureFloorRemainingSeconds() > 0;
	}

	/**
	 * Applied to a freshly fetched document before it is committed to the cache.
	 * A subclass that throws here leaves the previously cached document in place,
	 * so nothing downstream can read a document that failed validation — not even
	 * transiently. The default accepts every document.
	 */
	protected validateDocument(document: TDocument): TDocument {
		return document;
	}

	private async fetchAndUpdate(forceUpstream: boolean): Promise<TDocument> {
		// Join an in-flight fetch only when it is at least as forceful as this one.
		// A forced caller must not inherit the answer of a fetch that was allowed
		// to resolve its URI from a stale upstream cache.
		if (this.fetchInFlight && (this.fetchInFlightForced || !forceUpstream)) {
			return this.fetchInFlight;
		}

		// Retry floor: after a failed attempt, refuse to reach upstream again
		// before `failureBackoffSeconds` have passed. Without it, an unreachable
		// upstream turns into per-request latency amplification once the refresh
		// interval elapses — every wave of traffic pays the fetch timeout again,
		// with no backoff between waves (`fetchInFlight` dedupes within a wave,
		// not across them). Applies to forced reads too: the caller that forces is
		// a JWKS `kid` miss, and hammering an upstream that just failed does not
		// make the key appear. Refusing rethrows the failure that started the
		// window, so `get()` serves the last known good document when one exists
		// and fails fast — same typed error, no network wait — when none does.
		const floorRemaining = this.failureFloorRemainingSeconds();
		if (floorRemaining > 0) {
			// One warning per floor window, not per refusal: an operator needs to
			// tell a backoff from a live outage, but under per-request traffic the
			// refusals are exactly what the floor makes cheap.
			if (!this.failureFloorWarned) {
				this.failureFloorWarned = true;
				console.warn(
					`[authplane] ${this.documentType} refresh backing off after a failed attempt (retry in ${floorRemaining}s).`,
				);
			}
			// The retained instance itself, deliberately shared across every
			// refusal in the window: it is the error the suppressed attempt
			// produced, complete with its original stack. Rebuilding it per
			// caller costs more than the sharing does — a descriptor-copying
			// clone has no `[[ErrorData]]` slot, so its `stack` reads
			// `undefined` and it fails `isNativeError`, while `errorFactory`
			// would relabel a metadata failure surfacing through the JWKS
			// cache — and callers do not own errors they catch.
			throw this.lastFailureError;
		}

		const sequence = ++this.startedSequence;
		const pending = (async () => {
			let result: FetchResult<TDocument>;
			let document: TDocument;
			try {
				result = await this.fetcher(forceUpstream);
				// Validate before committing, not after reading. `this.cache` is what
				// every reader sees — including `jwks_uri` resolution — so validating
				// on the way out would let a rejected document decide where keys come
				// from.
				document = this.validateDocument(result.document);
			} catch (error) {
				// A rejected document opens the floor exactly like an unreachable
				// upstream: both would otherwise be re-attempted on every call, and
				// the retained error keeps refusals indistinguishable from the
				// attempt they suppress. Guarded by the mirror of the success
				// sequence check below: a failure that has already been superseded —
				// a newer fetch committed while this one was in flight — proves
				// nothing about the upstream now, and stamping it would open a floor
				// against an upstream that demonstrably just answered.
				if (sequence > this.committedSequence) {
					this.lastFailureSeconds = Math.floor(Date.now() / 1000);
					this.lastFailureError = error;
					this.failureFloorWarned = false;
				}
				throw error;
			}
			// Any successful attempt closes the floor — the upstream answered, so
			// the next expiry may reach it again — including a superseded one,
			// which proves reachability even though its document is discarded.
			this.lastFailureSeconds = undefined;
			this.lastFailureError = undefined;
			// Commit only if nothing newer has. Fetches can land out of order —
			// a background refresh started before a rotation can return after a
			// forced read that observed it — and an unconditional write is
			// last-writer-wins, which would put the withdrawn `jwks_uri` back for
			// the rest of the interval. Ordered by start rather than by
			// forcefulness. Start order is an approximation of "which fetch saw the
			// more recent upstream state", not that property: an earlier-started
			// fetch the AS happens to serve later saw newer state and is still
			// discarded. Without a server-side version there is no better signal,
			// and the cost is bounded — the older document stands until the next
			// interval or forced read, rather than a withdrawn URI standing in
			// place of a current one.
			if (sequence > this.committedSequence) {
				this.committedSequence = sequence;
				this.cache = document;
				this.cacheTimeSeconds = Math.floor(Date.now() / 1000);
				this.serverExpiresAt = result.expiresAt;
				return document;
			}
			// Superseded: hand back what the cache holds rather than this stale
			// answer, so the caller and the cache cannot disagree either.
			return this.cache ?? document;
		})();

		this.fetchInFlight = pending;
		this.fetchInFlightForced = forceUpstream;

		try {
			return await pending;
		} finally {
			// Only the owner clears. A concurrent fetch that started later owns the
			// fields by then, and tearing its dedupe state down would let the next
			// caller start a duplicate upstream fetch instead of joining it.
			if (this.fetchInFlight === pending) {
				this.fetchInFlight = undefined;
				this.fetchInFlightForced = false;
			}
		}
	}

	public async get(forceRefresh = false): Promise<TDocument> {
		const now = Math.floor(Date.now() / 1000);
		const hasValidCache =
			this.cache !== undefined && now < this.effectiveExpiresAt();

		if (!forceRefresh && hasValidCache) {
			if (this.shouldRefreshInBackground(now)) {
				this.triggerBackgroundRefresh();
			}
			return this.cache as TDocument;
		}

		try {
			return await this.fetchAndUpdate(forceRefresh);
		} catch (error) {
			if (this.cache !== undefined) {
				return this.cache;
			}
			// Already one of the SDK's typed fetch errors: keep it. The JWKS fetcher
			// resolves its URI through the metadata cache, so a metadata failure can
			// surface here — relabelling it `JWKSFetchError` would point the operator
			// at the wrong document. A validation rejection is likewise not a fetch
			// failure and reads better without the prefix.
			if (
				error instanceof MetadataFetchError ||
				error instanceof MissingMetadataEndpoint
			) {
				throw error;
			}
			const message = error instanceof Error ? error.message : String(error);
			throw this.errorFactory(`Failed to fetch document: ${message}`);
		}
	}

	public async close(): Promise<void> {
		if (this.refreshInFlight) {
			await this.refreshInFlight.catch(() => {});
		}
	}
}

export interface Jwk extends Record<string, unknown> {
	[key: string]: unknown;
}

export interface JwksDocument extends Record<string, unknown> {
	[key: string]: unknown;
	keys: Jwk[];
}

export class JWKSCache extends DocumentCache<JwksDocument> {
	public constructor(
		fetcher: Fetcher<JwksDocument>,
		refreshSeconds: number,
		failureBackoffSeconds?: number | undefined,
	) {
		super(fetcher, {
			refreshSeconds,
			failureBackoffSeconds,
			errorFactory: (message) => new JWKSFetchError(message),
			documentType: "JWKS",
		});
	}

	private static isKeyUsableForVerification(
		key: Jwk,
		kid: string,
		algorithm: string | undefined,
	): boolean {
		if (key.kid !== kid) {
			return false;
		}
		// RFC 7517 §4.2: `use` restricts the key's purpose. Only `sig` is valid
		// for signature verification; absence means no restriction.
		const use = key.use;
		if (typeof use === "string" && use !== "sig") {
			return false;
		}
		// RFC 7517 §4.3: `key_ops` is a list of permitted operations. If
		// present, verification requires `verify` in the list.
		const keyOps = key.key_ops;
		if (Array.isArray(keyOps) && !keyOps.includes("verify")) {
			return false;
		}
		// RFC 7517 §4.4: `alg` when present pins the key to a single algorithm.
		const jwkAlg = key.alg;
		if (
			algorithm !== undefined &&
			typeof jwkAlg === "string" &&
			jwkAlg !== algorithm
		) {
			return false;
		}
		return true;
	}

	public async containsKid(
		kid: string,
		forceRefresh = false,
		algorithm?: string,
	): Promise<boolean> {
		const jwks = await this.get(forceRefresh);
		return jwks.keys.some((key) =>
			JWKSCache.isKeyUsableForVerification(key, kid, algorithm),
		);
	}

	public async getKeyByKid(
		kid: string,
		forceRefresh = false,
		algorithm?: string,
	): Promise<Jwk | undefined> {
		const jwks = await this.get(forceRefresh);
		return jwks.keys.find((key) =>
			JWKSCache.isKeyUsableForVerification(key, kid, algorithm),
		);
	}
}

export class MetadataCache extends DocumentCache<Record<string, unknown>> {
	private readonly expectedIssuer: string;
	private readonly allowHttp: boolean;
	/**
	 * Ceiling on how far apart forced metadata reads can be spaced. The floor
	 * itself is `min(refreshSeconds, this)`, so a deployment that asks for
	 * fresher metadata than a minute still gets it.
	 */
	private static readonly FORCED_READ_FLOOR_CEILING_SECONDS = 60;
	private readonly forcedReadFloorSeconds: number;
	private lastForcedReadSeconds: number | undefined;
	private static readonly VALIDATED_ENDPOINT_FIELDS = [
		"jwks_uri",
		"token_endpoint",
		"introspection_endpoint",
		"revocation_endpoint",
	] as const;

	public constructor(
		fetcher: Fetcher<Record<string, unknown>>,
		options: {
			refreshSeconds: number;
			failureBackoffSeconds?: number | undefined;
			expectedIssuer?: string;
			allowHttp?: boolean;
		},
	) {
		super(fetcher, {
			refreshSeconds: options.refreshSeconds,
			failureBackoffSeconds: options.failureBackoffSeconds,
			errorFactory: (message) => new MetadataFetchError(message),
			documentType: "metadata",
		});

		// RFC 8414 §3.3: the issuer is compared for identity. Keep the expected
		// value verbatim so the comparison in `validateMetadata` is byte-for-byte;
		// a trailing-slash difference must surface as a mismatch, not be reconciled.
		this.expectedIssuer = options.expectedIssuer ?? "";
		this.allowHttp = options.allowHttp ?? false;
		this.forcedReadFloorSeconds = Math.min(
			options.refreshSeconds,
			MetadataCache.FORCED_READ_FLOOR_CEILING_SECONDS,
		);
	}

	/**
	 * A forced read bypasses `refreshSeconds`, so on its own it is no rate limit.
	 * The caller that reaches it is a JWKS `kid` miss, and nothing upstream of
	 * that has authenticated anything — `verify()` has only decoded the header —
	 * so a well-formed header carrying an attacker-chosen `kid` would otherwise
	 * cost the AS one discovery fetch per request, unthrottled, on top of the
	 * pre-existing JWKS fetch.
	 *
	 * The floor caps that at one forced read per interval while still following a
	 * real rotation promptly: the first miss after the floor elapses re-reads
	 * immediately. Refusing only downgrades the read to an ordinary one, which
	 * still serves a valid cached document or refetches an expired one.
	 *
	 * A floor of zero (`refreshSeconds: 0`, meaning "re-read every time") opts
	 * out, which is what the rotation conformance cases configure.
	 */
	private admitForcedRead(): boolean {
		if (this.forcedReadFloorSeconds <= 0) {
			return true;
		}
		const now = Math.floor(Date.now() / 1000);
		if (
			this.lastForcedReadSeconds !== undefined &&
			now - this.lastForcedReadSeconds < this.forcedReadFloorSeconds
		) {
			return false;
		}
		this.lastForcedReadSeconds = now;
		return true;
	}

	public override async get(
		forceRefresh = false,
	): Promise<Record<string, unknown>> {
		// The failure floor is consulted before the budget is spent: a read the
		// floor refuses sends nothing upstream, and the budget exists solely to
		// cap what an attacker-chosen `kid` can make the SDK ask of the AS.
		// Burning it on a refusal would downgrade the first miss after the floor
		// elapses — exactly the read that follows a rotation — to an ordinary
		// one, serving the withdrawn document.
		return super.get(
			forceRefresh && !this.isWithinFailureFloor() && this.admitForcedRead(),
		);
	}

	private validateEndpointUrl(field: string, value: string): void {
		let parsed: URL;
		try {
			parsed = new URL(value);
		} catch {
			throw new MetadataFetchError(
				`AS metadata field '${field}' is not an absolute URL: '${value}'`,
			);
		}
		if (!parsed.host) {
			throw new MetadataFetchError(
				`AS metadata field '${field}' is not an absolute URL: '${value}'`,
			);
		}
		if (!this.allowHttp && parsed.protocol !== "https:") {
			throw new MetadataFetchError(
				`AS metadata field '${field}' must use HTTPS, got '${parsed.protocol.replace(/:$/, "")}': '${value}'`,
			);
		}
	}

	protected override validateDocument(
		metadata: Record<string, unknown>,
	): Record<string, unknown> {
		// RFC 8414 §3.3: compare the raw issuer identifier for exact equality.
		// Do NOT strip a trailing slash — a document whose issuer differs from the
		// expected identifier only by a trailing slash is a different identity and
		// must be rejected.
		const issuer = typeof metadata.issuer === "string" ? metadata.issuer : "";
		if (!issuer) {
			throw new MetadataFetchError(
				"AS metadata missing required 'issuer' field.",
			);
		}
		if (this.expectedIssuer && issuer !== this.expectedIssuer) {
			throw new MetadataFetchError(
				`AS metadata issuer mismatch: expected '${this.expectedIssuer}', got '${issuer}'.`,
			);
		}
		for (const field of MetadataCache.VALIDATED_ENDPOINT_FIELDS) {
			const value = metadata[field];
			if (typeof value === "string" && value.length > 0) {
				this.validateEndpointUrl(field, value);
			}
		}
		return metadata;
	}

	public async getJwksUri(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const jwksUri = metadata.jwks_uri;
		if (typeof jwksUri !== "string" || jwksUri.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'jwks_uri' field.",
			);
		}
		return jwksUri;
	}

	public async getTokenEndpoint(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const tokenEndpoint = metadata.token_endpoint;
		if (typeof tokenEndpoint !== "string" || tokenEndpoint.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'token_endpoint' field.",
			);
		}
		return tokenEndpoint;
	}

	public async getRevocationEndpoint(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const endpoint = metadata.revocation_endpoint;
		if (typeof endpoint !== "string" || endpoint.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'revocation_endpoint' field.",
			);
		}
		return endpoint;
	}

	public async getIntrospectionEndpoint(forceRefresh = false): Promise<string> {
		const metadata = await this.get(forceRefresh);
		const endpoint = metadata.introspection_endpoint;
		if (typeof endpoint !== "string" || endpoint.length === 0) {
			throw new MissingMetadataEndpoint(
				"Authorization Server metadata is missing required 'introspection_endpoint' field.",
			);
		}
		return endpoint;
	}
}
