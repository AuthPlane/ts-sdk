export interface FetchResult<TDocument extends Record<string, unknown>> {
	document: TDocument;
	expiresAt: number | undefined;
}
