# @authplane/fastmcp

[Authplane](https://github.com/AuthPlane/authserver) JWT validation adapter for [FastMCP](https://github.com/punkpeye/fastmcp). Bearer-token auth on your FastMCP server in a few lines.

## Install

```bash
npm install @authplane/sdk @authplane/fastmcp fastmcp zod
```

Requires Node.js 20 LTS or newer.

## Quickstart

```ts
import { FastMCP, requireScopes } from "fastmcp";
import { authplaneFastMcpAuth, type AuthplaneFastMcpSession } from "@authplane/fastmcp";
import { z } from "zod";

const auth = await authplaneFastMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://mcp.example.com/mcp",
  scopes: ["tools/get_weather"],
});

const server = new FastMCP<AuthplaneFastMcpSession>({
  name: "weather",
  version: "1.0.0",
  authenticate: auth.authenticate,
  oauth: auth.oauth,
});

server.addTool({
  name: "get_weather",
  parameters: z.object({ city: z.string() }),
  canAccess: requireScopes("tools/get_weather"),
  execute: async ({ city }) => ({ content: [{ type: "text", text: `${city}: sunny` }] }),
});

await server.start({ transportType: "httpStream", httpStream: { port: 8090, endpoint: "/mcp" } });
```

`auth.authenticate` validates the bearer token and exposes a typed session; `auth.oauth` publishes the RFC 9728 Protected Resource Metadata automatically.

## Local development

The default `FetchSettings` reject plaintext `http://` issuers (SSRF protection). When pointing the adapter at a local authserver — typically `http://localhost:9000` — pass `devMode: true` to relax the network policy:

```ts
const auth = await authplaneFastMcpAuth({
  issuer: "http://localhost:9000",
  resource: "http://localhost:8090/mcp",
  scopes: ["tools/get_weather"],
  devMode: true,
});
```

> **Warning:** Never set `devMode: true` in production — it disables SSRF protection entirely.

`devMode: true` is shorthand for `fetchSettings: new FetchSettings({ ssrfProtection: false, allowHttp: true, allowLocalhost: true, allowPrivateNetworks: true })`. If you need finer control (e.g. allow loopback but keep HTTPS-only), construct a `FetchSettings` directly and pass it as `fetchSettings`:

```ts
import { FetchSettings } from "@authplane/fastmcp";
```

Without one of these, metadata discovery against an `http://` issuer fails with `MetadataFetchError: URL must use HTTPS`.

## Compatibility

Tested against **`fastmcp@^3.35.0`** (verified on `3.35.x` and `4.0.1`).

If you configure `inboundDPoP` in any mode (Required *or* Supported — every accepted DPoP-bound request goes through the replay store), note that the adapter relies on a per-request verification cache to accommodate FastMCP's current `authenticate` invocation pattern: FastMCP calls the callback twice per HTTP request (once at the request gate, once when building the session payload), but RFC 9449 inbound replay verification can only run once per proof. The cache uses Node's [`AsyncLocalStorage`](https://nodejs.org/api/async_context.html#class-asynclocalstorage) scoped to the request's async context (see [`src/auth.ts`](src/auth.ts)): both invocations within the same HTTP request share the in-flight `verifyAccessToken` promise, and different requests carry distinct async contexts so cross-request leakage is structurally impossible. If a future FastMCP version moves the second `authenticate` invocation to a callsite that loses async-context propagation, you may observe `DPoPReplayDetected` errors on previously-working flows — please [file an issue](https://github.com/AuthPlane/ts-sdk/issues).

## Learn more

- **[User Guide](docs/user-guide.md)** — complete reference: options, session shape, scope enforcement, URL elicitation for consent, introspection, DPoP, error handling, advanced configuration.
- **[`@authplane/sdk`](../sdk)** — the underlying OAuth/JWT primitives.

On shutdown call `await auth.client.close()` to stop internal refresh timers.
