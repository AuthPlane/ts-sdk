# @authplane/mcp

[Authplane](https://github.com/AuthPlane/authserver) JWT validation adapter for the official [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk). Bearer-token auth on your MCP server in a few lines.

## Install

```bash
npm install @authplane/sdk @authplane/mcp @modelcontextprotocol/sdk express zod
```

Requires Node.js 20 LTS or newer.

## Quickstart

```ts
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { authplaneMcpAuth } from "@authplane/mcp";
import { z } from "zod";

const server = new McpServer({ name: "weather", version: "1.0.0" });
server.tool(
  "get_weather",
  { city: z.string() },
  async ({ city }) => ({ content: [{ type: "text", text: `${city}: sunny` }] }),
);

const auth = await authplaneMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://mcp.example.com/mcp",
  scopes: ["tools/get_weather"],
});

const app = express();
app.use(express.json());
app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);
app.all("/mcp", auth.bearerAuth /* , transport handlers */);
app.listen(3000);
```

`auth.bearerAuth` is an Express middleware that validates the bearer token, enforces scopes, and attaches `req.auth` (MCP's `AuthInfo`).

## Per-tool scope enforcement

Two `requireScope` symbols exist; use the right one:

- `requireScope(scope, extra.authInfo)` from `@authplane/mcp` — call inside an MCP tool handler. Throws if the bound bearer token does not carry `scope`.
- `claims.requireScope(scope)` method on `VerifiedClaims` from `@authplane/sdk/core` — call when you are doing manual JWT validation outside the MCP request flow and you already hold a `VerifiedClaims`.

In a normal MCP server you only need the first one; the bearer middleware already populated `extra.authInfo` for you.

## Local development

The default `FetchSettings` reject plaintext `http://` issuers (SSRF protection). When pointing the adapter at a local authserver — typically `http://localhost:9000` — pass `devMode: true` to relax the network policy:

```ts
const auth = await authplaneMcpAuth({
  issuer: "http://localhost:9000",
  resource: "http://localhost:8080/mcp",
  scopes: ["tools/get_weather"],
  devMode: true,
});
```

> **Warning:** Never set `devMode: true` in production — it disables SSRF protection entirely.

`devMode: true` is shorthand for `fetchSettings: new FetchSettings({ ssrfProtection: false, allowHttp: true, allowLocalhost: true, allowPrivateNetworks: true })`. If you need finer control (e.g. allow loopback but keep HTTPS-only), construct a `FetchSettings` directly and pass it as `fetchSettings`:

```ts
import { FetchSettings } from "@authplane/mcp";
```

Without one of these, metadata discovery against an `http://` issuer fails with `MetadataFetchError: URL must use HTTPS`.

## Learn more

- **[User Guide](docs/user-guide.md)** — complete reference: options, scope enforcement, URL elicitation, introspection, error handling, advanced configuration.
- **[`@authplane/sdk`](../sdk)** — the underlying OAuth/JWT primitives.

On shutdown call `await auth.client.close()` to stop internal refresh timers.
