# @authplane/fastmcp

[Authplane](https://github.com/AuthPlane/authserver) JWT validation adapter for [FastMCP](https://github.com/punkpeye/fastmcp). Bearer-token auth on your FastMCP server in a few lines.

## Install

```bash
npm install @authplane/sdk @authplane/fastmcp fastmcp zod
```

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

## Learn more

- **[User Guide](docs/user-guide.md)** — complete reference: options, session shape, scope enforcement, URL elicitation for consent, introspection, DPoP, error handling, advanced configuration.
- **[`@authplane/sdk`](../sdk)** — the underlying OAuth/JWT primitives.

On shutdown call `await auth.client.close()` to stop internal refresh timers.
