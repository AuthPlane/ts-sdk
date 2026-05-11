# @authplane/mcp

[Authplane](https://github.com/AuthPlane/authserver) JWT validation adapter for the official [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk). Bearer-token auth on your MCP server in a few lines.

## Install

```bash
npm install @authplane/sdk @authplane/mcp @modelcontextprotocol/sdk express zod
```

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

## Learn more

- **[User Guide](docs/user-guide.md)** — complete reference: options, scope enforcement, URL elicitation, introspection, error handling, advanced configuration.
- **[`@authplane/sdk`](../sdk)** — the underlying OAuth/JWT primitives.

On shutdown call `await auth.client.close()` to stop internal refresh timers.
