# @authplane/hono

[Authplane](https://github.com/AuthPlane/authserver) JWT validation adapter for the [Hono](https://hono.dev) web framework. Bearer-token auth on your Hono server in a few lines — runs on Node, Bun, Deno, Cloudflare Workers, and any other Hono-supported runtime.

## Install

```bash
npm install @authplane/sdk @authplane/hono hono
```

## Quickstart

```ts
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import {
  authplaneHonoAuth,
  requireScope,
  type HonoAuthVariables,
} from "@authplane/hono";

const auth = await authplaneHonoAuth({
  issuer: "https://auth.example.com",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/get_weather"],
});

const app = new Hono<{ Variables: HonoAuthVariables }>();

app.get(
  auth.protectedResourceMetadataPath,
  auth.protectedResourceMetadataHandler,
);

app.use("/mcp/*", auth.bearerAuth);
app.post("/mcp/tools/get_weather", async (c) => {
  requireScope(c, "tools/get_weather");
  const { city } = await c.req.json<{ city: string }>();
  return c.json({ content: [{ type: "text", text: `${city}: sunny` }] });
});

serve({ fetch: app.fetch, port: 3000 });
```

`auth.bearerAuth` is a Hono `MiddlewareHandler` that validates the bearer token, enforces scopes, and attaches the verified claims to `c.get("auth")`. `requireScope(c, "…")` layers per-route scope checks on top.

## Learn more

- **[User Guide](docs/user-guide.md)** — complete reference: options, scope enforcement, `onError` bridging, DPoP, introspection, error handling, runtime portability.
- **[Demo](demo/README.md)** — runnable multi-route calculator (`./demo/run.sh`).
- **[`@authplane/sdk`](../sdk)** — the underlying OAuth/JWT primitives.

On shutdown call `await auth.client.close()` to stop internal JWKS / metadata refresh timers.
