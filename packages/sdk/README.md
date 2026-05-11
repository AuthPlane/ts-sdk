# @authplane/sdk

OAuth 2.1 + JWT validation primitives for Node.js. Verify access tokens from [Authplane's `authserver`](https://github.com/AuthPlane/authserver) in a few lines, or use the OAuth client to obtain and exchange tokens yourself.

Ships two subpath entry points:

- **`@authplane/sdk/core`** — resource-server primitives (JWT validation, RFC 8414 discovery, JWKS, RFC 9728 Protected Resource Metadata, RFC 7662 introspection, DPoP).
- **`@authplane/sdk/auth`** — stateless OAuth protocol primitives (client-credentials, RFC 8693 token exchange, introspection, revocation, DPoP signer).

## Install

```bash
npm install @authplane/sdk
```

Requires Node.js 22 LTS (or newer). TypeScript consumers need `"moduleResolution": "bundler" | "node16" | "nodenext"`.

## Validate an access token

```ts
import { AuthplaneClient } from "@authplane/sdk/core";

const client = await AuthplaneClient.create({ issuer: "https://auth.example.com" });

const resource = client.resource({
  resource: "https://api.example.com",
  scopes: ["read"],
});

const claims = await resource.verify(bearerToken);
claims.requireScope("read");
```

## Obtain an access token

```ts
import { AuthplaneClient } from "@authplane/sdk/core";

const client = await AuthplaneClient.create({
  issuer: "https://auth.example.com",
  auth: { clientId: "my-client-id", clientSecret: "my-client-secret" },
});

const token = await client.clientCredentials(["tools/read"]);
console.log(token.accessToken);
```

## Learn more

- **[User Guide](docs/user-guide.md)** — complete reference: scope enforcement, DPoP, token exchange, introspection & revocation, fetch settings, error handling, advanced configuration.
- **[`@authplane/mcp`](../mcp)** — adapter for the MCP TypeScript SDK.
- **[`@authplane/fastmcp`](../fastmcp)** — adapter for FastMCP.
- **[Root CHANGELOG](../../CHANGELOG.md)** — release history.
- **[SECURITY](../../SECURITY.md)** — vulnerability reporting.
