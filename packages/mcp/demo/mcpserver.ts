/**
 * Run from the package root:
 *
 *   cp demo/.env.example demo/.env
 *   ./demo/run.sh
 */

import crypto from "node:crypto";
import { config } from "dotenv";
import { resolve, dirname } from "node:path";
import { fileURLToPath, URL } from "node:url";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import {
  authplaneMcpAuth,
  requireScope,
  type ASCredentials,
  IntrospectionRevocation,
} from "@authplane/mcp";
// Not re-exported by `@authplane/mcp`; the hono and nestjs demos reach for
// `@authplane/sdk/core` the same way.
import { buildDPoPRequestContext } from "@authplane/sdk/core";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, ".env") });

function env(name: string, legacyName: string, fallback: string): string {
  return process.env[name] ?? process.env[legacyName] ?? fallback;
}

const resource = env(
  "AUTHPLANE_RESOURCE",
  "RESOURCE_URL",
  "http://localhost:8080/mcp",
);
const parsedResourceUrl = new URL(resource);
const port = parsedResourceUrl.port
  ? Number(parsedResourceUrl.port)
  : parsedResourceUrl.protocol === "https:"
    ? 443
    : 80;

const auth = await authplaneMcpAuth({
  issuer: env("AUTHPLANE_ISSUER", "ISSUER_URL", "http://localhost:9000"),
  resource,
  scopes: ["tools/add", "tools/multiply", "tools/consent_demo"],
  devMode: true,
  asCredentials: {
    clientId: process.env.AUTHPLANE_CLIENT_ID ?? process.env.CLIENT_ID ?? resource,
    clientSecret:
      process.env.AUTHPLANE_CLIENT_SECRET ?? process.env.CLIENT_SECRET ?? "",
  } satisfies ASCredentials,
  revocationChecker: IntrospectionRevocation.get(),
});

// Broker resource registered by the demo authserver (see
// authserver/demo/mcp-demo-server-start.sh). The broker has fake upstream
// Google credentials, so a real upstream exchange would fail at Google's
// screen — but that's irrelevant to this demo: we only need the AS to emit
// `consent_required` with a `consent_url` so the wrapped client can
// translate it into MCP `UrlElicitationRequiredError` (-32042).
const GOOGLE_CALENDAR_RESOURCE_URI = "https://www.googleapis.com/calendar/v3";
const GOOGLE_CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar";

function createMcpServer(): McpServer {
  const server = new McpServer({ name: "Calculator Service", version: "1.0.0" });

  server.tool("add", { a: z.number(), b: z.number() }, async (params, extra) => {
    requireScope("tools/add", extra.authInfo);
    return { content: [{ type: "text", text: String(params.a + params.b) }] };
  });

  server.tool(
    "multiply",
    { a: z.number(), b: z.number() },
    async (params, extra) => {
      requireScope("tools/multiply", extra.authInfo);
      return { content: [{ type: "text", text: String(params.a * params.b) }] };
    },
  );

  // Exchange the inbound user token for a Google Calendar token via RFC 8693.
  //
  // Until the user has connected Google Calendar (which they cannot in this
  // demo — the upstream credentials are fake), the AS responds to this
  // exchange with `consent_required` and a `consent_url` pointing at the
  // AS's connect endpoint. The wrapped `auth.client.exchange` translates
  // that into `UrlElicitationRequiredError` (MCP error code `-32042`)
  // before this handler returns. The `@modelcontextprotocol/sdk` server
  // re-raises `UrlElicitationRequiredError` on the JSON-RPC wire, so the
  // client sees `-32042` and prompts the user to visit the URL — no
  // try/except needed in this handler.
  server.tool("consent_demo", {}, async (_params, extra) => {
    requireScope("tools/consent_demo", extra.authInfo);
    const inboundToken = extra.authInfo?.token;
    if (!inboundToken) {
      throw new Error("missing access token");
    }
    const downstream = await auth.client.exchange({
      subjectToken: inboundToken,
      scope: GOOGLE_CALENDAR_SCOPE,
      resources: [GOOGLE_CALENDAR_RESOURCE_URI],
    });
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { tokenType: downstream.tokenType, scope: downstream.scope ?? "" },
            null,
            2,
          ),
        },
      ],
    };
  });

  // --- Debug/inspection tools for Claude flow testing ---
  // These tools allow Claude to directly call the AuthplaneClient to test token ops.
  // NOTE: they are protected by tools/add for simplicity so they work with the existing demo scopes.
  server.tool(
    "debug_client_credentials",
    { scope: z.string().default("tools/add") },
    async ({ scope }, extra) => {
      requireScope("tools/add", extra.authInfo);
      const token = await auth.client.clientCredentials([scope], [resource]);
      return { content: [{ type: "text", text: JSON.stringify(token, null, 2) }] };
    },
  );

  server.tool(
    "debug_introspect_token",
    { token: z.string() },
    async ({ token }, extra) => {
      requireScope("tools/add", extra.authInfo);
      const info = await auth.client.introspect(token);
      return { content: [{ type: "text", text: JSON.stringify(info, null, 2) }] };
    },
  );

  server.tool(
    "debug_exchange_token",
    {
      subjectToken: z.string(),
      scope: z.string().default("tools/add"),
    },
    async ({ subjectToken, scope }, extra) => {
      requireScope("tools/add", extra.authInfo);
      const exchanged = await auth.client.exchange({
        subjectToken,
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
        scope,
        resources: [resource],
        audiences: [resource],
      });
      return { content: [{ type: "text", text: JSON.stringify(exchanged, null, 2) }] };
    },
  );

  server.tool(
    "debug_verify_dpop_proof",
    {
      token: z.string(),
      proof: z.string(),
      method: z.string().default("POST"),
      url: z.string(),
    },
    async ({ token, proof, method, url }, extra) => {
      requireScope("tools/add", extra.authInfo);
      const verifier = auth.verifier;
      // Build the context through the factory rather than by object literal:
      // `buildDPoPRequestContext` is where RFC 9449 §4.3 #1 ("not more than
      // one DPoP header") is enforced, so a comma-joined pair arriving in
      // `proof` fails with MultipleDPoPProofs instead of being verified as a
      // single opaque string.
      const claims = await verifier.verify(token, {
        dpopRequest: buildDPoPRequestContext({
          method,
          url,
          dpopHeaderValues: [proof],
        }),
      });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                sub: claims.sub,
                clientId: claims.clientId,
                scopes: claims.scopes,
                dpopProof: (claims as unknown as { dpopProof?: unknown }).dpopProof ?? null,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  return server;
}

const app = express();
app.use(express.json());

app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);

const sessions = new Map<
  string,
  { transport: StreamableHTTPServerTransport; server: McpServer }
>();

app.all("/mcp", auth.bearerAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const existing = sessionId === undefined ? undefined : sessions.get(sessionId);
  if (existing) {
    await existing.transport.handleRequest(req, res, req.body);
    return;
  }

  const newSessionId = crypto.randomUUID();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => newSessionId,
  });
  const mcp = createMcpServer();
  sessions.set(newSessionId, { transport, server: mcp });
  // @ts-expect-error -- upstream @modelcontextprotocol/sdk mismatch, not ours:
  // Transport declares `onclose?: () => void` (shared/transport.d.ts:65) while
  // StreamableHTTPServerTransport exposes it as an accessor typed
  // `(() => void) | undefined` (server/streamableHttp.d.ts:70-71). Under
  // exactOptionalPropertyTypes those are incompatible. Delete this line's
  // suppression once the SDK's declarations agree — tsc will flag it as unused.
  await mcp.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(port, () => {
  console.log(`MCP Calculator Service running on ${resource}`);
});
