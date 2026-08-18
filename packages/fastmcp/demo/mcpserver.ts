/**
 * Run from the package root:
 *
 *   cp demo/.env.example demo/.env
 *   ./demo/run.sh
 */

import { config } from "dotenv";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { URL } from "node:url";
import { FastMCP, requireScopes } from "fastmcp";
import { z } from "zod";
import {
  authplaneFastMcpAuth,
  type ASCredentials,
  IntrospectionRevocation,
} from "@authplane/fastmcp";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, ".env") });

function env(name: string, legacyName: string, fallback: string): string {
  return process.env[name] ?? process.env[legacyName] ?? fallback;
}

const baseUrl = env("AUTHPLANE_BASE_URL", "BASE_URL", "http://localhost:8080");
const resource = `${baseUrl.replace(/\/+$/, "")}/mcp`;
const parsedBaseUrl = new URL(baseUrl);
const port = parsedBaseUrl.port
  ? Number(parsedBaseUrl.port)
  : parsedBaseUrl.protocol === "https:"
    ? 443
    : 80;

const auth = await authplaneFastMcpAuth({
  issuer: env("AUTHPLANE_ISSUER", "ISSUER_URL", "http://localhost:9000"),
  baseUrl,
  scopes: ["tools/add", "tools/multiply"],
  devMode: true,
  asCredentials: {
    clientId: process.env.AUTHPLANE_CLIENT_ID ?? process.env.CLIENT_ID ?? resource,
    clientSecret:
      process.env.AUTHPLANE_CLIENT_SECRET ?? process.env.CLIENT_SECRET ?? "",
  } satisfies ASCredentials,
  revocationChecker: IntrospectionRevocation.get(),
});

const mcp = new FastMCP({
  name: "Calculator Service",
  version: "1.0.0",
  authenticate: auth.authenticate,
  oauth: auth.oauth,
});

mcp.addTool({
  name: "add",
  description: "Add two numbers",
  parameters: z.object({ a: z.number(), b: z.number() }),
  canAccess: requireScopes("tools/add"),
  execute: async ({ a, b }) => String(a + b),
});

mcp.addTool({
  name: "multiply",
  description: "Multiply two numbers",
  parameters: z.object({ a: z.number(), b: z.number() }),
  canAccess: requireScopes("tools/multiply"),
  execute: async ({ a, b }) => String(a * b),
});

// NOTE: a `consent_demo` tool that exercises the URL elicitation path was
// intentionally omitted from this demo. fastmcp 3.35.0 does not propagate
// `UrlElicitationRequiredError` (an `McpError` subclass) raised inside a
// tool handler — its tool-call dispatch catches every non-`UserError` and
// wraps it as an `isError: true` tool result, so the client never sees
// JSON-RPC `-32042`. To showcase the elicitation flow end-to-end, use the
// low-level `@authplane/mcp` adapter instead.

await mcp.start({ transportType: "httpStream", httpStream: { port } });
console.log(`FastMCP Calculator Service running on ${baseUrl.replace(/\/+$/, "")}/mcp`);
// Keep demo server alive when running via shell scripts.
await new Promise(() => {});
