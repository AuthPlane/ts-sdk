import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";

import { describe, expect, it, vi } from "vitest";

import { DocumentFetcher } from "../../src/core/fetching/documentFetcher.js";
import { FetchSettings } from "../../src/core/fetching/fetchSettings.js";
import { ssrfSafeFetch } from "../../src/core/fetching/ssrf.js";

type TestServer = {
  server: Server;
  base: string;
  close: () => Promise<void>;
};

function startServer(
  handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void,
): Promise<TestServer> {
  const server = createServer();
  server.on("request", handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      const base = `http://127.0.0.1:${addr.port}`;
      resolve({
        server,
        base,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

describe("fetching/documentFetcher", () => {
  it("fetches JSON and parses expiresAt with ssrfProtection=false", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/ok") {
        res.setHeader("content-type", "application/json");
        res.setHeader("cache-control", "public, max-age=20");
        res.end(JSON.stringify({ hello: "world" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const fixedNow = Date.parse("2026-03-13T00:00:00Z");
    const spy = vi.spyOn(Date, "now").mockReturnValue(fixedNow);
    try {
      const fetcher = new DocumentFetcher<{ hello: string }>(
        `${server.base}/ok`,
        {
          settings: new FetchSettings({ ssrfProtection: false, timeoutSeconds: 2 }),
          maxSize: 1024,
        },
      );

      const result = await fetcher.fetch();
      expect(result.document).toEqual({ hello: "world" });
      expect(result.expiresAt).toBe(Math.floor(fixedNow / 1000) + 20);
    } finally {
      spy.mockRestore();
      await server.close();
    }
  });

  it("rejects redirects when ssrfProtection=false", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/redirect") {
        res.statusCode = 302;
        res.setHeader("location", "/ok");
        res.end();
        return;
      }
      if (req.url === "/ok") {
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const fetcher = new DocumentFetcher<{ ok: boolean }>(
      `${server.base}/redirect`,
      { settings: new FetchSettings({ ssrfProtection: false, timeoutSeconds: 2 }) },
    );

    await expect(fetcher.fetch()).rejects.toThrow(/Redirects are not allowed/);
    await server.close();
  });

  it("rejects non-2xx responses when ssrfProtection=false", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/err") {
        res.statusCode = 500;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "boom" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const fetcher = new DocumentFetcher<{ error: string }>(
      `${server.base}/err`,
      { settings: new FetchSettings({ ssrfProtection: false, timeoutSeconds: 2 }) },
    );

    await expect(fetcher.fetch()).rejects.toThrow(
      /HTTP request failed with status 500/,
    );
    await server.close();
  });

  it("rejects when content-length exceeds maxSize (ssrfProtection=false)", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/too-large") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.setHeader("content-length", "1000");
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const fetcher = new DocumentFetcher<{ ok: boolean }>(
      `${server.base}/too-large`,
      { settings: new FetchSettings({ ssrfProtection: false, timeoutSeconds: 2 }), maxSize: 10 },
    );

    await expect(fetcher.fetch()).rejects.toThrow(/Response too large: 1000 bytes/);
    await server.close();
  });

  it("rejects when streamed body exceeds maxSize (ssrfProtection=false)", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/stream-too-large") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        // No content-length: stream chunks to avoid setting it.
        res.write("{\"data\":\"");
        res.write("x".repeat(50));
        res.end("\"}");
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const fetcher = new DocumentFetcher<{ data: string }>(
      `${server.base}/stream-too-large`,
      { settings: new FetchSettings({ ssrfProtection: false, timeoutSeconds: 2 }), maxSize: 10 },
    );

    await expect(fetcher.fetch()).rejects.toThrow(/Response too large: body exceeded/);
    await server.close();
  });

  it("rejects invalid JSON (ssrfProtection=false)", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/invalid") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end("not-json");
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const fetcher = new DocumentFetcher<Record<string, unknown>>(
      `${server.base}/invalid`,
      { settings: new FetchSettings({ ssrfProtection: false, timeoutSeconds: 2 }) },
    );

    await expect(fetcher.fetch()).rejects.toThrow(/Unexpected token|JSON/);
    await server.close();
  });

  it("fetches JSON and parses expiresAt with ssrfProtection=true", async () => {
    const server = await startServer((req, res) => {
      if (req.url === "/ok") {
        res.setHeader("content-type", "application/json");
        res.setHeader("cache-control", "public, max-age=10");
        res.end(JSON.stringify({ a: 1 }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    const fixedNow = Date.parse("2026-03-13T00:00:00Z");
    const spy = vi.spyOn(Date, "now").mockReturnValue(fixedNow);
    try {
      // Sanity check: ssrfSafeFetch works with our local server and settings.
      await ssrfSafeFetch(`${server.base}/ok`, {
        allowHttp: true,
        allowLocalhost: true,
        maxSize: 1024,
        timeoutSeconds: 2,
      });

      const fetcher = new DocumentFetcher<{ a: number }>(
        `${server.base}/ok`,
        {
          settings: new FetchSettings({
            ssrfProtection: true,
            allowHttp: true,
            allowLocalhost: true,
            timeoutSeconds: 2,
          }),
          maxSize: 1024,
        },
      );

      const result = await fetcher.fetch();
      expect(result.document).toEqual({ a: 1 });
      expect(result.expiresAt).toBe(Math.floor(fixedNow / 1000) + 10);
    } finally {
      spy.mockRestore();
      await server.close();
    }
  });
});

