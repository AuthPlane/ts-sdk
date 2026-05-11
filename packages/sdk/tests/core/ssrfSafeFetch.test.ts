import { createServer, type IncomingMessage, type Server } from "node:http";
import { AddressInfo } from "node:net";

import { describe, expect, it } from "vitest";

import {
  ssrfSafeFetch,
  ssrfSafePost,
  ssrfSafePostWithStatus,
  SSRFError,
} from "../../src/core/fetching/ssrf.js";

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

describe("fetching/ssrf: safe fetch helpers", () => {
  it("ssrfSafeFetch fetches JSON from localhost when allowHttp+allowLocalhost are enabled", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (req, res) => {
      if (req.url === "/fetch") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      res.statusCode = 404;
      res.end();
    });

    try {
      const result = await ssrfSafeFetch(`${base}/fetch`, {
        allowHttp: true,
        allowLocalhost: true,
      });
      expect(result.body).toEqual({ ok: true });
      expect(result.headers["content-type"]).toMatch(/application\/json/i);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafePost sends urlencoded form and returns JSON on 2xx", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    let received: {
      host?: string;
      contentType?: string;
      accept?: string;
      xTest?: string;
      body?: string;
    } = {};

    server.on("request", async (req, res) => {
      if (req.url !== "/post-ok") {
        res.statusCode = 404;
        res.end();
        return;
      }

      received = {
        host: String(req.headers.host ?? ""),
        contentType: String(req.headers["content-type"] ?? ""),
        accept: String(req.headers["accept"] ?? ""),
        xTest: String(req.headers["x-test"] ?? ""),
        body: await readBody(req),
      };

      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ received: received.body }));
    });

    try {
      const result = await ssrfSafePost(`${base}/post-ok`, {
        allowHttp: true,
        allowLocalhost: true,
        formData: { a: "b" },
        extraHeaders: { "X-Test": "1" },
      });

      expect(result.body.received).toBe("a=b");
      expect(received.host).toBe("127.0.0.1");
      expect(received.accept).toBe("application/json");
      expect(received.contentType).toBe("application/x-www-form-urlencoded");
      expect(received.xTest).toBe("1");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafePostWithStatus returns statusCode and JSON body for non-2xx", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (_req, res) => {
      if (_req.url !== "/post-bad") {
        res.statusCode = 404;
        res.end();
        return;
      }

      res.statusCode = 400;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: "bad_request" }));
    });

    try {
      const result = await ssrfSafePostWithStatus(`${base}/post-bad`, {
        allowHttp: true,
        allowLocalhost: true,
        formData: { a: "b" },
      });

      expect(result.statusCode).toBe(400);
      expect(result.body).toEqual({ error: "bad_request" });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafePostWithStatus rejects invalid JSON bodies", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (req, res) => {
      if (req.url !== "/post-invalid-json") {
        res.statusCode = 404;
        res.end();
        return;
      }

      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end("not-json");
    });

    try {
      await expect(
        ssrfSafePostWithStatus(`${base}/post-invalid-json`, {
          allowHttp: true,
          allowLocalhost: true,
          formData: { a: "b" },
          maxSize: 1024,
        }),
      ).rejects.toThrow(/Failed to parse JSON response/i);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafePostWithStatus rejects when streamed body exceeds maxSize", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (req, res) => {
      if (req.url !== "/post-stream-too-large") {
        res.statusCode = 404;
        res.end();
        return;
      }

      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.write('{"data":"');
      res.write("x".repeat(50));
      res.end('"}');
    });

    try {
      await expect(
        ssrfSafePostWithStatus(`${base}/post-stream-too-large`, {
          allowHttp: true,
          allowLocalhost: true,
          formData: { a: "b" },
          maxSize: 10,
        }),
      ).rejects.toThrow(/Response too large: streaming exceeded 10 bytes/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafeFetch throws SSRFError for non-HTTPS URLs when allowHttp is not set", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;
    server.on("request", (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true }));
    });

    try {
      await expect(ssrfSafeFetch(`${base}/fetch`, { allowLocalhost: true })).rejects.toThrow(
        SSRFError,
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafeFetch rejects redirects for SSRF-safe fetches", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (req, res) => {
      if (req.url === "/redirect") {
        res.statusCode = 302;
        res.setHeader("location", "/fetch");
        res.end();
        return;
      }

      res.statusCode = 404;
      res.end();
    });

    try {
      await expect(
        ssrfSafeFetch(`${base}/redirect`, {
          allowHttp: true,
          allowLocalhost: true,
          maxSize: 1024,
        }),
      ).rejects.toThrow(/Redirects are not allowed/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafeFetch throws on non-2xx responses", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (req, res) => {
      if (req.url === "/non2xx") {
        res.statusCode = 500;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "boom" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    try {
      await expect(
        ssrfSafeFetch(`${base}/non2xx`, {
          allowHttp: true,
          allowLocalhost: true,
          maxSize: 1024,
        }),
      ).rejects.toThrow(/HTTP request failed with status 500/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafeFetch rejects invalid JSON bodies", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (req, res) => {
      if (req.url === "/invalid-json") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end("not-json");
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    try {
      await expect(
        ssrfSafeFetch(`${base}/invalid-json`, {
          allowHttp: true,
          allowLocalhost: true,
          maxSize: 1024,
        }),
      ).rejects.toThrow(/Failed to parse JSON response/i);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafeFetch rejects when Content-Length exceeds maxSize", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (req, res) => {
      if (req.url === "/too-large") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        // Force the content-length branch without streaming a large payload.
        res.setHeader("content-length", "1000");
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    try {
      await expect(
        ssrfSafeFetch(`${base}/too-large`, {
          allowHttp: true,
          allowLocalhost: true,
          maxSize: 10,
        }),
      ).rejects.toThrow(/Response too large: 1000 bytes/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafeFetch normalizes array header values (Array.isArray branch)", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (_req, res) => {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      // Ensure the header value comes as a string[] in IncomingHttpHeaders.
      res.setHeader("set-cookie", ["a=1", "b=2"]);
      res.end(JSON.stringify({ ok: true }));
    });

    try {
      const result = await ssrfSafeFetch(`${base}/fetch-array-headers`, {
        allowHttp: true,
        allowLocalhost: true,
        maxSize: 1024,
      });

      // ssrf.ts normalizeHeaders joins arrays with ", "
      expect(result.headers["set-cookie"]).toBe("a=1, b=2");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("ssrfSafeFetch rejects when streaming body exceeds maxSize (streaming exceeded)", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    server.on("request", (_req, res) => {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      // Stream a body without content-length so the fetch helper uses the streaming size check.
      res.write('{"data":"');
      res.write("x".repeat(50));
      res.end('"}');
    });

    try {
      await expect(
        ssrfSafeFetch(`${base}/stream-too-large`, {
          allowHttp: true,
          allowLocalhost: true,
          maxSize: 10,
        }),
      ).rejects.toThrow(/Response too large: streaming exceeded 10 bytes/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

