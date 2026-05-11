import { createServer } from "node:http";
import { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";

import { FetchSettings } from "../../src/core/index.js";
import { formPost } from "../../src/auth/oauth/http.js";

describe("oauth/http formPost", () => {
  it("uses ssrf-safe POST when fetchSettings.ssrfProtection=true", async () => {
    let received = false;

    const server = createServer((req, res) => {
      if (req.url !== "/token" || req.method !== "POST") {
        res.statusCode = 404;
        res.end();
        return;
      }
      received = true;
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.setHeader("x-custom", "abc");
      res.end(JSON.stringify({ ok: true }));
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      const resp = await formPost({
        url: `${base}/token`,
        formData: { grant_type: "client_credentials" },
        fetchSettings: new FetchSettings({
          ssrfProtection: true,
          allowHttp: true,
          allowLocalhost: true,
          timeoutSeconds: 2,
        }),
        extraHeaders: {},
      });

      expect(received).toBe(true);
      expect(resp.statusCode).toBe(200);
      expect(resp.body).toEqual({ ok: true });
      expect(resp.headers["x-custom"]).toBe("abc");
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("returns {} when the AS returns invalid JSON (ssrfProtection=false)", async () => {
    const server = createServer((req, res) => {
      if (req.url !== "/token" || req.method !== "POST") {
        res.statusCode = 404;
        res.end();
        return;
      }
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end("not-json");
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      const resp = await formPost({
        url: `${base}/token`,
        formData: { grant_type: "client_credentials" },
        fetchSettings: FetchSettings.fromDevMode(true),
        extraHeaders: {},
      });

      expect(resp.statusCode).toBe(200);
      expect(resp.body).toEqual({});
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});
