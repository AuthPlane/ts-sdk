import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { describe, expect, it } from "vitest";

import { exchange, FetchSettings } from "../../src/core/index.js";

describe("exchangeToken form encoding", () => {
  it("sends repeated resource/audience params (RFC 8693)", async () => {
    let receivedBody = "";
    const server = createServer((req, res) => {
      if (req.url === "/token" && req.method === "POST") {
        req.on("data", (chunk) => {
          receivedBody += chunk.toString("utf-8");
        });
        req.on("end", () => {
          res.statusCode = 200;
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              access_token: "at_1",
              token_type: "Bearer",
              expires_in: 300,
              scope: "",
              issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
            }),
          );
        });
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      await exchange({
        tokenEndpoint: `${base}/token`,
        authHeader: {},
        fetchSettings: FetchSettings.fromDevMode(true),
        exchange: {
          subjectToken: "st_1",
          resources: ["r1", "r2"],
          audiences: ["a1", "a2"],
        },
      });

      // Ensure the POST body contains repeated keys (not space-joined).
      const resourceCount = (receivedBody.match(/(?:^|&)resource=/g) ?? []).length;
      const audienceCount = (receivedBody.match(/(?:^|&)audience=/g) ?? []).length;
      expect(resourceCount).toBe(2);
      expect(audienceCount).toBe(2);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

