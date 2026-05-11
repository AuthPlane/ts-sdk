import { createServer } from "node:http";
import { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";

import {
  exchange,
  FetchSettings,
  InvalidRequestError,
} from "../../src/core/index.js";

describe("oauth/tokenExchange branches", () => {
  it("throws when subjectToken is missing", async () => {
    await expect(
      exchange({
        tokenEndpoint: "http://example.test/token",
        authHeader: {},
        fetchSettings: FetchSettings.fromDevMode(true),
        exchange: {
          // Intentionally empty
          subjectToken: "",
        },
      }),
    ).rejects.toThrow(/subjectToken is required/);
  });

  it("includes actor_token and actor_token_type when actorToken is provided", async () => {
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
              issued_token_type:
                "urn:ietf:params:oauth:token-type:access_token",
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
          subjectTokenType: "urn:example:token-type:subject",
          actorToken: "act_1",
          actorTokenType: "urn:example:token-type:actor",
          scope: "tools/echo",
          resources: ["r1"],
          audiences: ["a1"],
        },
      });

      const params = new URLSearchParams(receivedBody);
      expect(params.get("actor_token")).toBe("act_1");
      expect(params.get("actor_token_type")).toBe(
        "urn:example:token-type:actor",
      );
      expect(params.get("subject_token_type")).toBe(
        "urn:example:token-type:subject",
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("maps non-2xx responses into OAuth errors (invalid_request)", async () => {
    const server = createServer((req, res) => {
      if (req.url === "/token" && req.method === "POST") {
        res.statusCode = 400;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "invalid_request", error_description: "bad" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;

    try {
      await expect(
        exchange({
          tokenEndpoint: `${base}/token`,
          authHeader: {},
          fetchSettings: FetchSettings.fromDevMode(true),
          exchange: {
            subjectToken: "st_1",
          },
        }),
      ).rejects.toBeInstanceOf(InvalidRequestError);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

