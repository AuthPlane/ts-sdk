import { describe, expect, it } from "vitest";

import {
  SSRFError,
  validateUrl,
} from "../../src/core/fetching/ssrf.js";

describe("fetching/ssrf.validateUrl", () => {
  it("throws SSRFError for invalid URLs", async () => {
    await expect(validateUrl("not-a-url")).rejects.toThrow(SSRFError);
  });

  it("rejects HTTP when allowHttp is false (default)", async () => {
    await expect(validateUrl("http://example.com/path")).rejects.toThrow(
      /URL must use HTTPS/,
    );
  });

  it("rejects localhost by default due to loopback blocking", async () => {
    await expect(
      validateUrl("https://localhost:8443/"),
    ).rejects.toThrow(/blocked IP address/);
  });

  it("allows localhost when allowLocalhost is true", async () => {
    const validated = await validateUrl("https://localhost:8443/", {
      allowLocalhost: true,
    });

    expect(validated.protocol).toBe("https:");
    expect(validated.hostname).toBe("localhost");
    expect(validated.port).toBe(8443);
    expect(validated.path).toBe("/");
    expect(validated.resolvedIps.length).toBeGreaterThan(0);
  });

  it("rejects non-http(s) protocols when allowHttp=true", async () => {
    await expect(
      validateUrl("ftp://example.com/resource", { allowHttp: true }),
    ).rejects.toThrow(/URL must use HTTP or HTTPS/);
  });

  it("rejects URLs without a host", async () => {
    await expect(validateUrl("https://", { allowLocalhost: true })).rejects.toThrow(
      /Invalid URL/,
    );
  });

  it("defaults port to 443 for https without explicit port", async () => {
    const validated = await validateUrl("https://localhost/resource", {
      allowLocalhost: true,
    });
    expect(validated.protocol).toBe("https:");
    expect(validated.port).toBe(443);
  });

  it("defaults port to 80 for http without explicit port", async () => {
    const validated = await validateUrl("http://localhost/resource", {
      allowHttp: true,
      allowLocalhost: true,
    });
    expect(validated.protocol).toBe("http:");
    expect(validated.port).toBe(80);
  });
});

