import { describe, expect, it, vi } from "vitest";

import { parseExpiresAt } from "../../src/core/fetching/cacheHeaders.js";

describe("fetching/cacheHeaders.parseExpiresAt", () => {
  it("parses Cache-Control max-age", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiresAt = parseExpiresAt({
      "cache-control": "public, max-age=60",
      expires: "2030-01-01T00:00:00Z",
    });

    expect(expiresAt).toBe(nowSeconds + 60);

    vi.useRealTimers();
  });

  it("treats max-age negative as undefined", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const expiresAt = parseExpiresAt({
      "cache-control": "public, max-age=-10",
    });

    expect(expiresAt).toBeUndefined();

    vi.useRealTimers();
  });

  it("parses max-age with different casing", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiresAt = parseExpiresAt({
      "cache-control": "public, MAX-AGE=10",
    });

    expect(expiresAt).toBe(nowSeconds + 10);

    vi.useRealTimers();
  });

  it("returns now when max-age=0", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiresAt = parseExpiresAt({
      "cache-control": "max-age=0",
    });

    expect(expiresAt).toBe(nowSeconds);

    vi.useRealTimers();
  });

  it("parses Expires header when Cache-Control has no max-age", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const expiresAt = parseExpiresAt({
      expires: "2030-01-01T00:00:00Z",
    });

    expect(expiresAt).toBe(Math.floor(new Date("2030-01-01T00:00:00Z").getTime() / 1000));

    vi.useRealTimers();
  });

  it("returns undefined for invalid Expires", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const expiresAt = parseExpiresAt({
      expires: "not-a-date",
    });

    expect(expiresAt).toBeUndefined();

    vi.useRealTimers();
  });
});

