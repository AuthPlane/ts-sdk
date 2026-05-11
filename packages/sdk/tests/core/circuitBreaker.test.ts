import { describe, expect, it, vi } from "vitest";

import { CircuitBreaker } from "../../src/core/circuitBreaker.js";
import { CircuitOpenError } from "../../src/core/errors.js";

describe("circuitBreaker", () => {
  it("assertClosed() no-ops when closed", () => {
    const cb = new CircuitBreaker(2, 10);
    expect(() => cb.assertClosed()).not.toThrow();
  });

  it("opens after reaching threshold failures and blocks until cooldown", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const cb = new CircuitBreaker(2, 10);
    cb.recordFailure();
    expect(() => cb.assertClosed()).not.toThrow();

    cb.recordFailure(); // threshold reached => openUntilSeconds set
    expect(() => cb.assertClosed()).toThrow(CircuitOpenError);

    // Still in cooldown window.
    vi.setSystemTime(new Date("2026-03-13T00:00:05Z"));
    expect(() => cb.assertClosed()).toThrow(CircuitOpenError);

    // Cooldown expired => it closes and resets failures.
    vi.setSystemTime(new Date("2026-03-13T00:00:11Z"));
    expect(() => cb.assertClosed()).not.toThrow();

    vi.useRealTimers();
  });

  it("recordSuccess() resets failures and closes the circuit", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const cb = new CircuitBreaker(2, 10);
    cb.recordFailure();
    cb.recordFailure(); // opens
    expect(() => cb.assertClosed()).toThrow(CircuitOpenError);

    cb.recordSuccess();
    expect(() => cb.assertClosed()).not.toThrow();

    vi.useRealTimers();
  });
});

