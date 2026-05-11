import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  conformanceCase,
  maybeRethrowConformanceError,
  normalizeConformanceError,
} from "../../conformance-tests/conformanceCase.js";

// Enable catch-path coverage inside conformanceCase without failing the test suite.
beforeAll(() => {
  globalThis.__AUTHPLANE_CONFORMANCE_RETHROW_ERRORS__ = false;
});

// These conformanceCase invocations intentionally throw to exercise the production `catch` path.
conformanceCase("cov-conformanceCase-throw-string", "conformanceCase catch: non-Error throwable", async () => {
  throw "not-an-error";
});

conformanceCase("cov-conformanceCase-throw-error", "conformanceCase catch: Error instance", async () => {
  throw new Error("boom");
});

describe("conformanceCase helpers", () => {
  it("normalizeConformanceError returns the same Error instance", () => {
    const err = new Error("boom");
    const normalized = normalizeConformanceError(err);
    expect(normalized).toBe(err);
    expect(normalized.message).toBe("boom");
  });

  it("normalizeConformanceError converts non-Error throwables to Error", () => {
    const normalized = normalizeConformanceError("not-an-error");
    expect(normalized).toBeInstanceOf(Error);
    expect(normalized.message).toBe("not-an-error");
  });

  it("maybeRethrowConformanceError throws when shouldRethrow=true", () => {
    let caught: unknown = undefined;
    try {
      maybeRethrowConformanceError("boom", true);
    } catch (err) {
      caught = err;
    }

    expect(caught).toBe("boom");
  });

  it("maybeRethrowConformanceError does not throw when shouldRethrow=false", () => {
    expect(() => maybeRethrowConformanceError("boom", false)).not.toThrow();
  });
});

afterAll(() => {
  const map = globalThis.__AUTHPLANE_CONFORMANCE_RESULTS__;
  expect(map).toBeDefined();
  expect(map!.get("cov-conformanceCase-throw-string")?.status).toBe("failed");
  expect(map!.get("cov-conformanceCase-throw-error")?.status).toBe("failed");
  expect(map!.get("cov-conformanceCase-throw-error")?.failure?.message).toBe("boom");
});

