import { describe, expect, test } from "vitest";
import { DPoPNonceRequiredError } from "../../src/auth/errors.js";

describe("errors", () => {
  test("DPoPNonceRequiredError exposes nonce and metadata", () => {
    const err = new DPoPNonceRequiredError("nonce required", "nonce-123");
    expect(err.name).toBe("DPoPNonceRequiredError");
    expect(err.code).toBe("use_dpop_nonce");
    expect(err.statusCode).toBe(400);
    expect(err.nonce).toBe("nonce-123");
  });
});
