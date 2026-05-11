import { describe, expect, it } from "vitest";

import {
  type AuthProvider,
  ClientCredentialsProvider,
  isAuthProvider,
  toAuthProvider,
} from "../../src/core/authProvider.js";

describe("ClientCredentialsProvider", () => {
  it("builds RFC 6749 §2.3.1 HTTP Basic header", () => {
    const provider = new ClientCredentialsProvider("client_1", "secret_2");
    const expected = Buffer.from(
      `${encodeURIComponent("client_1")}:${encodeURIComponent("secret_2")}`,
    ).toString("base64");
    expect(provider.authHeaders()).toEqual({
      Authorization: `Basic ${expected}`,
    });
  });

  it("percent-encodes reserved characters in client_id and client_secret", () => {
    const provider = new ClientCredentialsProvider("id with space", "s@cret:!");
    const encodedId = encodeURIComponent("id with space");
    const encodedSecret = encodeURIComponent("s@cret:!");
    const expected = Buffer.from(`${encodedId}:${encodedSecret}`).toString(
      "base64",
    );
    expect(provider.authHeaders()).toEqual({
      Authorization: `Basic ${expected}`,
    });
  });
});

describe("isAuthProvider / toAuthProvider", () => {
  it("isAuthProvider detects AuthProvider instances by shape", () => {
    expect(isAuthProvider(new ClientCredentialsProvider("a", "b"))).toBe(true);
    expect(isAuthProvider({ authHeaders: () => ({}) })).toBe(true);
    expect(isAuthProvider({ clientId: "x", clientSecret: "y" })).toBe(false);
    expect(isAuthProvider(undefined)).toBe(false);
  });

  it("toAuthProvider wraps ASCredentials into ClientCredentialsProvider", () => {
    const provider = toAuthProvider({ clientId: "x", clientSecret: "y" });
    expect(provider).toBeInstanceOf(ClientCredentialsProvider);
  });

  it("toAuthProvider returns AuthProvider instances unchanged", () => {
    const custom: AuthProvider = {
      authHeaders: () => ({ Authorization: "Bearer tenant-A" }),
    };
    expect(toAuthProvider(custom)).toBe(custom);
  });

  it("toAuthProvider returns undefined when given undefined", () => {
    expect(toAuthProvider(undefined)).toBeUndefined();
  });
});
