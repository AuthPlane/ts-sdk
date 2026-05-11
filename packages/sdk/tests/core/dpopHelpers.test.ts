import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";

import {
  InMemoryDPoPNonceStore,
  InMemoryDPoPReplayStore,
  requireDpopProof,
  verifyDpopProof,
} from "../../src/core/dpop.js";
import {
  DPoPBindingMismatch,
  DPoPProofMissing,
  DPoPReplayDetected,
  InvalidDPoPProof,
} from "../../src/core/errors.js";

function sha256Base64Url(value: string): string {
  const digest = createHash("sha256").update(value, "utf-8").digest();
  return digest
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

describe("dpop helpers", () => {
  it("requires proof when ctx.proof is missing", () => {
    expect(() => requireDpopProof(undefined)).toThrow(DPoPProofMissing);
    expect(() =>
      requireDpopProof({
        method: "GET",
        url: "https://example.com",
      }),
    ).toThrow(DPoPProofMissing);

    expect(
      requireDpopProof({
        method: "GET",
        url: "https://example.com",
        proof: "proof_1",
      }),
    ).toBe("proof_1");
  });

  it("InMemoryDPoPNonceStore evicts oldest entries past maxEntries", () => {
    const store = new InMemoryDPoPNonceStore(2);
    store.put("k1", "n1");
    store.put("k2", "n2");
    store.put("k3", "n3");

    expect(store.get("k1")).toBe("");
    expect(store.get("k2")).toBe("n2");
    expect(store.get("k3")).toBe("n3");

    // get() is idempotent but also moves the key to "most recently used".
    store.put("k4", "n4");
    // With LRU semantics, k2 should be evicted after k3/k2 were "touched".
    expect(store.get("k2")).toBe("");
    expect(store.get("k3")).toBe("n3");
    expect(store.get("k4")).toBe("n4");
  });

  it("InMemoryDPoPReplayStore allows first proof, rejects replayed jti", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);

    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as NonNullable<unknown> as any;

    const expectedJkt = await calculateJwkThumbprint(publicJwk);

    const method = "GET";
    const url = "https://api.example.com/resource";
    const accessToken = "at_1";

    const proofPayload = {
      htm: method,
      // verifyDpopProof normalizes hash; we intentionally include a fragment.
      htu: `${url}#fragment`,
      iat: nowSeconds,
      exp: nowSeconds + 120,
      jti: "jti_replay_1",
      ath: sha256Base64Url(accessToken),
    };

    const proof = await new SignJWT(proofPayload as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
      .sign(privateKey);

    const store = new InMemoryDPoPReplayStore();

    const verified1 = await verifyDpopProof({
      proof,
      method,
      url,
      accessToken,
      expectedJkt: String(expectedJkt),
      maxAgeSeconds: 60,
      clockSkewSeconds: 0,
      replayStore: store,
    });

    expect(verified1.jti).toBe("jti_replay_1");

    await expect(
      verifyDpopProof({
        proof,
        method,
        url,
        accessToken,
        expectedJkt: String(expectedJkt),
        maxAgeSeconds: 60,
        clockSkewSeconds: 0,
        replayStore: store,
      }),
    ).rejects.toThrow(DPoPReplayDetected);

    vi.useRealTimers();
  });

  it("throws DPoPBindingMismatch when expected jkt differs", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as NonNullable<unknown> as any;

    const method = "GET";
    const url = "https://api.example.com/resource";
    const accessToken = "at_1";

    const proofPayload = {
      htm: method,
      htu: url,
      iat: nowSeconds,
      exp: nowSeconds + 120,
      jti: "jti_bind_1",
      ath: sha256Base64Url(accessToken),
    };

    const proof = await new SignJWT(proofPayload as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
      .sign(privateKey);

    await expect(
      verifyDpopProof({
        proof,
        method,
        url,
        accessToken,
        expectedJkt: "wrong_jkt",
        maxAgeSeconds: 60,
        clockSkewSeconds: 0,

        replayStore: new InMemoryDPoPReplayStore(),
      }),
    ).rejects.toThrow(DPoPBindingMismatch);

    vi.useRealTimers();
  });

  it("throws InvalidDPoPProof when jwk is missing from protected header", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const { privateKey } = await generateKeyPair("ES256");

    const proofPayload = {
      htm: "GET",
      htu: "https://api.example.com/resource",
      iat: nowSeconds,
      exp: nowSeconds + 120,
      jti: "jti_missing_jwk",
      ath: sha256Base64Url("at_1"),
    };

    const proof = await new SignJWT(proofPayload as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt" })
      .sign(privateKey);

    await expect(
      verifyDpopProof({
        proof,
        method: "GET",
        url: "https://api.example.com/resource",
        accessToken: "at_1",
        expectedJkt: "any",
        maxAgeSeconds: 60,
        clockSkewSeconds: 0,

        replayStore: new InMemoryDPoPReplayStore(),
      }),
    ).rejects.toThrow(InvalidDPoPProof);

    vi.useRealTimers();
  });

  it("throws InvalidDPoPProof when ath mismatches provided accessToken", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as NonNullable<unknown> as any;

    const expectedJkt = await calculateJwkThumbprint(publicJwk);

    const method = "GET";
    const url = "https://api.example.com/resource";
    const proofAccessToken = "at_1";
    const providedAccessToken = "at_2";

    const proofPayload = {
      htm: method,
      htu: url,
      iat: nowSeconds,
      exp: nowSeconds + 120,
      jti: "jti_ath_mismatch_1",
      ath: sha256Base64Url(proofAccessToken),
    };

    const proof = await new SignJWT(proofPayload as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
      .sign(privateKey);

    await expect(
      verifyDpopProof({
        proof,
        method,
        url,
        accessToken: providedAccessToken,
        expectedJkt: String(expectedJkt),
        maxAgeSeconds: 60,
        clockSkewSeconds: 0,

        replayStore: new InMemoryDPoPReplayStore(),
      }),
    ).rejects.toThrow(/ath mismatch/i);

    vi.useRealTimers();
  });

  it("throws InvalidDPoPProof when iat is in the future", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as NonNullable<unknown> as any;

    const expectedJkt = await calculateJwkThumbprint(publicJwk);

    const method = "GET";
    const url = "https://api.example.com/resource";
    const accessToken = "at_1";

    const proofPayload = {
      htm: method,
      htu: url,
      iat: nowSeconds + 120, // future
      exp: nowSeconds + 240,
      jti: "jti_future_1",
      ath: sha256Base64Url(accessToken),
    };

    const proof = await new SignJWT(proofPayload as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
      .sign(privateKey);

    await expect(
      verifyDpopProof({
        proof,
        method,
        url,
        accessToken,
        expectedJkt: String(expectedJkt),
        maxAgeSeconds: 60,
        clockSkewSeconds: 0,

        replayStore: new InMemoryDPoPReplayStore(),
      }),
    ).rejects.toThrow(/iat is in the future/i);

    vi.useRealTimers();
  });

  it("throws InvalidDPoPProof when proof is too old", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T00:00:00Z"));

    const nowSeconds = Math.floor(Date.now() / 1000);
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as NonNullable<unknown> as any;

    const expectedJkt = await calculateJwkThumbprint(publicJwk);

    const method = "GET";
    const url = "https://api.example.com/resource";
    const accessToken = "at_1";

    const maxAgeSeconds = 60;
    const proofPayload = {
      htm: method,
      htu: url,
      iat: nowSeconds - (maxAgeSeconds + 10),
      // Keep exp in the future so jose passes signature+timestamp checks.
      exp: nowSeconds + 360,
      jti: "jti_too_old_1",
      ath: sha256Base64Url(accessToken),
    };

    const proof = await new SignJWT(proofPayload as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
      .sign(privateKey);

    await expect(
      verifyDpopProof({
        proof,
        method,
        url,
        accessToken,
        expectedJkt: String(expectedJkt),
        maxAgeSeconds,
        clockSkewSeconds: 0,

        replayStore: new InMemoryDPoPReplayStore(),
      }),
    ).rejects.toThrow(/too old/i);

    vi.useRealTimers();
  });

});

