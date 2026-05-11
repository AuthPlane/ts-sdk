import { describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, jwtVerify } from "jose";
import { createHash } from "node:crypto";

import {
  DPoPKeyMaterial,
  DPoPProvider,
  InMemoryDPoPNonceStore,
  InMemoryDPoPReplayStore,
  verifyDpopProof,
} from "../../src/core/dpop.js";

function sha256Base64Url(value: string): string {
  const digest = createHash("sha256").update(value, "utf-8").digest();
  return digest
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function normalizeHtu(url: string): string {
  const parsed = new URL(url);
  parsed.hash = "";
  return parsed.toString();
}

describe("dpop: DPoPProvider", () => {
  it("buildHeadersAsync includes nonce, htm/htu and ath; verifyDpopProof passes", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as Parameters<
      typeof DPoPProvider
    >[0]["publicJwk"];

    const nonceStore = new InMemoryDPoPNonceStore(16);
    const provider = new DPoPProvider({
      keyMaterial: new DPoPKeyMaterial({
        privateKey,
        publicJwk,
        algorithm: "ES256",
      }),
      nonceStore,
    });

    const method = "POST";
    const url = "https://api.example.com/resource#frag";
    const accessToken = "at_1";
    const nonce = "nonce_1";

    provider.noteNonce(url, nonce);

    const headers = await provider.buildHeadersAsync(method, url, {
      accessToken,
    });

    expect(typeof headers.DPoP).toBe("string");

    const verified = await jwtVerify(headers.DPoP, publicKey, { typ: "dpop+jwt" });
    const payload = verified.payload as Record<string, unknown>;

    expect(payload.htm).toBe(method);
    expect(payload.htu).toBe(normalizeHtu(url));
    expect(payload.nonce).toBe(nonce);
    expect(payload.ath).toBe(sha256Base64Url(accessToken));

    const expectedJkt = await (await import("jose")).calculateJwkThumbprint(publicJwk as any);
    await expect(
      verifyDpopProof({
        proof: headers.DPoP,
        method,
        url,
        accessToken,
        expectedJkt: String(expectedJkt),
        maxAgeSeconds: 300,
        clockSkewSeconds: 0,
        replayStore: new InMemoryDPoPReplayStore(),
      }),
    ).resolves.toHaveProperty("jti");
  });

  it("verifyDpopProof rejects when htm mismatches", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as Parameters<
      typeof DPoPProvider
    >[0]["publicJwk"];

    const provider = new DPoPProvider({
      keyMaterial: new DPoPKeyMaterial({
        privateKey,
        publicJwk,
        algorithm: "ES256",
      }),
    });

    const proofHeaders = await provider.buildHeadersAsync("POST", "https://api.example.com/x", {
      accessToken: "at_1",
    });

    const expectedJkt = await (await import("jose")).calculateJwkThumbprint(publicJwk as any);

    await expect(
      verifyDpopProof({
        proof: proofHeaders.DPoP,
        method: "GET",
        url: "https://api.example.com/x",
        accessToken: "at_1",
        expectedJkt: String(expectedJkt),
        maxAgeSeconds: 300,
        clockSkewSeconds: 0,
        replayStore: new InMemoryDPoPReplayStore(),
      }),
    ).rejects.toThrow(/htm mismatch/i);
  });
});

