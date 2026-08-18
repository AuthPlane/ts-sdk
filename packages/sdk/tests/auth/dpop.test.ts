import { exportJWK, generateKeyPair, jwtVerify, type JWK } from "jose";
import { assert, describe, expect, test } from "vitest";

import {
  DPoPKeyMaterial,
  DPoPProvider,
  InMemoryDPoPNonceStore,
  normalizeHtu,
  sha256Base64Url,
} from "../../src/auth/dpop.js";

describe("DPoPProvider / DPoPKeyMaterial", () => {
  test("DPoPProvider.createProof produces a verifiable DPoP proof with nonce + ath", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as JWK;

    const provider = new DPoPProvider({
      keyMaterial: new DPoPKeyMaterial({
        privateKey,
        publicJwk,
        algorithm: "ES256",
      }),
      nonceStore: new InMemoryDPoPNonceStore(16),
    });

    const proof = await provider.createProof({
      method: "POST",
      url: "https://auth.example.com/oauth/token",
      nonce: "nonce-123",
      accessToken: "access-token-xyz",
    });

    const [encodedHeader] = proof.split(".");
    assert(encodedHeader);
    const header = JSON.parse(
      Buffer.from(encodedHeader, "base64url").toString("utf-8"),
    ) as { typ: string; alg: string; jwk: JWK };

    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("ES256");
    expect(header.jwk).toBeDefined();

    const { payload } = await jwtVerify(proof, publicKey);
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://auth.example.com/oauth/token");
    expect(payload.nonce).toBe("nonce-123");
    expect(typeof payload.jti).toBe("string");
    expect(typeof payload.iat).toBe("number");
    expect(typeof payload.ath).toBe("string");
  });

  test("DPoPKeyMaterial.thumbprint is stable for the same key (RFC 7638)", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as JWK;
    const km1 = new DPoPKeyMaterial({ privateKey, publicJwk, algorithm: "ES256" });
    const km2 = new DPoPKeyMaterial({ privateKey, publicJwk, algorithm: "ES256" });
    expect(km1.thumbprint).toBe(km2.thumbprint);
    expect(km1.thumbprint.length).toBeGreaterThan(0);
  });

  test("DPoPKeyMaterial.fromPem imports PEM and derives matching public JWK", async () => {
    const { generateKeyPairSync } = await import("node:crypto");
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const km = await DPoPKeyMaterial.fromPem(privateKey as string, {
      algorithm: "ES256",
    });

    expect(km.algorithm).toBe("ES256");
    expect(km.publicJwk.kty).toBe("EC");
    expect(km.publicJwk.crv).toBe("P-256");
    expect(km.publicJwk.x).toBeTypeOf("string");
    expect(km.publicJwk.y).toBeTypeOf("string");
    expect(km.thumbprint.length).toBeGreaterThan(0);
  });

  test("DPoPKeyMaterial rejects unsupported algorithms", () => {
    const publicJwk: JWK = { kty: "EC", crv: "P-256", x: "x", y: "y" };
    expect(
      () =>
        new DPoPKeyMaterial({
          privateKey: {} as never,
          publicJwk,
          algorithm: "PS256" as never,
        }),
    ).toThrow(/DPoP algorithm must be one of/);
  });

  test("DPoPKeyMaterial defaults to ES256 when algorithm is omitted", () => {
    const publicJwk: JWK = { kty: "EC", crv: "P-256", x: "x", y: "y" };
    const km = new DPoPKeyMaterial({ privateKey: {} as never, publicJwk });
    expect(km.algorithm).toBe("ES256");
  });

  test("DPoPKeyMaterial.thumbprint supports RSA and rejects unknown kty", () => {
    const rsaJwk: JWK = { kty: "RSA", n: "modulus", e: "AQAB" };
    const km = new DPoPKeyMaterial({
      privateKey: {} as never,
      publicJwk: rsaJwk,
      algorithm: "RS256",
    });
    expect(km.thumbprint.length).toBeGreaterThan(0);

    const oddJwk: JWK = { kty: "oct", k: "..." } as unknown as JWK;
    const kmOdd = new DPoPKeyMaterial({
      privateKey: {} as never,
      publicJwk: oddJwk,
      algorithm: "ES256",
    });
    expect(() => kmOdd.thumbprint).toThrow(/Unsupported DPoP JWK type/);
  });

  test("DPoPKeyMaterial.thumbprint handles OKP key type", () => {
    const okpJwk: JWK = { kty: "OKP", crv: "Ed25519", x: "abc" };
    const km = new DPoPKeyMaterial({
      privateKey: {} as never,
      publicJwk: okpJwk,
      algorithm: "ES256",
    });
    expect(km.thumbprint.length).toBeGreaterThan(0);
  });

  test("normalizeHtu rejects malformed and host-less URLs", () => {
    expect(() => normalizeHtu("not a url")).toThrow(/must be absolute/);
    // mailto has no hostname
    expect(() => normalizeHtu("mailto:a@b.com")).toThrow(/must be absolute/);
  });

  test("normalizeHtu strips default ports and keeps custom ports", () => {
    expect(normalizeHtu("https://api.example.com:443/x")).toBe(
      "https://api.example.com/x",
    );
    expect(normalizeHtu("http://api.example.com:80/x")).toBe(
      "http://api.example.com/x",
    );
    expect(normalizeHtu("https://api.example.com:8443/x")).toBe(
      "https://api.example.com:8443/x",
    );
  });

  test("normalizeHtu defaults missing path to '/' and lowercases scheme/host", () => {
    expect(normalizeHtu("HTTPS://API.EXAMPLE.COM")).toBe(
      "https://api.example.com/",
    );
  });

  test("sha256Base64Url returns a non-empty base64url string", () => {
    const digest = sha256Base64Url("hello");
    expect(digest).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test("InMemoryDPoPNonceStore rejects non-positive maxEntries", () => {
    expect(() => new InMemoryDPoPNonceStore(0)).toThrow(/must be positive/);
    expect(() => new InMemoryDPoPNonceStore(-3)).toThrow(/must be positive/);
  });

  test("InMemoryDPoPNonceStore.put updates existing key in place (LRU touch)", () => {
    const store = new InMemoryDPoPNonceStore(2);
    store.put("k1", "n1");
    store.put("k2", "n2");
    store.put("k1", "n1-updated"); // existing key path
    expect(store.get("k1")).toBe("n1-updated");
    expect(store.get("k2")).toBe("n2");
  });

  test("InMemoryDPoPNonceStore.get returns '' for missing key", () => {
    const store = new InMemoryDPoPNonceStore();
    expect(store.get("missing")).toBe("");
  });

  test("DPoPProvider rejects non-positive proofTtlSeconds and uses default when omitted", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as JWK;
    const keyMaterial = new DPoPKeyMaterial({
      privateKey,
      publicJwk,
      algorithm: "ES256",
    });
    expect(
      () => new DPoPProvider({ keyMaterial, proofTtlSeconds: 0 }),
    ).toThrow(/must be positive/);
    // Default ttl + default nonceStore branches.
    const provider = new DPoPProvider({ keyMaterial });
    const proof = await provider.createProof({
      method: "GET",
      url: "https://api.example.com/x",
    });
    expect(typeof proof).toBe("string");
  });

  test("DPoPProvider uses noteNonce for subsequent createProof calls", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as JWK;
    const provider = new DPoPProvider({
      keyMaterial: new DPoPKeyMaterial({
        privateKey,
        publicJwk,
        algorithm: "ES256",
      }),
    });
    provider.noteNonce("https://api.example.com/x", "stored-nonce");
    expect(provider.currentNonce("https://api.example.com/x")).toBe(
      "stored-nonce",
    );

    const proof = await provider.createProof({
      method: "POST",
      url: "https://api.example.com/x",
    });
    const [, payloadB64] = proof.split(".");
    assert(payloadB64);
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf-8"),
    ) as { nonce?: string; ath?: string };
    expect(payload.nonce).toBe("stored-nonce");
    expect(payload.ath).toBeUndefined(); // accessToken omitted
  });

  test("DPoPProvider.buildHeadersAsync wraps createProof in a DPoP header", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(publicKey)) as JWK;
    const provider = new DPoPProvider({
      keyMaterial: new DPoPKeyMaterial({
        privateKey,
        publicJwk,
        algorithm: "ES256",
      }),
    });
    const headers = await provider.buildHeadersAsync(
      "GET",
      "http://api.example.com:8080/x",
    );
    expect(typeof headers.DPoP).toBe("string");
  });
});
