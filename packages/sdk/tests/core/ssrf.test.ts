import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthplaneClient } from "../../src/core/index.js";
import { buildMetadataUrl } from "../../src/core/fetching/metadataUrl.js";
import { isIpAllowed } from "../../src/core/fetching/ssrf.js";

function buildTeredoAddress(options: {
  serverIpv4: [number, number, number, number];
  clientIpv4: [number, number, number, number];
  flags?: number;
  port?: number;
}): string {
  const flags = options.flags ?? 0;
  const port = options.port ?? 40000;
  const obfuscatedPort = (~port) & 0xffff;
  const [rawC0, rawC1, rawC2, rawC3] = options.clientIpv4;
  const obfuscate = (octet: number): number => (0xff ^ octet) & 0xff;
  const obfuscatedClient = [
    obfuscate(rawC0),
    obfuscate(rawC1),
    obfuscate(rawC2),
    obfuscate(rawC3),
  ] as const;

  return [
    "2001",
    "0000",
    ((options.serverIpv4[0] << 8) | options.serverIpv4[1]).toString(16).padStart(4, "0"),
    ((options.serverIpv4[2] << 8) | options.serverIpv4[3]).toString(16).padStart(4, "0"),
    (flags & 0xffff).toString(16).padStart(4, "0"),
    obfuscatedPort.toString(16).padStart(4, "0"),
    ((obfuscatedClient[0] << 8) | obfuscatedClient[1]).toString(16).padStart(4, "0"),
    ((obfuscatedClient[2] << 8) | obfuscatedClient[3]).toString(16).padStart(4, "0"),
  ].join(":");
}

describe("buildMetadataUrl", () => {
  it("builds metadata URL for root issuer", () => {
    const url = buildMetadataUrl("https://auth.example.com");
    expect(url).toBe("https://auth.example.com/.well-known/oauth-authorization-server");
  });

  it("inserts .well-known before issuer path", () => {
    const url = buildMetadataUrl("https://auth.example.com/org/tenant");
    expect(url).toBe(
      "https://auth.example.com/.well-known/oauth-authorization-server/org/tenant"
    );
  });

  // RFC 8414 §3.1: derivation strips the issuer path's terminating slash when
  // building the `.well-known` URL (previously asserted only by a source
  // comment; pin it so the strip cannot silently regress).
  it("drops the terminating slash of the issuer path during derivation", () => {
    expect(buildMetadataUrl("https://auth.example.com/tenant-a/")).toBe(
      "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a"
    );
  });

  it("rejects an issuer carrying a query component", () => {
    expect(() => buildMetadataUrl("https://auth.example.com/t?x=1")).toThrow(
      TypeError
    );
  });

  it("rejects an issuer carrying a fragment component", () => {
    expect(() => buildMetadataUrl("https://auth.example.com/t#frag")).toThrow(
      TypeError
    );
  });

  it("rejects an issuer carrying a bare empty query", () => {
    expect(() => buildMetadataUrl("https://auth.example.com/t?")).toThrow(
      TypeError
    );
  });

  it("does not leak the rejected query value into the error message", () => {
    expect(() =>
      buildMetadataUrl("https://auth.example.com/t?token=secret")
    ).toThrow("https://auth.example.com/t");
    expect(() =>
      buildMetadataUrl("https://auth.example.com/t?token=secret")
    ).not.toThrow("secret");
  });
});

describe("AuthplaneClient.create rejects a query-bearing issuer", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects before any network fetch", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await expect(
      AuthplaneClient.create({ issuer: "https://auth.example.com/t?x=1" })
    ).rejects.toThrow(TypeError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("isIpAllowed", () => {
  it("allows public addresses by default", () => {
    expect(isIpAllowed("8.8.8.8")).toBe(true);
    expect(isIpAllowed("2001:4860:4860::8888")).toBe(true);
  });

  it("blocks private and loopback by default", () => {
    expect(isIpAllowed("10.0.0.1")).toBe(false);
    expect(isIpAllowed("127.0.0.1")).toBe(false);
    expect(isIpAllowed("::1")).toBe(false);
    expect(isIpAllowed("fc00::1")).toBe(false);
    expect(isIpAllowed("fe80::1")).toBe(false);
  });

  it("returns false for invalid IP strings", () => {
    expect(isIpAllowed("not-an-ip")).toBe(false);
  });

  it("blocks multicast by default", () => {
    expect(isIpAllowed("224.0.0.1")).toBe(false);
  });

  it("blocks embedded IPv4 bypass patterns by default", () => {
    expect(isIpAllowed("::ffff:127.0.0.1")).toBe(false);
    expect(isIpAllowed("::ffff:192.168.1.1")).toBe(false);
    expect(isIpAllowed("2002:c0a8:0101::1")).toBe(false);
    const teredoWithPrivateClient = buildTeredoAddress({
      serverIpv4: [8, 8, 8, 8],
      clientIpv4: [10, 0, 0, 1],
    });
    expect(isIpAllowed(teredoWithPrivateClient)).toBe(false);
  });

  it("can allow localhost and private networks with flags", () => {
    expect(isIpAllowed("127.0.0.1", { allowLocalhost: true })).toBe(true);
    expect(isIpAllowed("10.0.0.1", { allowPrivateNetworks: true })).toBe(true);
    expect(isIpAllowed("::1", { allowLocalhost: true })).toBe(true);
    expect(isIpAllowed("fc00::1", { allowPrivateNetworks: true })).toBe(true);
    expect(isIpAllowed("::ffff:127.0.0.1", { allowLocalhost: true })).toBe(true);
    expect(isIpAllowed("::ffff:10.0.0.1", { allowPrivateNetworks: true })).toBe(
      true,
    );

    const teredoWithPrivateClient = buildTeredoAddress({
      serverIpv4: [8, 8, 8, 8],
      clientIpv4: [10, 0, 0, 1],
    });
    expect(isIpAllowed(teredoWithPrivateClient, { allowPrivateNetworks: true })).toBe(
      true,
    );
  });
});
