import { expect, it } from "vitest";

import { ProtocolError } from "../../src/auth/errors.js";
import { parseTokenResponse } from "../../src/auth/oauth/parsing.js";

it(
  "rfc6749-token-response-token-type-must-be-supported",
  "rejects unsupported token_type (RFC 6749)",
  () => {
    expect(() =>
      parseTokenResponse({
        access_token: "tok",
        token_type: "N_A",
        expires_in: 10,
      }),
    ).toThrow(ProtocolError);
  },
);

it(
  "rfc9449-token-response-token-type-dpop-must-be-accepted",
  "accepts token_type DPoP (RFC 9449)",
  () => {
    const resp = parseTokenResponse({
      access_token: "tok",
      token_type: "DPoP",
      expires_in: 10,
      scope: "",
    });
    expect(resp.tokenType).toBe("DPoP");
  },
);

it(
  "rfc6749-token-response-expires-in-must-be-non-negative-integer",
  "rejects negative expires_in (RFC 6749)",
  () => {
    expect(() =>
      parseTokenResponse({
        access_token: "tok",
        token_type: "Bearer",
        expires_in: -1,
      }),
    ).toThrow(ProtocolError);
  },
);

it(
  "rfc6749-token-response-expires-in-must-be-non-negative-integer",
  "rejects non-integer expires_in when present",
  () => {
    expect(() =>
      parseTokenResponse({
        access_token: "tok",
        token_type: "Bearer",
        expires_in: 1.5,
      }),
    ).toThrow(ProtocolError);
  },
);

it("accepts token_type Bearer", () => {
  const resp = parseTokenResponse({
    access_token: "tok",
    token_type: "Bearer",
    expires_in: 3600,
    scope: "",
  });
  expect(resp.tokenType).toBe("Bearer");
  expect(resp.expiresIn).toBe(3600);
});

it("allows missing expires_in (expiresIn defaults to 0)", () => {
  const resp = parseTokenResponse({
    access_token: "tok",
    token_type: "Bearer",
  });
  expect(resp.expiresIn).toBe(0);
});

