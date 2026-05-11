import { describe, expect, test } from "vitest";
import {
  DPoPKeyMaterial,
  DPoPProvider,
  FetchSettings,
  GRANT_TYPE_TOKEN_EXCHANGE,
  TOKEN_TYPE_ACCESS_TOKEN,
  clientCredentialsGrant,
  exchange,
  introspectToken,
  revokeToken,
} from "../../src/auth/index.js";

describe("index exports", () => {
  test("exports public API symbols", () => {
    expect(typeof FetchSettings).toBe("function");
    expect(typeof clientCredentialsGrant).toBe("function");
    expect(typeof exchange).toBe("function");
    expect(typeof introspectToken).toBe("function");
    expect(typeof revokeToken).toBe("function");
    expect(typeof DPoPProvider).toBe("function");
    expect(typeof DPoPKeyMaterial).toBe("function");
    expect(GRANT_TYPE_TOKEN_EXCHANGE).toBe(
      "urn:ietf:params:oauth:grant-type:token-exchange",
    );
    expect(TOKEN_TYPE_ACCESS_TOKEN).toBe(
      "urn:ietf:params:oauth:token-type:access_token",
    );
  });
});
