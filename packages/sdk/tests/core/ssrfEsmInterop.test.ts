import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// The SSRF guard is the one place the SDK imports a CommonJS dependency
// (ipaddr.js, no `exports` map). Vitest resolves that import through its own
// interop layer, which synthesises named exports a real `node` process never
// sees — so every in-process test of `isIpAllowed` passes regardless of the
// import form, and the regression this file guards against (a namespace
// import whose `.parse` is `undefined`, a swallowed TypeError, and a guard
// that rejects every address) is invisible to them. The only honest check is
// to build the package and load the emitted module under Node's own loader.

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(import.meta.url);

function runUnderNodeEsm(script: string): string {
  return execFileSync(process.execPath, ["--input-type=module", "-e", script], {
    cwd: PACKAGE_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

describe("ssrf built output under Node's ESM loader", () => {
  // `tsc -b` is incremental: a no-op when dist is current, a full emit when a
  // fresh checkout runs the suite before `npm run build`. Either way the
  // module exercised below is the one the package ships.
  beforeAll(() => {
    execFileSync(process.execPath, [require.resolve("typescript/bin/tsc"), "-b"], {
      cwd: PACKAGE_ROOT,
      stdio: "inherit",
    });
  }, 120_000);

  it("premise: a namespace import of ipaddr.js has no `parse` under node", () => {
    // Pins the packaging fact the default import exists to work around. If
    // ipaddr.js starts shipping named ESM exports this fails, and the comment
    // on the import in src/shared/ssrf.ts is then the thing to revisit.
    const shape = runUnderNodeEsm(
      'import * as ipaddr from "ipaddr.js"; process.stdout.write(typeof ipaddr.parse);'
    );
    expect(shape).toBe("undefined");
    // Explicit budget: the body is a synchronous execFileSync, so it cannot be
    // interrupted, and a cold `node` spawn on a contended runner would surface
    // as a timeout failure rather than as a guard signal.
  }, 60_000);

  it("isIpAllowed classifies addresses through the real loader", () => {
    const verdicts = runUnderNodeEsm(
      [
        'import { isIpAllowed } from "./dist/shared/ssrf.js";',
        "process.stdout.write(JSON.stringify([",
        '  isIpAllowed("8.8.8.8"),',
        '  isIpAllowed("2001:4860:4860::8888"),',
        '  isIpAllowed("10.0.0.1"),',
        '  isIpAllowed("127.0.0.1", { allowLocalhost: true }),',
        '  isIpAllowed("not-an-ip"),',
        "]));",
      ].join("\n")
    );
    // Public allowed, private blocked, loopback opt-in honoured, garbage
    // rejected — a broken import collapses all five to `false`.
    expect(JSON.parse(verdicts)).toEqual([true, true, false, true, false]);
  }, 60_000);
});
