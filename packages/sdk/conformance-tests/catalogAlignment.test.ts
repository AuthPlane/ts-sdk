import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import yaml from "yaml";

type CatalogCase = { id: string };

type Catalog = {
  cases: CatalogCase[];
};

function walkDirRecursive(dir: string): string[] {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkDirRecursive(p));
      continue;
    }
    if (entry.isFile()) {
      files.push(p);
    }
  }

  return files;
}

function extractConformanceIdsFromDirs(dirs: string[]): Set<string> {
  const ids = new Set<string>();
  const idRe = /conformanceCase\s*\(\s*["'`]([^"'`]+)["'`]\s*,/g;

  for (const dir of dirs) {
    const testFiles = walkDirRecursive(dir).filter((p) =>
      p.endsWith(".test.ts"),
    );

    for (const filePath of testFiles) {
      const text = readFileSync(filePath, "utf-8");

      let m: RegExpExecArray | null;
      while ((m = idRe.exec(text)) !== null) {
        ids.add(m[1]);
      }
    }
  }

  return ids;
}

const skipCatalog = process.env.AUTHPLANE_CONFORMANCE_SKIP_CATALOG === "1";

describe.skipIf(skipCatalog)("conformance catalog alignment", () => {
  it("all catalog case ids are covered by conformance tests", () => {
    const envPath = process.env.CONFORMANCE_CATALOG_PATH;

    const candidates = [
      envPath,
      // oss-repo/conformance/ — sibling of ts-sdk, from test file location
      resolve(
        __dirname,
        "..",
        "..",
        "..",
        "..",
        "conformance",
        "oauth-sdk-conformance-catalog.yaml",
      ),
      // oss-repo/conformance/ — when cwd is packages/sdk (npm -w invocation)
      resolve(
        process.cwd(),
        "..",
        "..",
        "..",
        "conformance",
        "oauth-sdk-conformance-catalog.yaml",
      ),
      // oss-repo/conformance/ — when cwd is the ts-sdk repo root
      resolve(
        process.cwd(),
        "..",
        "conformance",
        "oauth-sdk-conformance-catalog.yaml",
      ),
    ];

    const catalogPath =
      candidates.filter((p): p is string => typeof p === "string").find((p) => existsSync(p)) ??
      candidates.find((p): p is string => typeof p === "string") ??
      candidates[0];

    if (!catalogPath || !existsSync(catalogPath)) {
      throw new Error(
        "Missing conformance catalog. Set CONFORMANCE_CATALOG_PATH or ensure oauth-sdk-conformance-catalog.yaml exists.",
      );
    }

    const text = readFileSync(catalogPath, "utf-8");
    const doc = yaml.parse(text) as Catalog;
    const catalogIds = new Set(doc.cases.map((c) => c.id));

    const conformanceIds = extractConformanceIdsFromDirs([
      // Regular unit tests that wrap conformanceCase(...)
      resolve(__dirname, "..", "tests"),
      // Python-like conformance suite layout: packages/sdk/conformance-tests/*
      __dirname,
    ]);

    const missing = Array.from(catalogIds).filter(
      (id) => !conformanceIds.has(id),
    );

    expect(missing).toEqual([]);
  });
});

