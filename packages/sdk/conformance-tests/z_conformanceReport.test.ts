import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import yaml from "yaml";
import type { ConformanceResult } from "./conformanceCase.js";

type CatalogCase = { id: string };
type Catalog = {
  catalog_id?: string;
  catalog_version?: string;
  cases: CatalogCase[];
};

function resolveCatalogPath(): string {
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

  for (const c of candidates) {
    if (!c) continue;
    if (existsSync(c)) return c;
  }

  throw new Error(
    "Missing conformance catalog. Set CONFORMANCE_CATALOG_PATH or ensure oauth-sdk-conformance-catalog.yaml exists.",
  );
}

function buildConformanceMarkdown(payload: unknown): string {
  // Keep it simple and deterministic (alignment suite is already strict).
  return JSON.stringify(payload, null, 2) + "\n";
}

function loadResultsFromJsonlFiles(): Map<string, ConformanceResult> {
  const candidates = new Set<string>([
    resolve(process.cwd(), ".conformance-results"),
    // Ensure we also find results if vitest workers change cwd.
    resolve(__dirname, "..", ".conformance-results"),
  ]);

  const map = new Map<string, ConformanceResult>();
  const writtenAtByCase = new Map<string, number>();

  const expectedRunId = process.env.AUTHPLANE_CONFORMANCE_RUN_ID;

  for (const dir of candidates) {
    if (!existsSync(dir)) continue;

    const files = readdirSync(dir).filter(
      (n) => n.startsWith("conformance-results-") && n.endsWith(".jsonl"),
    );

    for (const file of files) {
      const text = readFileSync(resolve(dir, file), "utf-8");
      for (const line of text.split("\n")) {
        if (!line.trim()) continue;
        const parsed = JSON.parse(line) as ConformanceResult & {
          writtenAt: number;
          runId?: string;
        };
        if (expectedRunId && parsed.runId !== expectedRunId) continue;
        const prev = writtenAtByCase.get(parsed.caseId);
        if (prev === undefined || parsed.writtenAt >= prev) {
          writtenAtByCase.set(parsed.caseId, parsed.writtenAt);
          map.set(parsed.caseId, parsed);
        }
      }
    }
  }

  return map;
}

const skipCatalog = process.env.AUTHPLANE_CONFORMANCE_SKIP_CATALOG === "1";

describe.skipIf(skipCatalog)("conformance report", () => {
  it("writes conformance-report.json and conformance-report.md", () => {
    const catalogPath = resolveCatalogPath();
    const catalogText = readFileSync(catalogPath, "utf-8");
    const doc = yaml.parse(catalogText) as Catalog;
    const catalogIds = doc.cases.map((c) => c.id);

    const fileResults = loadResultsFromJsonlFiles();
    const globalResults = (globalThis as any).__AUTHPLANE_CONFORMANCE_RESULTS__ as
      | Map<string, ConformanceResult>
      | undefined;

    // Prefer file-based aggregation (works across workers); fallback to global map.
    const results = fileResults.size > 0 ? fileResults : globalResults;

    const entries = catalogIds.map((id) => {
      const r = results?.get(id);
      if (!r) {
        return { case_id: id, status: "not_run", coverage: { level: "full", gaps: [], note: "" } };
      }
      return {
        case_id: id,
        status: r.status,
        test_name: r.testName,
        coverage: r.coverage,
        failure: r.failure ? { message: r.failure.message, stack: r.failure.stack } : undefined,
      };
    });

    const total = entries.length;
    const passed = entries.filter((e) => e.status === "passed").length;
    const failed = entries.filter((e) => e.status === "failed").length;
    const not_run = entries.filter((e) => e.status === "not_run").length;

    const pkg = JSON.parse(
      readFileSync(resolve(process.cwd(), "package.json"), "utf-8"),
    ) as { name?: string; version?: string };

    const payload = {
      catalog_id: doc.catalog_id ?? "oauth-sdk-conformance-catalog",
      catalog_version: doc.catalog_version ?? "",
      implementation: { name: pkg.name ?? "authplane-core", version: pkg.version ?? "", language: "TypeScript" },
      runner: { tool: "vitest", exit_status: failed > 0 ? 1 : 0 },
      summary: { total, passed, failed, skipped: 0, not_run },
      cases: entries,
    };

    const jsonOut = resolve(process.cwd(), "conformance-report.json");
    const mdOut = resolve(process.cwd(), "conformance-report.md");

    writeFileSync(jsonOut, JSON.stringify(payload, null, 2) + "\n", "utf-8");
    writeFileSync(mdOut, buildConformanceMarkdown(payload), "utf-8");
    expect(true).toBe(true);
  });
});

