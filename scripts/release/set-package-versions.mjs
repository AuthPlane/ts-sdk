#!/usr/bin/env node
/**
 * Bump `version` on the root + workspace packages and align:
 * - `peerDependencies["@authplane/sdk"]` → `^<version>`
 * - `devDependencies["@authplane/sdk"]` on adapter packages → `^<version>` (matches peer; avoids "*" in published tarballs)
 *
 * Preserves each package.json indent (tabs vs 2 spaces) to avoid noisy release diffs.
 *
 * Updates `package-lock.json` workspace snapshots (`packages[""]`, `packages/sdk`, …) in place
 * instead of running `npm install --package-lock-only`, so the lockfile does not pick up
 * unrelated transitive resolution changes during release (only version / dep string bumps).
 *
 * Usage: node scripts/release/set-package-versions.mjs <version>
 * Example: node scripts/release/set-package-versions.mjs 1.2.3-rc.0
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "../..");

const version = process.argv[2];
if (!version) {
	console.error("usage: set-package-versions.mjs <version>");
	process.exit(1);
}

const files = [
	"package.json",
	"packages/sdk/package.json",
	"packages/mcp/package.json",
	"packages/fastmcp/package.json",
	"packages/hono/package.json",
	"packages/nestjs/package.json",
];

/**
 * @param {string} rawOriginal
 * @returns {string}
 */
function packageJsonIndent(rawOriginal) {
	return /\n\t"/.test(rawOriginal) ? "\t" : "  ";
}

/**
 * @param {unknown} obj
 * @param {string} rawOriginal
 */
function stringifyPackageJson(obj, rawOriginal) {
	const indent = packageJsonIndent(rawOriginal);
	return `${JSON.stringify(obj, null, indent)}\n`;
}

/**
 * @param {string} relFile
 */
function workspaceDirFromPackageJsonRel(relFile) {
	if (relFile === "package.json") {
		return "";
	}
	return path.dirname(relFile);
}

/**
 * Sync workspace package snapshots in package-lock.json v3 to match on-disk package.json
 * files (already written). Does not re-resolve the full graph.
 *
 * @param {string} repoRoot
 * @param {Map<string, object>} packagesByWorkspaceDir — keys: "" | "packages/sdk" | …
 */
function syncPackageLockWorkspaceSnapshots(repoRoot, packagesByWorkspaceDir) {
	const lockPath = path.join(repoRoot, "package-lock.json");
	const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));

	const rootPkg = packagesByWorkspaceDir.get("");
	if (!rootPkg) {
		throw new Error("internal: missing root package.json in map");
	}
	lock.packages[""].version = rootPkg.version;

	const workspaceDirs = [
		"packages/sdk",
		"packages/mcp",
		"packages/fastmcp",
		"packages/hono",
		"packages/nestjs",
	];
	for (const dir of workspaceDirs) {
		const pkg = packagesByWorkspaceDir.get(dir);
		if (!pkg) {
			throw new Error(`internal: missing ${dir}/package.json in map`);
		}
		const entry = lock.packages[dir];
		if (!entry) {
			throw new Error(`package-lock.json: missing packages[${JSON.stringify(dir)}]`);
		}
		entry.name = pkg.name;
		entry.version = pkg.version;
		for (const k of [
			"dependencies",
			"devDependencies",
			"peerDependencies",
			"optionalDependencies",
		]) {
			if (pkg[k] && Object.keys(pkg[k]).length > 0) {
				entry[k] = { ...pkg[k] };
			} else {
				delete entry[k];
			}
		}
	}

	fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
}

/** @type {Map<string, object>} */
const packagesByWorkspaceDir = new Map();

for (const rel of files) {
	const p = path.join(root, rel);
	const raw = fs.readFileSync(p, "utf8");
	const pkg = JSON.parse(raw);
	pkg.version = version;
	if (pkg.peerDependencies?.["@authplane/sdk"]) {
		pkg.peerDependencies["@authplane/sdk"] = `^${version}`;
	}
	if (pkg.devDependencies?.["@authplane/sdk"]) {
		pkg.devDependencies["@authplane/sdk"] = `^${version}`;
	}
	packagesByWorkspaceDir.set(workspaceDirFromPackageJsonRel(rel), pkg);
	fs.writeFileSync(p, stringifyPackageJson(pkg, raw));
}

syncPackageLockWorkspaceSnapshots(root, packagesByWorkspaceDir);
