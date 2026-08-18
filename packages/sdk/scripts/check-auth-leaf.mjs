// Enforces the auth leaf property: nothing under `src/auth` may import from
// `core`, so `@authplane/sdk/auth` stays importable without dragging the
// resource-server half of the package in behind it.
//
// Scope is `src/auth` only, and stays there now that tests are type-checked and
// linted too. The property being protected belongs to the published artifact,
// and tests are not published — `tsconfig.json` includes `src` and nothing
// else. A test is entitled to drive both halves at once: seven files under
// `tests/` and `conformance-tests/` already import from `src/auth` and
// `src/core` together, and none of them changes what a consumer of
// `@authplane/sdk/auth` ends up loading. Extending this check over them would
// forbid legitimate tests while protecting nothing.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const authDir = join(process.cwd(), "src", "auth");
const forbiddenImportPatterns = [
	/from\s+["'][^"']*core\//,
	/import\s*\(\s*["'][^"']*core\//,
];

function walkTsFiles(dir) {
	const files = [];
	for (const entry of readdirSync(dir)) {
		const fullPath = join(dir, entry);
		const stat = statSync(fullPath);
		if (stat.isDirectory()) {
			files.push(...walkTsFiles(fullPath));
			continue;
		}
		if (fullPath.endsWith(".ts")) {
			files.push(fullPath);
		}
	}
	return files;
}

const offenders = [];
for (const filePath of walkTsFiles(authDir)) {
	const content = readFileSync(filePath, "utf8");
	if (forbiddenImportPatterns.some((pattern) => pattern.test(content))) {
		offenders.push(filePath);
	}
}

if (offenders.length > 0) {
	console.error("auth leaf violation: auth files importing core detected");
	for (const filePath of offenders) {
		console.error(` - ${filePath}`);
	}
	process.exit(1);
}

console.log("auth leaf check passed");
