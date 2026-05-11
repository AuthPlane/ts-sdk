import { copyFileSync, existsSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkgDir = process.cwd();

const rel = relative(join(repoRoot, "packages"), pkgDir);
if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
	console.error(
		`sync-package-files: expected cwd inside ${join(repoRoot, "packages")}, got ${pkgDir}`,
	);
	process.exit(1);
}

const files = ["LICENSE", "CHANGELOG.md"];
for (const name of files) {
	const src = join(repoRoot, name);
	const dest = join(pkgDir, name);
	if (!existsSync(src)) {
		console.error(`sync-package-files: missing ${src}`);
		process.exit(1);
	}
	copyFileSync(src, dest);
}
