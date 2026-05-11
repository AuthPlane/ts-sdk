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
