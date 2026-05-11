#!/usr/bin/env node
/**
 * Exit 0 if CHANGELOG.md has at least one `- ` bullet under ## [Unreleased].
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const changelog = path.join(__dirname, "../../CHANGELOG.md");
const text = fs.readFileSync(changelog, "utf8");
const marker = "## [Unreleased]";
const i = text.indexOf(marker);
if (i < 0) {
	console.error("CHANGELOG.md: missing ## [Unreleased] section");
	process.exit(1);
}
const after = text.slice(i + marker.length);
const next = after.search(/\n## \[/);
const section = next < 0 ? after : after.slice(0, next);
if (!/^- /m.test(section)) {
	console.error("CHANGELOG.md: [Unreleased] has no bullet lines starting with '- '");
	process.exit(1);
}
