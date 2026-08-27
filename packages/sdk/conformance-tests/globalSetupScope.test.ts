import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { TestProject } from "vitest/node";
import { resolveRunId } from "./conformanceCase.js";
import { setup } from "./globalSetup.js";

/**
 * The run scope, tested directly.
 *
 * This is the fix for "a pinned run id retires nothing", and it had no test:
 * reverting `setup()` to its pre-fix form left the whole suite green, 418 for
 * 418, because nothing imports this module. The case it was paired with in the
 * mutation matrix exercises `loadResults`' file filter, which is a different
 * function — so the matrix read as though the Critical were covered when it was
 * not.
 *
 * `setup` is directly testable: it takes a `TestProject` and its only other
 * effect is the env write.
 */

let prev: string | undefined;

// Only the assignment is under test here; `setup` stores the project and reads
// nothing off it.
const PROJECT = {} as TestProject;

beforeEach(() => {
	prev = process.env.AUTHPLANE_CONFORMANCE_RUN_ID;
});

afterEach(() => {
	if (prev === undefined) delete process.env.AUTHPLANE_CONFORMANCE_RUN_ID;
	else process.env.AUTHPLANE_CONFORMANCE_RUN_ID = prev;
});

describe("setup", () => {
	it("does not reuse a scope across invocations under a pinned env value", () => {
		// The regression. Exporting AUTHPLANE_CONFORMANCE_RUN_ID once made every
		// invocation write under the same slug, so the pruner classified the
		// previous run's files as this run's and kept them, and the failure-first
		// merge turned a stale failure into a permanent one.
		process.env.AUTHPLANE_CONFORMANCE_RUN_ID = "pinned";
		setup(PROJECT);
		const first = process.env.AUTHPLANE_CONFORMANCE_RUN_ID;

		process.env.AUTHPLANE_CONFORMANCE_RUN_ID = "pinned";
		setup(PROJECT);
		const second = process.env.AUTHPLANE_CONFORMANCE_RUN_ID;

		expect(first).not.toBe(second);
	});

	it("keeps the env value as a label", () => {
		process.env.AUTHPLANE_CONFORMANCE_RUN_ID = "ci-run-7";
		setup(PROJECT);

		expect(process.env.AUTHPLANE_CONFORMANCE_RUN_ID).toMatch(/^ci-run-7-/);
	});

	it("assigns a scope when the env carries none, and when it carries an empty one", () => {
		// `??=` left an explicitly empty value in place, and an empty value reads
		// downstream as "no run id" — a scope matching every record, including the
		// previous run's.
		for (const initial of [undefined, ""]) {
			if (initial === undefined)
				delete process.env.AUTHPLANE_CONFORMANCE_RUN_ID;
			else process.env.AUTHPLANE_CONFORMANCE_RUN_ID = initial;

			setup(PROJECT);

			expect(process.env.AUTHPLANE_CONFORMANCE_RUN_ID).toMatch(/^vitest-.+/);
		}
	});
});

describe("resolveRunId", () => {
	it("throws rather than falling back when no scope was assigned", () => {
		// The fallback it replaced was the quietest possible failure: workers tag
		// records `default`, the teardown reads the generated id, every record is
		// filtered out on the run-id check, and the write is skipped — no report,
		// nothing on either stream. Reaching this at all means globalSetup did not
		// run, so saying so is the only useful behaviour.
		delete process.env.AUTHPLANE_CONFORMANCE_RUN_ID;

		expect(() => resolveRunId()).toThrow(/globalSetup/);
	});

	it("returns the assigned scope", () => {
		process.env.AUTHPLANE_CONFORMANCE_RUN_ID = "a-scope";

		expect(resolveRunId()).toBe("a-scope");
	});
});
