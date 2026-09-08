import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

const temporaryDirectories: string[] = [];

async function createTemporaryDirectory(): Promise<string> {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "omp-startup-capture-policy-"));
	temporaryDirectories.push(directory);
	return directory;
}

afterEach(async () => {
	await Promise.all(
		temporaryDirectories.splice(0).map(directory => fs.rm(directory, { recursive: true, force: true })),
	);
});

describe("capture policy startup", () => {
	test("a missing policy fails in an isolated CLI process before it emits a session receipt", async () => {
		const directory = await createTemporaryDirectory();
		const policyPath = path.join(directory, "missing.json");
		const cliPath = path.resolve(import.meta.dir, "../src/cli.ts");
		const child = Bun.spawn(
			[process.execPath, cliPath, "launch", "--mode", "json", "--capture-policy", policyPath, "synthetic prompt"],
			{
				stdout: "pipe",
				stderr: "pipe",
			},
		);
		const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
		expect(exitCode).not.toBe(0);
		expect(stdout).not.toContain('"type":"capture_policy"');
	});
});
