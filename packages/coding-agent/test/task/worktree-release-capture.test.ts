import { afterEach, expect, it, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { AgentLifecycleManager } from "@oh-my-pi/pi-coding-agent/registry/agent-lifecycle";
import { AgentRegistry } from "@oh-my-pi/pi-coding-agent/registry/agent-registry";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent/session/agent-session";
import * as executor from "@oh-my-pi/pi-coding-agent/task/executor";
import { runIsolatedSubprocess } from "@oh-my-pi/pi-coding-agent/task/isolation-runner";
import { cleanupIsolation } from "@oh-my-pi/pi-coding-agent/task/worktree";
import * as natives from "@oh-my-pi/pi-natives";
import * as utils from "@oh-my-pi/pi-utils";

const roots: string[] = [];
afterEach(async () => {
	vi.restoreAllMocks();
	await Promise.all(roots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
});

async function git(cwd: string, ...args: string[]): Promise<string> {
	const child = Bun.spawn(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
	const [out, error, code] = await Promise.all([
		new Response(child.stdout).text(),
		new Response(child.stderr).text(),
		child.exited,
	]);
	if (code !== 0) throw new Error(error || out);
	return out;
}

it("release saves unique late work before deleting isolation without overwriting run-end artifacts", async () => {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "omp-release-capture-"));
	roots.push(root);
	const repo = path.join(root, "repo");
	const artifacts = path.join(root, "artifacts");
	await fs.mkdir(repo);
	await git(repo, "init", "-q", "-b", "main");
	await git(repo, "config", "user.name", "Test User");
	await git(repo, "config", "user.email", "test@example.com");
	await Bun.write(path.join(repo, "origin.txt"), "origin remains\n");
	await git(repo, "add", ".");
	await git(repo, "commit", "-qm", "baseline");
	vi.spyOn(utils, "getWorktreeDir").mockImplementation(segment => path.join(root, "worktrees", segment));
	const registry = new AgentRegistry();
	const lifecycle = AgentLifecycleManager.forRegistry(registry);
	const stub = { dispose: async () => {} } as unknown as AgentSession;
	const owner = registry.register({ id: "Main", displayName: "main", kind: "main", session: stub });
	let isolated = "";
	// Only the model turn is substituted; isolation, patches, git commits and cleanup are real.
	vi.spyOn(executor, "runSubprocess").mockImplementation(async options => {
		isolated = options.worktree!;
		await Bun.write(path.join(isolated, "run.txt"), "first result\n");
		const ref = registry.register({
			id: options.id,
			parentId: owner.id,
			displayName: "child",
			kind: "sub",
			status: "idle",
			session: stub,
		});
		lifecycle.adopt(ref.id, { idleTtlMs: 0, onRelease: options.onRelease }, ref);
		return {
			index: 0,
			id: options.id,
			agent: "task",
			agentSource: "bundled",
			task: "work",
			assignment: "work",
			exitCode: 0,
			output: "done",
			stderr: "",
			truncated: false,
			durationMs: 1,
			tokens: 0,
			requests: 0,
		};
	});
	const result = await runIsolatedSubprocess({
		baseOptions: {
			cwd: repo,
			agent: { name: "task", description: "Task", systemPrompt: "test", source: "bundled" },
			task: "work",
			index: 0,
			id: "Child",
			parentAgentId: owner.id,
			agentRegistry: registry,
		},
		context: { repoRoot: repo },
		preferredBackend: natives.IsoBackendKind.Rcopy,
		agentId: "Child",
		mergeMode: "patch",
		artifactsDir: artifacts,
		buildFailureResult: error => {
			throw error;
		},
	});
	expect(result.error).toBeUndefined();
	const runPatch = await Bun.file(result.patchPath!).text();
	await Bun.write(path.join(isolated, "late.txt"), "late unique change\n");
	await lifecycle.park("Child");
	expect(await lifecycle.releaseDescendants(owner, Date.now() + 30_000)).toEqual(["Child"]);
	expect(await Bun.file(result.patchPath!).text()).toBe(runPatch);
	const latePatches = (await fs.readdir(artifacts)).filter(
		name => name.startsWith("Child-release-") && name.endsWith(".patch"),
	);
	expect(latePatches).toHaveLength(1);
	expect(await Bun.file(path.join(artifacts, latePatches[0])).text()).toContain("late unique change");
	const branch = (await git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads/omp/task")).trim();
	expect(await git(repo, "show", `${branch}:late.txt`)).toBe("late unique change\n");
	expect(await Bun.file(path.join(isolated, "late.txt")).exists()).toBe(false);
	expect(await Bun.file(path.join(repo, "origin.txt")).text()).toBe("origin remains\n");
});

it("strict backend-stop failure keeps the isolated working tree available for recovery", async () => {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "omp-release-stop-failure-"));
	roots.push(root);
	const mergedDir = path.join(root, "m");
	await fs.mkdir(mergedDir);
	const pending = path.join(mergedDir, "pending.txt");
	await Bun.write(pending, "unique pending work\n");
	vi.spyOn(natives, "isoStop").mockRejectedValue(new Error("backend could not unmount"));
	await expect(
		cleanupIsolation(
			{
				mergedDir,
				backend: natives.IsoBackendKind.Rcopy,
				fellBack: false,
				fallbackReason: null,
			},
			{ strict: true },
		),
	).rejects.toThrow("backend could not unmount");
	expect(await Bun.file(pending).text()).toBe("unique pending work\n");
});
