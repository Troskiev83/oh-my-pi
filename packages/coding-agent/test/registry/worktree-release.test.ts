import { describe, expect, it } from "bun:test";
import { AgentLifecycleManager } from "@oh-my-pi/pi-coding-agent/registry/agent-lifecycle";
import { AgentRegistry } from "@oh-my-pi/pi-coding-agent/registry/agent-registry";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent/session/agent-session";

function session(dispose = async (): Promise<void> => {}): AgentSession {
	return { dispose } as unknown as AgentSession;
}

function scope() {
	const registry = new AgentRegistry();
	const lifecycle = AgentLifecycleManager.forRegistry(registry);
	const owner = registry.register({ id: "Main", displayName: "main", kind: "main", session: session() });
	return { registry, lifecycle, owner };
}

describe("worktree release barrier", () => {
	it("waits for in-flight parking and final capture while another main remains untouched", async () => {
		const { registry, lifecycle, owner } = scope();
		const parking = Promise.withResolvers<void>();
		const capture = Promise.withResolvers<void>();
		let saved = false;
		const child = registry.register({
			id: "Child",
			parentId: owner.id,
			displayName: "child",
			kind: "sub",
			status: "idle",
			session: session(() => parking.promise),
		});
		lifecycle.adopt(
			child.id,
			{
				idleTtlMs: 0,
				onRelease: async () => {
					await capture.promise;
					saved = true;
				},
			},
			child,
		);
		const other = registry.register({ id: "OtherMain", displayName: "other", kind: "main", session: session() });
		let strangerDisposed = false;
		const stranger = registry.register({
			id: "OtherChild",
			parentId: other.id,
			displayName: "stranger",
			kind: "sub",
			status: "idle",
			session: session(async () => {
				strangerDisposed = true;
			}),
		});
		lifecycle.adopt(stranger.id, { idleTtlMs: 0 }, stranger);
		const park = lifecycle.park(child.id);
		await Promise.resolve();
		let receipt: string[] | undefined;
		const release = lifecycle.releaseDescendants(owner, Date.now() + 10_000).then(ids => {
			receipt = ids;
			return ids;
		});
		parking.resolve();
		await park;
		expect(receipt).toBeUndefined();
		expect(saved).toBe(false);
		capture.resolve();
		expect(await release).toEqual(["Child"]);
		expect(saved).toBe(true);
		expect(registry.get(stranger.id)).toBe(stranger);
		expect(strangerDisposed).toBe(false);
		await lifecycle.disposeDescendants(other);
	});

	it("cannot turn a swallowed normal cleanup failure into a successful receipt", async () => {
		const { registry, lifecycle, owner } = scope();
		let captures = 0;
		const child = registry.register({
			id: "Child",
			parentId: owner.id,
			displayName: "child",
			kind: "sub",
			status: "idle",
			session: session(),
		});
		lifecycle.adopt(
			child.id,
			{
				idleTtlMs: 0,
				onRelease: async () => {
					captures++;
					throw new Error("capture lost access to origin");
				},
			},
			child,
		);
		expect(await lifecycle.release(child.id, child)).toBe(true);
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 1000)).rejects.toThrow("capture lost access");
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 1000)).rejects.toThrow("capture lost access");
		expect(captures).toBe(1);
	});

	it("read-only check does not close admission but pre-ref pending work blocks release", async () => {
		const { registry, lifecycle, owner } = scope();
		lifecycle.checkRelease(owner);
		const settle = registry.beginTask(owner.id);
		expect(() => lifecycle.checkRelease(owner)).toThrow("pending child task");
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 1000)).rejects.toThrow("pending child task");
		expect(() =>
			registry.register({ id: "Late", parentId: owner.id, displayName: "late", kind: "sub", session: session() }),
		).toThrow("released its worktree");
		settle();
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 1000)).rejects.toThrow("pending child task");
	});

	it("rejects running children without disposing active user work", async () => {
		const { registry, lifecycle, owner } = scope();
		let disposed = false;
		registry.register({
			id: "Running",
			parentId: owner.id,
			displayName: "running",
			kind: "sub",
			session: session(async () => {
				disposed = true;
			}),
		});
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 1000)).rejects.toThrow("is running");
		expect(disposed).toBe(false);
	});

	it("keeps timeout failure truthful after late cleanup eventually settles", async () => {
		const { registry, lifecycle, owner } = scope();
		const gate = Promise.withResolvers<void>();
		const child = registry.register({
			id: "Child",
			parentId: owner.id,
			displayName: "child",
			kind: "sub",
			status: "idle",
			session: session(),
		});
		lifecycle.adopt(child.id, { idleTtlMs: 0, onRelease: () => gate.promise }, child);
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 10)).rejects.toThrow(/timed out|timeout/i);
		gate.resolve();
		await lifecycle.release(child.id, child, { strict: true });
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 1000)).rejects.toThrow(/timed out|timeout/i);
		expect(() => lifecycle.checkRelease(owner)).toThrow(/timed out|timeout/i);
	});

	it("does not capture a parked child until its post-grace disposal work really settles", async () => {
		const { registry, lifecycle, owner } = scope();
		const gate = Promise.withResolvers<void>();
		let finalDelta = "initial";
		let captured: string | undefined;
		const childSession = {
			dispose: async () => {},
			settleDispose: async () => {
				await gate.promise;
				finalDelta = "late unique delta";
			},
		} as unknown as AgentSession;
		const child = registry.register({
			id: "Child",
			parentId: owner.id,
			displayName: "child",
			kind: "sub",
			status: "idle",
			session: childSession,
		});
		lifecycle.adopt(
			child.id,
			{
				idleTtlMs: 0,
				onRelease: async () => {
					captured = finalDelta;
				},
			},
			child,
		);
		await lifecycle.park(child.id);
		const release = lifecycle.releaseDescendants(owner, Date.now() + 1000);
		await Promise.resolve();
		expect(captured).toBeUndefined();
		gate.resolve();
		await release;
		expect(captured).toBe("late unique delta");
	});

	it("rejects a pre-existing revival and disposes its late session instead of reopening admission", async () => {
		const { registry, lifecycle, owner } = scope();
		const gate = Promise.withResolvers<AgentSession>();
		let disposed = false;
		const child = registry.register({
			id: "Child",
			parentId: owner.id,
			displayName: "child",
			kind: "sub",
			status: "parked",
			session: null,
		});
		lifecycle.adopt(child.id, { idleTtlMs: 0, revive: () => gate.promise }, child);
		const revival = lifecycle.ensureLive(child.id);
		await expect(lifecycle.releaseDescendants(owner, Date.now() + 1000)).rejects.toThrow("pending child task");
		gate.resolve(
			session(async () => {
				disposed = true;
			}),
		);
		await expect(revival).rejects.toThrow("released its worktree");
		expect(disposed).toBe(true);
		expect(registry.get(child.id)?.session).toBeNull();
		await lifecycle.disposeDescendants(owner);
	});
});
