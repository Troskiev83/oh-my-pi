import { execFile } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { getBaseConfigRoot, isEnoent } from "@oh-my-pi/pi-utils";
import type { AgentLifecycleManager } from "./agent-lifecycle";
import type { AgentRef, AgentRegistry } from "./agent-registry";

const VERSION = 1;
const MAX_BYTES = 64 * 1024;
const MAX_TIMEOUT_MS = 2_147_483_647;

interface Metadata {
	v: number;
	pid: number;
	cwd: string;
	session_id: string;
	endpoint: string;
	token: string;
}

export interface WorktreeReleaseReceipt {
	pid: number;
	cwd: string;
	session_id: string;
	ready?: boolean;
	released?: boolean;
	released_agents?: string[];
	error?: string;
}

export interface WorktreeReleaseOptions {
	pid: number;
	cwd: string;
	check?: boolean;
	timeoutMs?: number;
}

function runtimeDir(): string {
	return path.join(getBaseConfigRoot(), "run", "worktree-release");
}

function record(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseMetadata(value: unknown): Metadata | undefined {
	if (!record(value) || value.v !== VERSION || !Number.isSafeInteger(value.pid) || Number(value.pid) <= 0) return;
	if (typeof value.cwd !== "string" || !path.isAbsolute(value.cwd)) return;
	if (typeof value.session_id !== "string" || !value.session_id) return;
	if (typeof value.endpoint !== "string" || !value.endpoint || typeof value.token !== "string" || !value.token) return;
	return {
		v: VERSION,
		pid: Number(value.pid),
		cwd: value.cwd,
		session_id: value.session_id,
		endpoint: value.endpoint,
		token: value.token,
	};
}

async function windowsPrivate(location: string, create: boolean, deadlineAt = Date.now() + 5000): Promise<void> {
	const timeout = Math.min(5000, deadlineAt - Date.now());
	if (timeout <= 0) throw new Error("Worktree release deadline exceeded while validating runtime permissions.");
	const script = [
		"$ErrorActionPreference = 'Stop'",
		"$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User",
		"$acl = Get-Acl -LiteralPath $env:OMP_RELEASE_PERMISSION_PATH",
		...(create
			? [
					"$acl.SetOwner($sid)",
					"$acl.SetAccessRuleProtection($true, $false)",
					"foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }",
					"$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))",
					"Set-Acl -LiteralPath $env:OMP_RELEASE_PERMISSION_PATH -AclObject $acl",
					"$acl = Get-Acl -LiteralPath $env:OMP_RELEASE_PERMISSION_PATH",
				]
			: []),
		"if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Runtime path is not owned by the current user' }",
		"foreach ($rule in $acl.Access) { if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Runtime path is not owner-only' } }",
	].join("; ");
	await new Promise<void>((resolve, reject) => {
		execFile(
			"powershell.exe",
			["-NoProfile", "-NonInteractive", "-Command", script],
			{
				env: { ...process.env, OMP_RELEASE_PERMISSION_PATH: location },
				timeout,
				maxBuffer: MAX_BYTES,
				windowsHide: true,
			},
			(error, _stdout, stderr) => {
				if (error)
					reject(
						new Error(
							`Cannot establish owner-only worktree release permissions: ${stderr.trim() || error.message}`,
						),
					);
				else resolve();
			},
		);
	});
}

async function assertPrivate(location: string, directory: boolean, deadlineAt?: number): Promise<void> {
	const stat = await fs.promises.lstat(location);
	if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) {
		throw new Error(`Unsafe worktree release runtime path: ${location}`);
	}
	if (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.())) {
		throw new Error(`Worktree release runtime path must be owner-only: ${location}`);
	}
	if (process.platform === "win32") await windowsPrivate(location, false, deadlineAt);
	if (!directory && stat.size > MAX_BYTES) throw new Error("Worktree release metadata exceeds its size limit.");
}

async function privateDir(location: string): Promise<void> {
	const created = await fs.promises.mkdir(location, { recursive: true, mode: 0o700 });
	if (process.platform === "win32" && created !== undefined) await windowsPrivate(location, true);
	await assertPrivate(location, true);
}

async function endpointFor(dir: string, id: string): Promise<string> {
	if (process.platform === "win32") return `\\\\.\\pipe\\omp-worktree-release-${id}`;
	let endpoint = path.join(dir, `${id}.sock`);
	const limit = process.platform === "darwin" ? 104 : 108;
	if (Buffer.byteLength(endpoint) >= limit) {
		const key = crypto
			.createHash("sha256")
			.update(`${process.getuid?.() ?? 0}\0${dir}`)
			.digest("hex")
			.slice(0, 16);
		const shortDir = path.join(os.tmpdir(), `omp-release-${key}`);
		await privateDir(shortDir);
		endpoint = path.join(shortDir, `${id}.sock`);
	}
	return endpoint;
}

/** Independent of Collab: each exact SDK main generation owns one authenticated endpoint. */
export async function publishWorktreeRelease(source: {
	cwd: string;
	sessionId: string;
	isCurrent(): boolean;
	owner: AgentRef;
	registry: AgentRegistry;
	lifecycle: AgentLifecycleManager;
}): Promise<{ close(): Promise<void> }> {
	if (!source.sessionId) throw new Error("Worktree release requires a durable session identity.");
	const cwd = await fs.promises.realpath(source.cwd);
	const dir = runtimeDir();
	await privateDir(dir);
	const id = crypto.randomBytes(8).toString("hex");
	const token = crypto.randomBytes(32).toString("hex");
	const endpoint = await endpointFor(dir, id);
	const metadata: Metadata = { v: VERSION, pid: process.pid, cwd, session_id: source.sessionId, endpoint, token };
	const metaPath = path.join(dir, `${id}.json`);
	const sockets = new Set<net.Socket>();
	let closed = false;
	const server = net.createServer(socket => {
		sockets.add(socket);
		socket.once("close", () => sockets.delete(socket));
		socket.on("error", () => socket.destroy());
		socket.setEncoding("utf8");
		socket.setTimeout(30_000, () => socket.destroy());
		let buffer = "";
		let handled = false;
		const respond = (payload: WorktreeReleaseReceipt): void => {
			const line = `${JSON.stringify(payload)}\n`;
			if (Buffer.byteLength(line) > MAX_BYTES) socket.destroy();
			else socket.end(line);
		};
		socket.on("data", chunk => {
			if (handled) return;
			buffer += chunk;
			if (Buffer.byteLength(buffer) > MAX_BYTES) return socket.destroy();
			const newline = buffer.indexOf("\n");
			if (newline < 0) return;
			handled = true;
			const identity = { pid: process.pid, cwd, session_id: source.sessionId };
			const fail = (error: unknown): void =>
				respond({
					...identity,
					ready: false,
					released: false,
					error: error instanceof Error ? error.message : String(error),
				});
			try {
				const request: unknown = JSON.parse(buffer.slice(0, newline));
				if (!record(request) || request.v !== VERSION || typeof request.token !== "string")
					throw new Error("Unsupported worktree release protocol.");
				const presented = Buffer.from(request.token);
				const expected = Buffer.from(token);
				if (presented.length !== expected.length || !crypto.timingSafeEqual(presented, expected))
					throw new Error("Worktree release authentication failed.");
				if (
					request.pid !== process.pid ||
					request.cwd !== cwd ||
					request.session_id !== source.sessionId ||
					closed ||
					!source.isCurrent() ||
					source.registry.get(source.owner.id) !== source.owner
				)
					throw new Error("Worktree release main session ownership mismatch.");
				if (
					!Number.isSafeInteger(request.deadline_at) ||
					Number(request.deadline_at) <= Date.now() ||
					Number(request.deadline_at) - Date.now() > MAX_TIMEOUT_MS
				)
					throw new Error("Worktree release deadline expired or invalid.");
				socket.setTimeout(Math.max(1, Number(request.deadline_at) - Date.now()), () => socket.destroy());
				if (request.op === "check") {
					source.lifecycle.checkRelease(source.owner);
					respond({ ...identity, ready: true });
				} else if (request.op === "release") {
					// This call seals admission synchronously, before any promise wait.
					void source.lifecycle
						.releaseDescendants(source.owner, Number(request.deadline_at))
						.then(released_agents => respond({ ...identity, released: true, released_agents }), fail);
				} else throw new Error("Unknown worktree release operation.");
			} catch (error) {
				fail(error);
			}
		});
	});
	const listening = Promise.withResolvers<void>();
	server.once("error", listening.reject);
	server.listen(endpoint, listening.resolve);
	const remove = (): void => {
		fs.rmSync(metaPath, { force: true });
		if (process.platform !== "win32") fs.rmSync(endpoint, { force: true });
	};
	try {
		await listening.promise;
		server.unref();
		if (process.platform !== "win32") await fs.promises.chmod(endpoint, 0o600);
		const tempPath = `${metaPath}.tmp`;
		const file = await fs.promises.open(tempPath, "wx", 0o600);
		try {
			try {
				await file.writeFile(JSON.stringify(metadata));
			} finally {
				await file.close();
			}
			await fs.promises.rename(tempPath, metaPath);
		} finally {
			await fs.promises.rm(tempPath, { force: true });
		}
	} catch (error) {
		server.close();
		remove();
		throw error;
	}
	process.once("exit", remove);
	return {
		async close(): Promise<void> {
			if (closed) return;
			closed = true;
			process.off("exit", remove);
			const done = Promise.withResolvers<void>();
			server.close(() => done.resolve());
			for (const socket of sockets) socket.destroy();
			remove();
			await done.promise;
		},
	};
}

/** Actual CLI transport; discovery is read-only and never purges stale metadata. */
export async function requestWorktreeRelease(options: WorktreeReleaseOptions): Promise<WorktreeReleaseReceipt> {
	const timeoutMs = options.timeoutMs ?? 30_000;
	if (!Number.isSafeInteger(options.pid) || options.pid <= 0) throw new Error("--pid must be a positive owner PID.");
	if (!path.isAbsolute(options.cwd)) throw new Error("--cwd must be an absolute worktree path.");
	if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS)
		throw new Error("--timeout-ms must be a positive bounded integer.");
	const deadlineAt = Date.now() + timeoutMs;
	const cwd = await fs.promises.realpath(options.cwd);
	const dir = runtimeDir();
	let names: string[];
	try {
		await assertPrivate(dir, true, deadlineAt);
		names = await fs.promises.readdir(dir);
	} catch (error) {
		if (isEnoent(error)) throw new Error("OMP owner does not support native worktree release (no session endpoint).");
		throw error;
	}
	const matches: Metadata[] = [];
	for (const name of names) {
		if (!/^[a-f0-9]{16}\.json$/.test(name)) continue;
		const file = path.join(dir, name);
		try {
			await assertPrivate(file, false, deadlineAt);
			const meta = parseMetadata(await Bun.file(file).json());
			if (meta?.pid === options.pid && meta.cwd === cwd) matches.push(meta);
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
	}
	if (matches.length !== 1)
		throw new Error(
			matches.length
				? "Ambiguous OMP main sessions for the requested PID and cwd."
				: "OMP owner/cwd has no supported native worktree release endpoint.",
		);
	const meta = matches[0];
	const result = Promise.withResolvers<WorktreeReleaseReceipt>();
	const socket = net.createConnection({ path: meta.endpoint });
	const finish = (error?: Error, receipt?: WorktreeReleaseReceipt): void => {
		clearTimeout(timer);
		socket.destroy();
		if (error) result.reject(error);
		else if (receipt) result.resolve(receipt);
	};
	const timer = setTimeout(
		() => finish(new Error("Worktree release deadline exceeded; origin must remain intact.")),
		Math.max(0, deadlineAt - Date.now()),
	);
	socket.setEncoding("utf8");
	socket.once("error", error => finish(error));
	socket.once("close", () => finish(new Error("OMP owner closed without a release receipt.")));
	socket.once("connect", () =>
		socket.write(
			`${JSON.stringify({ v: VERSION, token: meta.token, pid: options.pid, cwd, session_id: meta.session_id, op: options.check ? "check" : "release", deadline_at: deadlineAt })}\n`,
		),
	);
	let buffer = "";
	socket.on("data", chunk => {
		buffer += chunk;
		if (Buffer.byteLength(buffer) > MAX_BYTES)
			return finish(new Error("OMP release response exceeds its size limit."));
		const newline = buffer.indexOf("\n");
		if (newline < 0) return;
		try {
			const receipt: unknown = JSON.parse(buffer.slice(0, newline));
			if (
				!record(receipt) ||
				receipt.pid !== options.pid ||
				receipt.cwd !== cwd ||
				receipt.session_id !== meta.session_id
			)
				throw new Error("OMP release receipt ownership mismatch.");
			if (options.check ? receipt.ready !== true : receipt.released !== true)
				throw new Error(typeof receipt.error === "string" ? receipt.error : "OMP worktree release failed.");
			if (
				!options.check &&
				(!Array.isArray(receipt.released_agents) || !receipt.released_agents.every(id => typeof id === "string"))
			)
				throw new Error("Invalid OMP release agent receipt.");
			finish(undefined, {
				pid: options.pid,
				cwd,
				session_id: meta.session_id,
				...(options.check
					? { ready: true }
					: { released: true, released_agents: receipt.released_agents as string[] }),
			});
		} catch (error) {
			finish(error instanceof Error ? error : new Error(String(error)));
		}
	});
	return result.promise;
}
