import { ptree } from "@oh-my-pi/pi-utils";
import {
	createCaptureWriter,
	isCaptureLimitError,
	type CaptureLimitError,
	type CaptureWriter,
} from "../session/capture-policy";

export interface ExecOptions {
	/** AbortSignal to cancel the command. */
	signal?: AbortSignal;
	/** Timeout in milliseconds. */
	timeout?: number;
	/** Working directory. */
	cwd?: string;
	/** UTF-8 input supplied on the process stdin. */
	input?: string;
	/** Environment additions/removals. An undefined value removes the inherited key. */
	env?: Record<string, string | undefined>;
}

export interface ExecResult {
	stdout: string;
	stderr: string;
	code: number;
	killed: boolean;
}

function resolveEnvironment(
	overrides: Record<string, string | undefined> | undefined,
): Record<string, string> | undefined {
	if (!overrides) return undefined;
	const env: Record<string, string> = Object.fromEntries(
		Object.entries(Bun.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
	);
	for (const [key, value] of Object.entries(overrides)) {
		if (value === undefined) delete env[key];
		else env[key] = value;
	}
	return env;
}

async function readCapturedStream(
	stream: ReadableStream<Uint8Array>,
	writer: CaptureWriter | undefined,
	parts: string[],
	onLimit: (error: CaptureLimitError) => void,
): Promise<void> {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	try {
		for (;;) {
			const next = await reader.read();
			if (next.done) break;
			const text = decoder.decode(next.value, { stream: true });
			if (!text) continue;
			try {
				parts.push(writer?.push(text) ?? text);
			} catch (error) {
				if (!isCaptureLimitError(error)) throw error;
				onLimit(error);
				await reader.cancel().catch(() => {});
				return;
			}
		}
		const tail = decoder.decode();
		if (tail) parts.push(writer?.push(tail) ?? tail);
	} finally {
		reader.releaseLock();
	}
}

/** Execute an argv command with supervised, bounded stdout and stderr capture. */
export async function execCommand(
	command: string,
	args: string[],
	cwd: string,
	options?: ExecOptions,
): Promise<ExecResult> {
	const stdoutWriter = createCaptureWriter();
	const stderrWriter = stdoutWriter?.fork();
	const input = options?.input === undefined ? "ignore" : Buffer.from(options.input);
	const child = ptree.spawn([command, ...args], {
		cwd: options?.cwd ?? cwd,
		signal: options?.signal,
		timeout: options?.timeout,
		stdin: input,
		env: resolveEnvironment(options?.env),
		detached: true,
		stderr: "stream",
	});
	const stdout: string[] = [];
	const stderr: string[] = [];
	let limitError: CaptureLimitError | undefined;
	const onLimit = (error: CaptureLimitError): void => {
		if (limitError) return;
		limitError = error;
		child.kill(undefined, -1);
	};
	const stderrStream = child.stderr;
	if (!stderrStream) throw new Error("Process stderr stream unavailable");
	await Promise.all([
		readCapturedStream(child.stdout, stdoutWriter, stdout, onLimit),
		readCapturedStream(stderrStream, stderrWriter, stderr, onLimit),
	]);
	try {
		const finalStdout = stdoutWriter?.finish();
		if (finalStdout) stdout.push(finalStdout);
		const finalStderr = stderrWriter?.finish();
		if (finalStderr) stderr.push(finalStderr);
	} catch (error) {
		if (!isCaptureLimitError(error)) throw error;
		onLimit(error);
	}
	await child.exited.catch(() => {});
	if (limitError) throw limitError;
	return {
		stdout: stdout.join(""),
		stderr: stderr.join(""),
		code: child.exitCode ?? 0,
		killed: Boolean(child.exitReason?.aborted),
	};
}
