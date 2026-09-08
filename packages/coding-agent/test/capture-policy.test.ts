import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	CaptureLimitError,
	createCaptureWriter,
	redactCaptureValue,
	registerCaptureSecret,
	setCapturePolicy,
	validateCapturePolicy,
} from "@oh-my-pi/pi-coding-agent/session/capture-policy";
import { OutputSink } from "@oh-my-pi/pi-coding-agent/session/streaming-output";
import { writeArtifact } from "@oh-my-pi/pi-coding-agent/session/artifacts";
import { execCommand } from "@oh-my-pi/pi-coding-agent/exec/exec";

const createdDirectories: string[] = [];
const policy = { version: 1 as const, toolMaxBytes: 512, runMaxBytes: 1024, reserveBytes: 64 };

async function createTemporaryDirectory(): Promise<string> {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "omp-capture-policy-"));
	createdDirectories.push(directory);
	return directory;
}

afterEach(async () => {
	setCapturePolicy(undefined);
	await Promise.all(createdDirectories.splice(0).map(directory => fs.rm(directory, { recursive: true, force: true })));
});

describe("capture policy", () => {
	test("rejects missing, extra, unsafe, and internally inconsistent policy fields", () => {
		expect(() => validateCapturePolicy({ ...policy, extra: true })).toThrow();
		expect(() => validateCapturePolicy({ ...policy, reserveBytes: policy.toolMaxBytes })).toThrow();
		expect(() => validateCapturePolicy({ ...policy, runMaxBytes: policy.toolMaxBytes - 1 })).toThrow();
		expect(() => validateCapturePolicy({ ...policy, toolMaxBytes: 1.5 })).toThrow();
	});

	test("bounds a finite self-reading artifact writer before it can amplify", async () => {
		const directory = await createTemporaryDirectory();
		const artifact = path.join(directory, "capture.log");
		setCapturePolicy(policy);
		await writeArtifact(artifact, "seed\n");
		let error: unknown;
		for (let index = 0; index < 8; index++) {
			const current = await Bun.file(artifact).text();
			try {
				await writeArtifact(artifact, `${current}${current}${current}${current}`);
			} catch (caught) {
				error = caught;
				break;
			}
		}
		expect(error).toBeInstanceOf(CaptureLimitError);
		expect(Bun.file(artifact).size).toBeLessThanOrEqual(policy.toolMaxBytes);
	});

	test("redacts UTF-8 and a secret split across stream chunks before artifact persistence", async () => {
		const directory = await createTemporaryDirectory();
		const artifact = path.join(directory, "output.log");
		const secret = "synthetic-refresh-token-0123456789";
		setCapturePolicy(policy);
		registerCaptureSecret(secret);
		const sink = new OutputSink({ artifactPath: artifact, spillThreshold: 16 });
		sink.push("prefix 😀 synthetic-refresh-");
		sink.push("token-0123456789 suffix");
		const summary = await sink.dump();
		await sink.dispose();
		expect(summary.output).not.toContain(secret);
		expect(await Bun.file(artifact).exists()).toBe(true);
		const persisted = await Bun.file(artifact).text();
		expect(persisted).not.toContain(secret);
		expect(persisted).toContain("[REDACTED]");
	});

	test("accounts actual UTF-8 bytes and keeps the diagnostic reserve inside the tool limit", () => {
		setCapturePolicy(policy);
		expect(redactCaptureValue("😀".repeat(112))).toHaveLength(224);
		setCapturePolicy(policy);
		expect(() => redactCaptureValue("x".repeat(policy.toolMaxBytes - policy.reserveBytes + 1))).toThrow(
			CaptureLimitError,
		);
	});

	test("applies one combined stdout and stderr budget to argv execution and kills on breach", async () => {
		setCapturePolicy(policy);
		await expect(
			execCommand(
				process.execPath,
				["-e", 'process.stdout.write("x".repeat(400)); process.stderr.write("y".repeat(400))'],
				process.cwd(),
			),
		).rejects.toMatchObject({ code: "CAPTURE_LIMIT_EXCEEDED" });
	});

	test("passes explicit stdin and environment only through argv execution", async () => {
		setCapturePolicy(policy);
		const result = await execCommand(
			process.execPath,
			["-e", 'process.stdin.on("data", value => process.stdout.write(process.env.OMP_CAPTURE_ENV + value))'],
			process.cwd(),
			{ input: "input", env: { OMP_CAPTURE_ENV: "env-" } },
		);
		expect(result).toMatchObject({ stdout: "env-input", stderr: "", code: 0, killed: false });
	});

	test("redacts multiline, split, long, and late-registered credential forms without unbounded writer state", () => {
		setCapturePolicy(policy);
		const writer = createCaptureWriter();
		expect(writer).toBeDefined();
		const lateSecret = `synthetic-${"x".repeat(8192)}`;
		registerCaptureSecret(lateSecret);
		const longSecretStream = `${writer!.push(lateSecret.slice(0, 5000))}${writer!.push(lateSecret.slice(5000))}${writer!.finish()}`;
		const pem = "-----BEGIN PRIVATE KEY-----\nsynthetic-pem-body\n-----END PRIVATE KEY-----";
		const bearer = `${writer!.push("Bearer synthe")}${writer!.push("tic-value")}${writer!.finish()}`;
		const tokenWriter = createCaptureWriter()!;
		const token = `${tokenWriter.push("ghp_synthe")}${tokenWriter.push("ticvalue")}${tokenWriter.finish()}`;
		const value = writer!.redactComplete(`${pem}\n${lateSecret}`);

		expect(longSecretStream).toBe("[REDACTED]");
		expect(bearer).toBe("Bearer [REDACTED]");
		expect(token).toBe("[REDACTED]");
		expect(value).not.toContain("synthetic-pem-body");
		expect(value).not.toContain(lateSecret);
		expect(value).toContain("[REDACTED]");
	});

	test("suppresses unregistered long credential forms before the bounded lookbehind can release them", () => {
		setCapturePolicy({ version: 1, toolMaxBytes: 32_768, runMaxBytes: 131_072, reserveBytes: 64 });
		const body = `SYNTHETIC_UNREGISTERED_${"x".repeat(12_000)}`;
		const inputs = [
			`Bearer ${body}`,
			`ghp_${body}`,
			JSON.stringify({ attribution: "retain", authorization: body }),
			`-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`,
		];
		const redact = (input: string, chunkSize: number): string => {
			const writer = createCaptureWriter()!;
			const parts: string[] = [];
			for (let index = 0; index < input.length; index += chunkSize)
				parts.push(writer.push(input.slice(index, index + chunkSize)));
			parts.push(writer.finish());
			return parts.join("");
		};

		for (const input of inputs) {
			expect(redact(input, 37)).not.toContain("x".repeat(64));
			expect(redact(input, input.length)).not.toContain("x".repeat(64));
		}
		const structured = JSON.parse(redact(inputs[2], 37));
		expect(structured.attribution).toBe("retain");
		expect(structured.authorization).toContain("[REDACTED]");
	});

	test("redacts complete quoted fields and credential headers across chunk boundaries while preserving JSON peers", () => {
		setCapturePolicy({ version: 1, toolMaxBytes: 32_768, runMaxBytes: 131_072, reserveBytes: 64 });
		const jsonInputs = [
			JSON.stringify({ password: "SYNTH_A SYNTH_B,SYNTH_C", keep: 4277 }),
			JSON.stringify({ authorization: "Basic c3ludGhldGljOnNlY3JldA==", keep: 4277 }),
			JSON.stringify({ cookie: "session=SYNTH_A; refresh=SYNTH_B", keep: 4277 }),
			JSON.stringify({ refresh_token: 'SYNTH_A"SYNTH_B\\SYNTH_C', keep: 4277 }),
		];
		const headers = [
			"Authorization: Basic c3ludGhldGljOnNlY3JldA==\nkeep: 4277",
			"Proxy-Authorization: Basic c3ludGhldGljOnNlY3JldA==\nkeep: 4277",
			"Cookie: session=SYNTH_A; refresh=SYNTH_B\nkeep: 4277",
			"Set-Cookie: session=SYNTH_A; refresh=SYNTH_B\nkeep: 4277",
		];
		const redact = (input: string, width: number): string => {
			const writer = createCaptureWriter()!;
			const parts: string[] = [];
			for (let index = 0; index < input.length; index += width)
				parts.push(writer.push(input.slice(index, index + width)));
			parts.push(writer.finish());
			return parts.join("");
		};

		for (const input of jsonInputs) {
			for (const width of [1, 37, 4096]) {
				const redacted = redact(input, width);
				expect(redacted).not.toContain("SYNTH_A");
				expect(redacted).not.toContain("c3ludGhldGljOnNlY3JldA==");
				expect(JSON.parse(redacted).keep).toBe(4277);
			}
		}
		for (const input of headers) {
			for (const width of [1, 37, 4096]) {
				const redacted = redact(input, width);
				expect(redacted).not.toContain("SYNTH_A");
				expect(redacted).not.toContain("c3ludGhldGljOnNlY3JldA==");
				expect(redacted).toContain("keep: 4277");
			}
		}
	});

	test("keeps JSON stdout separate from stderr with sibling redactors sharing one tool budget", async () => {
		setCapturePolicy(policy);
		const result = await execCommand(
			process.execPath,
			["-e", 'process.stdout.write(JSON.stringify({ ok: true })); process.stderr.write("synthetic warning")'],
			process.cwd(),
		);

		expect(JSON.parse(result.stdout)).toEqual({ ok: true });
		expect(result.stderr).toBe("synthetic warning");
	});

	test("redacts complete sensitive JSON values without corrupting nulls, non-sensitive containers, or embedded JSON strings", () => {
		setCapturePolicy(policy);
		const embedded = JSON.stringify({ password: "SYNTHETIC_EMBEDDED", attribution: "embedded-keep" });
		const output = redactCaptureValue(
			JSON.stringify({
				token: null,
				secret: 482915,
				token_object: { access_token: "SYNTHETIC_NESTED", keep: 4277 },
				content: [{ type: "text", text: embedded }],
				attribution: { peer: "fixture-peer", runId: 4277 },
			}),
		);
		const parsed = JSON.parse(output);

		expect(output).not.toContain("SYNTHETIC_NESTED");
		expect(output).not.toContain("SYNTHETIC_EMBEDDED");
		expect(output).not.toContain("482915");
		expect(parsed.token).toBeNull();
		expect(parsed.secret).toBe("[REDACTED]");
		expect(parsed.token_object).toBe("[REDACTED]");
		expect(JSON.parse(parsed.content[0].text)).toEqual({ password: "[REDACTED]", attribution: "embedded-keep" });
		expect(parsed.attribution).toEqual({ peer: "fixture-peer", runId: 4277 });
	});

	test("redacts structured metadata values before their JSONL writer can serialize them", () => {
		const secret = "synthetic-access-token-abcdef";
		setCapturePolicy(policy);
		registerCaptureSecret(secret);
		const value = redactCaptureValue(
			JSON.stringify({
				authorization: `Bearer ${secret}`,
				rawContent: secret,
				attribution: { peer: "fixture-peer", invoker: "posthog_triage", runId: 4277 },
			}),
		);
		expect(value).not.toContain(secret);
		expect(value).toContain("[REDACTED]");
		expect(JSON.parse(value).attribution).toEqual({ peer: "fixture-peer", invoker: "posthog_triage", runId: 4277 });
	});
});
