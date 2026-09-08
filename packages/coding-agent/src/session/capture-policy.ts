import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const MAX_REDACTION_LOOKBEHIND_BYTES = 4096;
const REDACTED = "[REDACTED]";
const CREDENTIAL_ENV_NAME = /(?:api[_-]?key|token|secret|password|authorization|cookie|session|credential|refresh)/i;
const SENSITIVE_FIELD_PREFIX =
	/(["']?(?:authorization|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|cookie)["']?\s*[=:]\s*)/gi;
const HEADER_PREFIX = /(^|\n)((?:proxy-)?authorization|cookie|set-cookie)\s*:\s*/gi;
const PEM_BLOCK = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
const BEARER_SECRET = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const BEARER_SECRET_WITH_BOUNDARY = /\bBearer\s+[A-Za-z0-9._~+/=-]+(?=[\s,;"'}])/gi;
const KNOWN_TOKEN_WITH_BOUNDARY = /\b(?:sk|rk|ghp|github_pat|xox[baprs])[-_A-Za-z0-9]{8,}(?=[\s,;"'}])/g;
const KNOWN_TOKEN = /\b(?:sk|rk|ghp|github_pat|xox[baprs])[-_A-Za-z0-9]{8,}\b/g;

export interface CapturePolicy {
	version: 1;
	toolMaxBytes: number;
	runMaxBytes: number;
	reserveBytes: number;
	policySha256?: string;
}

export class CaptureLimitError extends Error {
	readonly code = "CAPTURE_LIMIT_EXCEEDED";
	constructor(readonly scope: "tool" | "run") {
		super("CAPTURE_LIMIT_EXCEEDED");
		this.name = "CaptureLimitError";
	}
}

export function isCaptureLimitError(error: unknown): error is CaptureLimitError {
	return error instanceof CaptureLimitError;
}

function assertSafePositiveInteger(value: unknown, name: string): asserts value is number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
		throw new TypeError(`Invalid capture policy ${name}`);
	}
}

export function validateCapturePolicy(value: unknown): CapturePolicy {
	if (value === null || typeof value !== "object" || Array.isArray(value))
		throw new TypeError("Invalid capture policy");
	const record = value as Record<string, unknown>;
	const keys = Object.keys(record).sort();
	const expected = ["reserveBytes", "runMaxBytes", "toolMaxBytes", "version"];
	if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
		throw new TypeError("Invalid capture policy keys");
	}
	if (record.version !== 1) throw new TypeError("Unsupported capture policy version");
	assertSafePositiveInteger(record.toolMaxBytes, "toolMaxBytes");
	assertSafePositiveInteger(record.runMaxBytes, "runMaxBytes");
	assertSafePositiveInteger(record.reserveBytes, "reserveBytes");
	if (record.runMaxBytes < record.toolMaxBytes || record.reserveBytes >= record.toolMaxBytes) {
		throw new TypeError("Invalid capture policy limits");
	}
	return {
		version: 1,
		toolMaxBytes: record.toolMaxBytes,
		runMaxBytes: record.runMaxBytes,
		reserveBytes: record.reserveBytes,
	};
}

export async function loadCapturePolicy(policyPath: string): Promise<CapturePolicy> {
	if (!path.isAbsolute(policyPath)) throw new TypeError("--capture-policy must be an absolute path");
	const bytes = await fs.readFile(policyPath);
	const policy = validateCapturePolicy(JSON.parse(bytes.toString("utf8")));
	return { ...policy, policySha256: crypto.createHash("sha256").update(bytes).digest("hex") };
}

export interface CapturePolicyReceipt {
	type: "capture_policy";
	version: 1;
	active: true;
	policySha256: string;
	toolMaxBytes: number;
	runMaxBytes: number;
	reserveBytes: number;
}

export function capturePolicyReceipt(policy: CapturePolicy): CapturePolicyReceipt {
	if (!policy.policySha256) throw new TypeError("Capture policy has no source hash");
	return {
		type: "capture_policy",
		version: 1,
		active: true,
		policySha256: policy.policySha256,
		toolMaxBytes: policy.toolMaxBytes,
		runMaxBytes: policy.runMaxBytes,
		reserveBytes: policy.reserveBytes,
	};
}
function findUnescapedQuote(text: string, start: number, quote: '"' | "'"): number {
	let escaped = false;
	for (let index = start; index < text.length; index++) {
		if (escaped) {
			escaped = false;
		} else if (text[index] === "\\") {
			escaped = true;
		} else if (text[index] === quote) {
			return index;
		}
	}
	return -1;
}

function redactStructuredValues(text: string, final: boolean): string {
	let output = "";
	let cursor = 0;
	const fields = new RegExp(SENSITIVE_FIELD_PREFIX);
	for (let match = fields.exec(text); match; match = fields.exec(text)) {
		const prefix = match[1]!;
		const valueStart = fields.lastIndex;
		output += text.slice(cursor, match.index) + prefix;
		const first = text[valueStart];
		if (first === '"' || first === "'") {
			const end = findUnescapedQuote(text, valueStart + 1, first);
			if (end < 0) {
				output += final ? `${first}${REDACTED}` : text.slice(valueStart);
				return output;
			}
			output += `${first}${REDACTED}${first}`;
			cursor = end + 1;
			fields.lastIndex = cursor;
			continue;
		}
		const terminator = text.slice(valueStart).search(/[,;}\r\n]/);
		if (terminator < 0) {
			output += final ? REDACTED : text.slice(valueStart);
			return output;
		}
		output += REDACTED;
		cursor = valueStart + terminator;
		fields.lastIndex = cursor;
	}
	return output + text.slice(cursor);
}

function redactHeaders(text: string, final: boolean): string {
	const headers = new RegExp(HEADER_PREFIX);
	let output = "";
	let cursor = 0;
	for (let match = headers.exec(text); match; match = headers.exec(text)) {
		const valueStart = headers.lastIndex;
		const ending = text.slice(valueStart).search(/[\r\n]/);
		if (ending < 0 && !final) continue;
		output += text.slice(cursor, match.index) + match[1]! + match[2]! + REDACTED;
		cursor = ending < 0 ? text.length : valueStart + ending;
		headers.lastIndex = cursor;
	}
	return output + text.slice(cursor);
}

function findUnclosedStructuredValue(
	text: string,
): { start: number; prefix: string; quote: '"' | "'" | undefined } | undefined {
	const fields = new RegExp(SENSITIVE_FIELD_PREFIX);
	for (let match = fields.exec(text); match; match = fields.exec(text)) {
		const valueStart = fields.lastIndex;
		const first = text[valueStart];
		if (first === '"' || first === "'") {
			const end = findUnescapedQuote(text, valueStart + 1, first);
			if (end < 0) {
				return { start: match.index, prefix: match[0] + first, quote: first };
			}
			fields.lastIndex = end + 1;
			continue;
		}
		const ending = text.slice(valueStart).search(/[,;}\r\n]/);
		if (ending < 0) return { start: match.index, prefix: match[0], quote: undefined };
		fields.lastIndex = valueStart + ending;
	}
	return undefined;
}

function findUnclosedHeader(text: string): { start: number; prefix: string } | undefined {
	const headers = new RegExp(HEADER_PREFIX);
	for (let match = headers.exec(text); match; match = headers.exec(text)) {
		const valueStart = headers.lastIndex;
		const ending = text.slice(valueStart).search(/[\r\n]/);
		if (ending < 0) return { start: match.index + match[1]!.length, prefix: match[2]! };
		headers.lastIndex = valueStart + ending;
	}
	return undefined;
}

type SuppressedCapture =
	| { kind: "known"; secret: string; matched: number }
	| { kind: "pem"; tail: string }
	| { kind: "token" }
	| { kind: "structured"; quote: '"' | "'" | undefined; escaped: boolean }
	| { kind: "header" };

class CaptureRedactor {
	#pending = "";
	#suppressed: SuppressedCapture | undefined;
	readonly #keepChars = MAX_REDACTION_LOOKBEHIND_BYTES;
	#secretsVersion = -1;
	#sortedSecrets: string[] = [];

	constructor(readonly secrets: ReadonlySet<string>) {}

	#knownSecrets(): readonly string[] {
		if (this.#secretsVersion !== registeredSecretsVersion) {
			this.#sortedSecrets = [...this.secrets]
				.filter(secret => secret.length > 0)
				.sort((a, b) => b.length - a.length);
			this.#secretsVersion = registeredSecretsVersion;
		}
		return this.#sortedSecrets;
	}

	#redact(text: string, final = false): string {
		let output = text;
		for (const secret of this.#knownSecrets()) output = output.split(secret).join(REDACTED);
		output = redactHeaders(output, final);
		output = redactStructuredValues(output, final);
		return output
			.replace(PEM_BLOCK, REDACTED)
			.replace(final ? BEARER_SECRET : BEARER_SECRET_WITH_BOUNDARY, `Bearer ${REDACTED}`)
			.replace(final ? KNOWN_TOKEN : KNOWN_TOKEN_WITH_BOUNDARY, REDACTED);
	}

	#withheldCapture(text: string): { start: number; replacement: string; suppressed: SuppressedCapture } | undefined {
		const outputBoundary = text.length - this.#keepChars;
		if (outputBoundary <= 0) return undefined;
		const candidates: Array<{ start: number; replacement: string; suppressed: SuppressedCapture }> = [];
		for (const secret of this.#knownSecrets()) {
			if (secret.length <= MAX_REDACTION_LOOKBEHIND_BYTES) continue;
			const prefix = secret.slice(0, Math.min(32, secret.length));
			let start = text.indexOf(prefix);
			while (start >= 0 && start < outputBoundary) {
				if (secret.startsWith(text.slice(start))) {
					candidates.push({
						start,
						replacement: REDACTED,
						suppressed: { kind: "known", secret, matched: text.length - start },
					});
					break;
				}
				start = text.indexOf(prefix, start + 1);
			}
		}
		const pem = /-----BEGIN [A-Z0-9 ]+-----/g.exec(text);
		if (
			pem?.index !== undefined &&
			pem.index < outputBoundary &&
			!/-----END [A-Z0-9 ]+-----/g.test(text.slice(pem.index))
		) {
			candidates.push({ start: pem.index, replacement: REDACTED, suppressed: { kind: "pem", tail: "" } });
		}
		const header = findUnclosedHeader(text);
		if (header && header.start < outputBoundary) {
			candidates.push({
				start: header.start,
				replacement: `${header.prefix}${REDACTED}`,
				suppressed: { kind: "header" },
			});
		}
		const structured = findUnclosedStructuredValue(text);
		if (structured && structured.start < outputBoundary) {
			candidates.push({
				start: structured.start,
				replacement: `${structured.prefix}${REDACTED}`,
				suppressed: { kind: "structured", quote: structured.quote, escaped: false },
			});
		}
		const bearer = /\bBearer\s+[A-Za-z0-9._~+/=-]*$/i.exec(text);
		if (bearer?.index !== undefined && bearer.index < outputBoundary) {
			candidates.push({ start: bearer.index, replacement: `Bearer ${REDACTED}`, suppressed: { kind: "token" } });
		}
		const token = /\b(?:sk|rk|ghp|github_pat|xox[baprs])[-_A-Za-z0-9]*$/i.exec(text);
		if (token?.index !== undefined && token.index < outputBoundary) {
			candidates.push({ start: token.index, replacement: REDACTED, suppressed: { kind: "token" } });
		}
		return candidates.sort((left, right) => left.start - right.start)[0];
	}

	#consumeSuppressedCapture(text: string): string | undefined {
		const suppressed = this.#suppressed;
		if (!suppressed) return text;
		if (suppressed.kind === "known") {
			const expected = suppressed.secret.slice(suppressed.matched);
			const count = Math.min(expected.length, text.length);
			if (text.slice(0, count) === expected.slice(0, count)) {
				suppressed.matched += count;
				if (suppressed.matched < suppressed.secret.length) return undefined;
				this.#suppressed = undefined;
				return text.slice(count);
			}
			this.#suppressed = undefined;
			return "";
		}
		if (suppressed.kind === "pem") {
			const combined = suppressed.tail + text;
			const end = /-----END [A-Z0-9 ]+-----/.exec(combined);
			if (!end) {
				suppressed.tail = combined.slice(-64);
				return undefined;
			}
			this.#suppressed = undefined;
			return combined.slice(end.index + end[0].length);
		}
		if (suppressed.kind === "header") {
			const end = text.search(/[\r\n]/);
			if (end < 0) return undefined;
			this.#suppressed = undefined;
			return text.slice(end);
		}
		if (suppressed.kind === "structured") {
			if (suppressed.quote) {
				for (let index = 0; index < text.length; index++) {
					if (suppressed.escaped) {
						suppressed.escaped = false;
					} else if (text[index] === "\\") {
						suppressed.escaped = true;
					} else if (text[index] === suppressed.quote) {
						this.#suppressed = undefined;
						return text.slice(index);
					}
				}
				return undefined;
			}
			const end = text.search(/[,;}\r\n]/);
			if (end < 0) return undefined;
			this.#suppressed = undefined;
			return text.slice(end);
		}
		const end = text.search(/[\s,;"'}]/);
		if (end < 0) return undefined;
		this.#suppressed = undefined;
		return text.slice(end);
	}

	push(text: string): string {
		const remaining = this.#consumeSuppressedCapture(text);
		if (remaining === undefined) return "";
		const combined = this.#pending + remaining;
		const withheld = this.#withheldCapture(combined);
		if (withheld) {
			this.#pending = "";
			this.#suppressed = withheld.suppressed;
			return this.#redact(combined.slice(0, withheld.start)) + withheld.replacement;
		}
		const redacted = this.#redact(combined);
		if (redacted.length <= this.#keepChars) {
			this.#pending = redacted;
			return "";
		}
		const split = redacted.length - this.#keepChars;
		const output = redacted.slice(0, split);
		this.#pending = redacted.slice(split);
		return output;
	}

	redactComplete(text: string): string {
		return this.#redact(text, true);
	}

	finish(): string {
		const output = this.#redact(this.#pending, true);
		this.#pending = "";
		this.#suppressed = undefined;
		return output;
	}
}
function parseJsonContainer(text: string): object | undefined {
	try {
		const value: unknown = JSON.parse(text);
		return value !== null && typeof value === "object" ? value : undefined;
	} catch {
		return undefined;
	}
}

function redactJsonValue(value: unknown, redactor: CaptureRedactor, sensitive = false): unknown {
	if (sensitive && value !== null) return REDACTED;
	if (typeof value === "string") {
		const embedded = parseJsonContainer(value);
		return embedded ? JSON.stringify(redactJsonValue(embedded, redactor)) : redactor.redactComplete(value);
	}
	if (Array.isArray(value)) return value.map(item => redactJsonValue(item, redactor));
	if (value !== null && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value).map(([key, child]) => [
				key,
				redactJsonValue(child, redactor, CREDENTIAL_ENV_NAME.test(key)),
			]),
		);
	}
	return value;
}

class CaptureToolBudget {
	bytes = 0;
}

export class CaptureWriter {
	#redactor: CaptureRedactor;
	readonly #toolBudget: CaptureToolBudget;

	constructor(
		readonly policy: CapturePolicy,
		readonly budget: CaptureBudget,
		toolBudget = new CaptureToolBudget(),
	) {
		this.#toolBudget = toolBudget;
		this.#redactor = new CaptureRedactor(registeredSecrets);
	}

	fork(): CaptureWriter {
		return new CaptureWriter(this.policy, this.budget, this.#toolBudget);
	}

	push(text: string): string {
		const redacted = this.#redactor.push(text);
		if (redacted) this.#claim(redacted);
		return redacted;
	}

	finish(): string {
		const redacted = this.#redactor.finish();
		if (redacted) this.#claim(redacted);
		return redacted;
	}
	redactReplacement(text: string): string {
		this.#redactor = new CaptureRedactor(registeredSecrets);
		return this.redactComplete(text);
	}

	redactComplete(text: string): string {
		const complete = new CaptureRedactor(registeredSecrets);
		const container = parseJsonContainer(text);
		const output = container ? JSON.stringify(redactJsonValue(container, complete))! : complete.redactComplete(text);
		this.#claim(output);
		return output;
	}

	#claim(text: string): void {
		const bytes = Buffer.byteLength(text, "utf8");
		if (this.#toolBudget.bytes + bytes > this.policy.toolMaxBytes - this.policy.reserveBytes) {
			this.budget.fail("tool");
		}
		this.budget.claim(bytes);
		this.#toolBudget.bytes += bytes;
	}
}

export class CaptureBudget {
	#bytes = 0;
	#failed = false;
	constructor(readonly policy: CapturePolicy) {}
	claim(bytes: number): void {
		if (this.#failed || this.#bytes + bytes > this.policy.runMaxBytes - this.policy.reserveBytes) {
			this.fail("run");
		}
		this.#bytes += bytes;
	}
	fail(scope: "tool" | "run"): never {
		if (!this.#failed) {
			this.#failed = true;
			captureLimitHandler?.(scope);
		}
		throw new CaptureLimitError(scope);
	}
	get failed(): boolean {
		return this.#failed;
	}
}

let activePolicy: CapturePolicy | undefined;
let activeBudget: CaptureBudget | undefined;
const registeredSecrets = new Set<string>();
let registeredSecretsVersion = 0;

function rememberCaptureSecret(secret: string): void {
	if (!registeredSecrets.has(secret)) {
		registeredSecrets.add(secret);
		registeredSecretsVersion++;
	}
}
let captureLimitHandler: ((scope: "tool" | "run") => void) | undefined;

export function setCapturePolicy(policy: CapturePolicy | undefined): void {
	if (!policy) {
		activePolicy = undefined;
		activeBudget = undefined;
		registeredSecrets.clear();
		registeredSecretsVersion++;
		captureLimitHandler = undefined;
		return;
	}
	const validated = validateCapturePolicy({
		version: policy.version,
		toolMaxBytes: policy.toolMaxBytes,
		runMaxBytes: policy.runMaxBytes,
		reserveBytes: policy.reserveBytes,
	});
	activePolicy = policy.policySha256 ? { ...validated, policySha256: policy.policySha256 } : validated;
	activeBudget = new CaptureBudget(activePolicy);
	for (const [name, value] of Object.entries(Bun.env)) {
		if (value && CREDENTIAL_ENV_NAME.test(name)) rememberCaptureSecret(value);
	}
}

export function getCapturePolicy(): CapturePolicy | undefined {
	return activePolicy;
}

export function registerCaptureSecret(secret: string | undefined): void {
	if (secret) rememberCaptureSecret(secret);
}

export function setCapturePolicyViolationHandler(handler: ((scope: "tool" | "run") => void) | undefined): void {
	captureLimitHandler = handler;
}

export function createCaptureWriter(): CaptureWriter | undefined {
	return activePolicy && activeBudget ? new CaptureWriter(activePolicy, activeBudget) : undefined;
}

/** Redact a complete value before it reaches metadata or JSONL persistence. */
export function redactCaptureValue(value: string): string {
	const writer = createCaptureWriter();
	if (!writer) return value;
	return writer.redactComplete(value);
}
