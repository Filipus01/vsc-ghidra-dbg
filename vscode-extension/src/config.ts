import * as vscode from 'vscode';

/**
 * Every tunable of the extension in one place. Nothing here carries a value of its own: the
 * defaults are the ones declared in package.json, so the settings UI and the code cannot
 * drift apart, and a setting left empty means "use the declared default" rather than "break".
 */
const SECTION = 'ghidraDbg';

function declared<T>(key: string): T | undefined {
	return vscode.workspace.getConfiguration(SECTION).inspect<T>(key)?.defaultValue;
}

function text(key: string): string {
	const value = vscode.workspace.getConfiguration(SECTION).get<string>(key)?.trim();
	return value || declared<string>(key)?.trim() || '';
}

function count(key: string): number {
	const value = vscode.workspace.getConfiguration(SECTION).get<number>(key);
	if (typeof value === 'number' && Number.isFinite(value)) {
		return value;
	}
	return declared<number>(key) ?? 0;
}

function flag(key: string): boolean {
	const value = vscode.workspace.getConfiguration(SECTION).get<boolean>(key);
	return typeof value === 'boolean' ? value : declared<boolean>(key) === true;
}

let report: (message: string) => void = () => undefined;

/** Where to complain about a setting that cannot be used - the extension's output channel. */
export function useLogger(sink: (message: string) => void): void {
	report = sink;
}

/**
 * A setting the user writes as a regular expression. A typo there must not take the whole
 * command down with it, so a pattern that does not compile falls back to the declared one.
 */
function pattern(key: string): RegExp {
	const source = text(key);
	try {
		return new RegExp(source, 'i');
	}
	catch (err) {
		report(`${SECTION}.${key} is not a valid regular expression (${err}) - using the default`);
		return new RegExp(declared<string>(key) ?? '$^', 'i');
	}
}

/** Base URL of the Ghidra plugin's HTTP API, without a trailing slash. */
export function apiUrl(): string {
	return text('apiUrl').replace(/\/+$/, '');
}

export function requestTimeoutMs(): number {
	return count('requestTimeoutMs');
}

/** Empty means: let Ghidra pick the frame pointer register for the program's processor. */
export function framePointerRegister(): string {
	return vscode.workspace.getConfiguration(SECTION).get<string>('framePointerRegister')?.trim() ?? '';
}

export function splitDisassembly(): boolean {
	return flag('splitDisassembly');
}

export function attachConfiguration(): string {
	return vscode.workspace.getConfiguration(SECTION).get<string>('attachConfiguration')?.trim() ?? '';
}

/** How the loader may place a module, for the search that finds where it really landed. */
export const modules = {
	baseAlignment: (): bigint => BigInt(Math.trunc(Math.max(count('modules.baseAlignment'), 1))),
	baseScanLimit: (): number => count('modules.baseScanLimit'),
};

export const stepping = {
	maxInstructionSteps: (): number => count('stepping.maxInstructionSteps'),
	maxWalkSteps: (): number => count('stepping.maxWalkSteps'),
	stopTimeoutMs: (): number => count('stepping.stopTimeoutMs'),
	runTimeoutMs: (): number => count('stepping.runTimeoutMs'),
	settleMs: (): number => count('stepping.settleMs'),
};

export const values = {
	maxValueBytes: (): number => count('values.maxValueBytes'),
	maxStringBytes: (): number => count('values.maxStringBytes'),
	maxBlockReadBytes: (): number => count('values.maxBlockReadBytes'),
};

/**
 * What a call, a return and a helper call look like in this debugger's disassembly. The
 * processor and the toolchain decide that, so it is settings rather than code.
 */
export const disassembly = {
	maxLineInstructions: (): number => count('disassembly.maxLineInstructions'),
	callPattern: (): RegExp => pattern('disassembly.callPattern'),
	returnPattern: (): RegExp => pattern('disassembly.returnPattern'),
	skipCallPattern: (): RegExp => pattern('disassembly.skipCallPattern'),
	/** Two groups: the name of what is called, and the target address in hex. */
	namedCallPattern: (): RegExp => pattern('disassembly.namedCallPattern'),
};
