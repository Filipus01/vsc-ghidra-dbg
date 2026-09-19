import * as config from './config';

export interface GhidraProgram {
	name: string;
	path: string;
	imageBase: string;
	/** Ghidra's language id, e.g. x86:LE:32:default */
	languageId: string;
	processor: string;
	pointerSize: number;
	bigEndian: boolean;
	/** the stack pointer register of this processor, as Ghidra's compiler spec names it */
	stackPointer: string | null;
}

export interface DecompLine {
	n: number;
	indent: number;
	text: string;
	min: string | null;
	max: string | null;
}

export type TypeClass =
	| 'int'
	| 'uint'
	| 'float'
	| 'bool'
	| 'char'
	| 'ptr'
	| 'enum'
	| 'struct'
	| 'array'
	| 'other';

/** Where a variable lives - the extension itself computes the address and reads memory. */
export type VarKind = 'stack' | 'register' | 'memory' | 'unique' | 'hash' | 'none' | 'other';

export interface DecompVar {
	name: string;
	type: string;
	typeClass: TypeClass;
	size: number;
	param: boolean;
	global: boolean;
	kind: VarKind;
	/** kind === 'stack': offset from the stack top at function entry */
	offset?: number;
	/** kind === 'register' */
	reg?: string;
	/** kind === 'memory': static Ghidra address */
	addr?: string;
	/** A register holds the variable only over part of the function - the value is approximate. */
	dynamic: boolean;
	/** Address from which the storage is valid; null = from entry. */
	validFrom: string | null;
	pointee?: string;
	pointeeClass?: TypeClass;
	pointeeSize?: number;
}

export interface Decompilation {
	name: string;
	entry: string;
	min: string;
	max: string;
	lines: DecompLine[];
	vars: DecompVar[];
}

/** Stack depths relative to the function entry, for one specific PC. */
export interface FrameDepths {
	entry: string;
	stackPointer: string | null;
	spDepth: number | null;
	framePointer: string | null;
	fpDepth: number | null;
}

/** One register of the target processor, and where it sits inside its parent. */
export interface RegisterSlice {
	name: string;
	/** the full register this one is a part of; equal to name for a full register */
	base: string;
	/** offset of this register inside its base, in bits */
	offsetBits: number;
	bits: number;
}

/**
 * The processor's register model. Debuggers report full registers only, so this is what a
 * narrow register (AL inside EAX, W0 inside X0) is cut out of - without the extension
 * having to know any one processor.
 */
export interface RegisterModel {
	stackPointer: string | null;
	framePointer: string | null;
	programCounter: string | null;
	pointerSize: number;
	bigEndian: boolean;
	registers: RegisterSlice[];
}

async function get<T>(path: string): Promise<T> {
	const base = config.apiUrl();
	if (!base) {
		throw new Error('the address of the Ghidra API is empty - set ghidraDbg.apiUrl');
	}

	let response: Response;
	try {
		response = await fetch(base + path, {
			signal: AbortSignal.timeout(config.requestTimeoutMs()),
		});
	}
	catch (err) {
		throw new Error(
			`no response from ${base} (${err instanceof Error ? err.message : String(err)}) - ` +
				'is the VscGhidraDbg plugin enabled in Ghidra, and does ghidraDbg.apiUrl point at it?'
		);
	}

	// Read the text first: an error from the plugin is JSON, but its HTTP server answers an
	// unknown path with an HTML page, and parsing that as JSON hides what actually happened.
	const text = await response.text();
	let body: Record<string, unknown> | undefined;
	try {
		body = JSON.parse(text) as Record<string, unknown>;
	}
	catch {
		body = undefined;
	}

	const endpoint = path.split('?')[0];
	if (!response.ok) {
		if (body?.error) {
			throw new Error(String(body.error));
		}
		if (response.status === 404) {
			throw new Error(
				`the plugin at ${base} does not serve ${endpoint} - it is older than this ` +
					'extension; rebuild and reinstall it with ghidra-plugin/build.sh, then restart Ghidra'
			);
		}
		throw new Error(`HTTP ${response.status} from ${endpoint}`);
	}
	if (body === undefined || body === null) {
		throw new Error(
			`${endpoint} did not answer with JSON - is something other than the VscGhidraDbg ` +
				`plugin listening on ${base}?`
		);
	}
	return body as T;
}

function params(entries: Record<string, string | number | undefined>): string {
	const query = new URLSearchParams();
	for (const [key, value] of Object.entries(entries)) {
		if (value !== undefined && value !== '') {
			query.set(key, String(value));
		}
	}
	return query.toString();
}

export function listPrograms(): Promise<GhidraProgram[]> {
	return get<GhidraProgram[]>('/programs');
}

export function decompile(program: string, address: string): Promise<Decompilation> {
	return get<Decompilation>(`/decompile?${params({ program, addr: address })}`);
}

export interface SymbolInfo {
	address: string;
	function: string | null;
	entry: string | null;
	symbol: string | null;
}

export function symbolAt(program: string, address: string): Promise<SymbolInfo> {
	return get<SymbolInfo>(`/symbol?${params({ program, addr: address })}`);
}

/** The frame pointer register is the user's setting when they have one, Ghidra's guess otherwise. */
export function frameDepths(program: string, address: string): Promise<FrameDepths> {
	return get<FrameDepths>(
		`/frame?${params({ program, addr: address, fp: config.framePointerRegister() })}`
	);
}

export function registerModel(program: string): Promise<RegisterModel> {
	return get<RegisterModel>(`/registers?${params({ program, fp: config.framePointerRegister() })}`);
}

export function readBytes(program: string, address: string, length: number): Promise<{ hex: string }> {
	return get<{ hex: string }>(`/bytes?${params({ program, addr: address, len: length })}`);
}
