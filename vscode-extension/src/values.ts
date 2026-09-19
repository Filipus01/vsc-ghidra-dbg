import * as vscode from 'vscode';

import * as config from './config';
import { DecompiledDoc, formatAddr, toAddr } from './decompiled';
import * as ghidra from './ghidra';

/** The frame without sources we are computing values for. */
export interface FrameContext {
	session: vscode.DebugSession;
	frameId: number;
	threadId: number | undefined;
	/** program name in Ghidra */
	program: string;
	/** bytes in an address of this target - stack slots and pointers are this wide */
	pointerSize: number;
	bigEndian: boolean;
	/** runtime address - static address */
	delta: bigint;
	doc: DecompiledDoc;
	/** static PC in this frame */
	address: bigint;
}

export interface ResolvedVar {
	variable: ghidra.DecompVar;
	value: string;
	/** readable storage location, in the target's own terms: EBP-0xc, EAX, 0x10ab12c0 */
	location: string;
	/** runtime address, when the variable lives in memory */
	address?: bigint;
	/** the value may not match what the pseudocode shows at this point */
	approximate: boolean;
	/** the bytes at the address, low to high, when the value text is not them */
	raw?: string;
	/** the stack top as of entry every stack offset hangs off */
	frameBase?: bigint;
	/** how the frame base was arrived at - that is how far it can be trusted */
	frameBaseSource?: string;
	note?: string;
}

const MAX_HEX_BYTES = 16;
/** Shown instead of the leftovers sitting in a stack slot the program has not written yet. */
const NOT_LIVE = '<not on the stack yet>';

export async function readMemory(
	session: vscode.DebugSession,
	address: bigint,
	count: number
): Promise<Buffer | undefined> {
	if (count <= 0) {
		return undefined;
	}
	try {
		const response = await session.customRequest('readMemory', {
			memoryReference: formatAddr(address),
			count,
		});
		return response?.data ? Buffer.from(response.data, 'base64') : undefined;
	}
	catch {
		return undefined; // unmapped memory is normal here, not an error
	}
}

// --- frame registers ---

const MAX_SCOPE_DEPTH = 3;

export type RegisterMap = Map<string, bigint>;

const registerCache = new Map<string, RegisterMap>();
/** The register model belongs to the program, not to the process - it outlives a session. */
const modelCache = new Map<string, Promise<ghidra.RegisterModel>>();

export function clearFrameCaches(): void {
	registerCache.clear();
}

/** Only after the program itself changed in Ghidra - a different processor, a reimport. */
export function clearProgramCaches(): void {
	modelCache.clear();
}

/**
 * A variable can live in a narrow register (AL inside EAX, W0 inside X0) while the debugger
 * reports the full ones only. Which register sits where inside which parent is something
 * Ghidra knows for every processor it supports, so we ask it instead of writing a table.
 */
export function registerModelOf(program: string): Promise<ghidra.RegisterModel> {
	let model = modelCache.get(program);
	if (!model) {
		model = ghidra.registerModel(program).catch((err) => {
			modelCache.delete(program); // a failed fetch must not be remembered as the answer
			throw err;
		});
		modelCache.set(program, model);
	}
	return model;
}

/** evaluate reports values in decimal ("1245632"), sometimes with a 0x prefix. */
function parseNumber(raw: string | undefined): bigint | undefined {
	if (!raw) {
		return undefined;
	}
	const hex = raw.match(/0x[0-9a-fA-F]+/);
	if (hex) {
		return BigInt(hex[0]);
	}
	const dec = raw.match(/-?\d+/);
	return dec ? BigInt(dec[0]) : undefined;
}

/**
 * The register scope reports bare hex without 0x ("001301C0"), so reading those as decimal
 * produced numbers that look plausible and are completely wrong (0x1301C0 -> 1301).
 * Anything that is not a single hex number - vectors, floating point flags - is skipped.
 */
function parseRegister(raw: string | undefined): bigint | undefined {
	const text = raw?.trim();
	if (!text) {
		return undefined;
	}
	const match = text.match(/^(?:0x)?([0-9a-fA-F]+)$/);
	return match ? BigInt(`0x${match[1]}`) : undefined;
}

async function collectVariables(
	session: vscode.DebugSession,
	variablesReference: number,
	into: RegisterMap,
	depth: number
): Promise<void> {
	if (variablesReference === 0 || depth > MAX_SCOPE_DEPTH) {
		return;
	}
	const response = await session.customRequest('variables', { variablesReference });
	for (const variable of (response?.variables ?? []) as any[]) {
		const value = parseRegister(variable?.value);
		if (value !== undefined) {
			into.set(String(variable.name).toUpperCase(), value);
		}
		if (variable?.variablesReference) {
			// registers can sit in subgroups (CPU, Flags, SSE)
			await collectVariables(session, variable.variablesReference, into, depth + 1);
		}
	}
}

/**
 * DAP has no "give me the registers" request - cppvsdbg among others offers nothing of the
 * kind - so we try in turn: a scope whose name mentions registers and, failing that,
 * evaluating the register pseudo-variables the adapter's expression syntax provides.
 */
export async function readRegisters(
	session: vscode.DebugSession,
	frameId: number,
	probe: string[] = []
): Promise<RegisterMap> {
	const key = `${session.id}:${frameId}`;
	const cached = registerCache.get(key);
	if (cached) {
		// An earlier caller may have asked for fewer registers than we need now - the scope
		// read is the same either way, only the probing below differs.
		await probeMissing(session, frameId, cached, probe);
		return cached;
	}

	const registers: RegisterMap = new Map();
	try {
		const scopes = await session.customRequest('scopes', { frameId });
		for (const scope of (scopes?.scopes ?? []) as any[]) {
			if (/register/i.test(String(scope?.name ?? ''))) {
				await collectVariables(session, scope.variablesReference, registers, 0);
			}
		}
	}
	catch {
		// no scopes is not the end of the world - evaluate is still there
	}

	await probeMissing(session, frameId, registers, probe);

	registerCache.set(key, registers);
	return registers;
}

/** The registers the scope did not report, asked for one by one through evaluate. */
async function probeMissing(
	session: vscode.DebugSession,
	frameId: number,
	registers: RegisterMap,
	probe: string[]
): Promise<void> {
	for (const raw of probe) {
		const name = raw.toUpperCase();
		if (!name || registers.has(name)) {
			continue;
		}
		const value = await evaluateRegister(session, frameId, name);
		if (value !== undefined) {
			registers.set(name, value);
		}
	}
}

async function evaluateRegister(
	session: vscode.DebugSession,
	frameId: number,
	name: string
): Promise<bigint | undefined> {
	for (const expression of [`@${name.toLowerCase()}`, `$${name.toLowerCase()}`, name.toLowerCase()]) {
		try {
			const response = await session.customRequest('evaluate', {
				expression,
				frameId,
				context: 'watch',
			});
			const value = parseNumber(response?.result);
			if (value !== undefined) {
				return value;
			}
		}
		catch {
			// wrong syntax for this evaluator - try the next one
		}
	}
	return undefined;
}

function registerValue(
	registers: RegisterMap,
	name: string,
	model?: ghidra.RegisterModel
): bigint | undefined {
	const upper = name.toUpperCase();
	const direct = registers.get(upper);
	if (direct !== undefined) {
		return direct;
	}
	const slice = model?.registers.find((entry) => entry.name.toUpperCase() === upper);
	if (!slice || slice.base.toUpperCase() === upper) {
		return undefined;
	}
	const parent = registers.get(slice.base.toUpperCase());
	if (parent === undefined) {
		return undefined;
	}
	return (parent >> BigInt(slice.offsetBits)) & ((1n << BigInt(slice.bits)) - 1n);
}

/** One machine word off a buffer, as wide and as ordered as the target has it. */
export function readWord(bytes: Buffer, offset: number, size: number, bigEndian: boolean): bigint {
	let value = 0n;
	for (let i = 0; i < size; i++) {
		const byte = BigInt(bytes[offset + (bigEndian ? i : size - 1 - i)]);
		value = (value << 8n) | byte;
	}
	return value;
}

// --- computing the values ---

const depthCache = new Map<string, ghidra.FrameDepths>();

async function depthsFor(program: string, address: bigint): Promise<ghidra.FrameDepths> {
	const key = `${program}:${address}`;
	const cached = depthCache.get(key);
	if (cached) {
		return cached;
	}
	const fresh = await ghidra.frameDepths(program, formatAddr(address));
	depthCache.set(key, fresh);
	return fresh;
}

export function clearDepthCache(): void {
	depthCache.clear();
}

const STACK_SCAN_WINDOWS = [0x1000, 0x400, 0x100];
/** In case the debugger reports the call address instead of the return one - a call instruction is short. */
const RETURN_SLACK = 16n;

/**
 * The stack top as of function entry - Ghidra counts variable offsets from there.
 *
 * The order is by how much each source can be trusted. A frame pointer is a register value,
 * so it is exact. Ghidra's stack depth comes next: it is the function's own arithmetic from
 * its entry to here, and a register we read holds the other end of it. Looking for the return
 * address on the live stack is the fallback, for functions Ghidra cannot work out - it takes
 * the lowest slot holding an address the debugger reports further down the stack, and when a
 * frame between us and those is missing from the stack trace (a hook trampoline leaves one
 * out), the lowest such slot is the wrong frame's base.
 *
 * Whatever the source, a base below the stack pointer is not a base at all: the stack top as
 * of entry is at or above where the stack pointer stands now.
 */
async function resolveFrameBase(
	ctx: FrameContext,
	depths: ghidra.FrameDepths,
	model: ghidra.RegisterModel,
	registers: RegisterMap,
	log: (message: string) => void
): Promise<{ address: bigint; source: string } | undefined> {
	if (depths.framePointer && depths.fpDepth !== null) {
		const pointer = registerValue(registers, depths.framePointer, model);
		if (pointer !== undefined) {
			return { address: pointer - BigInt(depths.fpDepth), source: depths.framePointer };
		}
	}

	const stackPointer = depths.stackPointer ?? model.stackPointer;
	if (!stackPointer) {
		log('  the processor has no stack pointer in Ghidra - the frame base is out of reach');
		return undefined;
	}
	const sp = registerValue(registers, stackPointer, model);
	const growsDown = model.stackGrowsDown !== false;
	const reachable = (base: bigint): boolean =>
		sp === undefined || !growsDown || base >= sp;

	const fromDepth =
		depths.spDepth !== null && sp !== undefined ? sp - BigInt(depths.spDepth) : undefined;
	if (fromDepth !== undefined && reachable(fromDepth)) {
		return { address: fromDepth, source: 'stack depth from Ghidra' };
	}
	if (fromDepth !== undefined) {
		log(
			`  Ghidra's stack depth puts the frame base at ${formatAddr(fromDepth)}, below ` +
				`${stackPointer} - ignoring it`
		);
	}

	const scanned = await stackEntryFromReturn(ctx, model, registers, stackPointer, log);
	return scanned === undefined
		? undefined
		: { address: scanned, source: 'return address on the stack' };
}

const MAX_RETURN_CANDIDATES = 4;

/**
 * Return addresses to look for on the stack. The immediate caller is sometimes a synthetic
 * frame with no instruction address ("Frames below may be incorrect") - then we take the
 * following ones, since we are looking for the lowest matching slot anyway.
 */
export async function returnCandidates(ctx: FrameContext): Promise<bigint[]> {
	const frames = await stackFramesOf(ctx);
	const index = frames.findIndex((frame) => frame.id === ctx.frameId);
	if (index < 0) {
		return [];
	}
	return frames
		.slice(index + 1)
		.map((frame) => frame.instructionPointerReference)
		.filter((pointer): pointer is string => Boolean(pointer))
		.slice(0, MAX_RETURN_CANDIDATES)
		.map(toAddr);
}

interface DapFrameBrief {
	id: number;
	name?: string;
	instructionPointerReference?: string;
}

/** The thread's frames, innermost first. Not cached: frame ids are reused between stops. */
async function stackFramesOf(ctx: FrameContext): Promise<DapFrameBrief[]> {
	if (ctx.threadId === undefined) {
		return [];
	}
	try {
		const trace = await ctx.session.customRequest('stackTrace', {
			threadId: ctx.threadId,
			startFrame: 0,
			levels: 200,
		});
		return (trace?.stackFrames ?? []) as DapFrameBrief[];
	}
	catch {
		return [];
	}
}

/**
 * The live stack pointer, but only when it belongs to the frame we are computing. Only the
 * innermost frame has one: further up the stack the debugger reports either the top frame's
 * registers unchanged or unwound ones, and neither says where that frame's outgoing-argument
 * area currently ends. When we cannot tell, there is no yardstick and the liveness check stays
 * off - showing a stale value, as we always did, beats hiding a live one.
 */
async function liveStackPointer(
	ctx: FrameContext,
	depths: ghidra.FrameDepths,
	model: ghidra.RegisterModel,
	registers: RegisterMap,
	log: (message: string) => void
): Promise<bigint | undefined> {
	const frames = await stackFramesOf(ctx);
	const top = frames[0];
	const pointer = top?.instructionPointerReference;
	// The id is only the first try: some adapters hand out frame ids afresh on every stackTrace,
	// and then ours never matches. What really says "this is the frame we are computing" is that
	// the program counter on top of the stack is the one we decompiled.
	const ours =
		top !== undefined &&
		(top.id === ctx.frameId ||
			(pointer !== undefined && toAddr(pointer) === ctx.address + ctx.delta));
	if (!ours) {
		log(
			top === undefined
				? '  the stack is unknown - no liveness check on the slots'
				: `  not the innermost frame (top is ${top.name ?? '?'} at ${pointer ?? 'no address'})` +
					' - no liveness check'
		);
		return undefined;
	}
	const name = depths.stackPointer ?? model.stackPointer;
	const sp = name ? registerValue(registers, name, model) : undefined;
	log(`  liveness yardstick: ${name ?? 'stack pointer'}=${describe(sp)}`);
	return sp;
}

/**
 * A slot the program has not written yet. Past the live stack pointer is scratch space: the
 * next call or an interrupt may overwrite it at any moment, and what sits there now is whatever
 * an earlier, deeper call left behind - 0xcc fill, in a debug build. Which side "past" is on
 * comes from Ghidra's compiler spec; a plugin too old to send it leaves us assuming a downward
 * stack, which is x86, ARM, MIPS and most others.
 */
function notWrittenYet(address: bigint, size: number, sp: bigint, growsDown: boolean): boolean {
	return growsDown ? address < sp : address + BigInt(size) > sp;
}

/**
 * Ghidra's stack analysis gives up on a fair share of functions - sometimes it knows neither
 * the stack pointer nor the frame pointer depth. The live process knows for sure: the return
 * address sits at the stack top as of entry, so we look for it walking up from the stack
 * pointer. On a processor that returns through a link register there is nothing to find here,
 * and the caller frame reported by the debugger is the better source.
 */
async function stackEntryFromReturn(
	ctx: FrameContext,
	model: ghidra.RegisterModel,
	registers: RegisterMap,
	stackPointer: string,
	log: (message: string) => void
): Promise<bigint | undefined> {
	const sp = registerValue(registers, stackPointer, model);
	const expected = await returnCandidates(ctx);
	if (sp === undefined || expected.length === 0) {
		log(
			`  stack scan skipped: ${stackPointer}=${describe(sp)}, ` +
				`return addresses from frames below: ${expected.length}`
		);
		return undefined;
	}

	let buffer: Buffer | undefined;
	for (const window of STACK_SCAN_WINDOWS) {
		buffer = await readMemory(ctx.session, sp, window);
		if (buffer) {
			break;
		}
	}
	if (!buffer) {
		log(`  stack scan: could not read memory at ${formatAddr(sp)}`);
		return undefined;
	}

	const stride = Math.max(ctx.pointerSize, 1);
	let tolerant: bigint | undefined;
	for (let offset = 0; offset + stride <= buffer.length; offset += stride) {
		const slot = readWord(buffer, offset, stride, ctx.bigEndian);
		if (expected.some((candidate) => slot === candidate)) {
			return sp + BigInt(offset);
		}
		if (
			tolerant === undefined &&
			expected.some((candidate) => slot > candidate && slot - candidate <= RETURN_SLACK)
		) {
			tolerant = sp + BigInt(offset);
		}
	}
	log(
		`  stack scan: none of the return addresses [${expected.map(formatAddr).join(', ')}] ` +
			`is in the ${buffer.length} bytes above ${formatAddr(sp)}`
	);
	return tolerant;
}

function locationLabel(
	variable: ghidra.DecompVar,
	depths: ghidra.FrameDepths,
	model: ghidra.RegisterModel,
	address: bigint | undefined,
	sp: bigint | undefined
): string {
	switch (variable.kind) {
		case 'stack': {
			if (depths.framePointer && depths.fpDepth !== null) {
				const shift = (variable.offset ?? 0) - depths.fpDepth;
				return `${depths.framePointer}${shift < 0 ? '-' : '+'}0x${Math.abs(shift).toString(16)}`;
			}
			// Without a frame pointer the offset counts from the frame base, not from the stack
			// pointer: printing it as "ESP-0x14" named a slot a whole frame away from the one we
			// read. Against the live stack pointer where we have one - that is what you would
			// type in a watch window - and against the frame base otherwise.
			const stackPointer = depths.stackPointer ?? model.stackPointer;
			if (stackPointer && sp !== undefined && address !== undefined) {
				const shift = address - sp;
				const magnitude = shift < 0n ? -shift : shift;
				return `${stackPointer}${shift < 0n ? '-' : '+'}0x${magnitude.toString(16)}`;
			}
			const offset = variable.offset ?? 0;
			return `frame${offset < 0 ? '-' : '+'}0x${Math.abs(offset).toString(16)}`;
		}
		case 'register':
			return variable.reg ?? 'register';
		case 'memory':
			return address === undefined ? variable.addr ?? 'memory' : formatAddr(address);
		case 'unique':
		case 'hash':
			return 'intermediate value';
		default:
			return variable.kind;
	}
}

/** The registers the frame base hangs on - the ones worth asking the debugger for by name. */
function probeNames(depths: ghidra.FrameDepths, model: ghidra.RegisterModel): string[] {
	return [depths.stackPointer, depths.framePointer, model.stackPointer, model.framePointer].filter(
		(name): name is string => Boolean(name)
	);
}

interface FrameFacts {
	depths: ghidra.FrameDepths;
	model: ghidra.RegisterModel;
	registers: RegisterMap;
}

async function frameFacts(ctx: FrameContext): Promise<FrameFacts> {
	const [depths, model] = await Promise.all([
		depthsFor(ctx.program, ctx.address),
		registerModelOf(ctx.program),
	]);
	const registers = await readRegisters(ctx.session, ctx.frameId, probeNames(depths, model));
	return { depths, model, registers };
}

/** The stack top as of entry - the anchor both the variables and the return address hang off. */
async function frameBase(
	ctx: FrameContext,
	log: (message: string) => void = () => undefined
): Promise<bigint | undefined> {
	const { depths, model, registers } = await frameFacts(ctx);
	return (await resolveFrameBase(ctx, depths, model, registers, log))?.address;
}

/**
 * The frame's return address. Where the call pushes it - the stack top as of entry, which is
 * exactly the frame base. Needed when the debugger cannot unwind sourceless code and hands us
 * a synthetic caller frame with no instruction address. A processor that returns through a
 * link register keeps it elsewhere, and then there is nothing to read here.
 */
export async function returnAddressOf(ctx: FrameContext): Promise<bigint | undefined> {
	const base = await frameBase(ctx);
	if (base === undefined) {
		return undefined;
	}
	const size = Math.max(ctx.pointerSize, 1);
	const bytes = await readMemory(ctx.session, base, size);
	return bytes && bytes.length >= size ? readWord(bytes, 0, size, ctx.bigEndian) : undefined;
}

/** Our own "Locals" for a frame the debugger has no sources for. */
export async function computeValues(
	ctx: FrameContext,
	log: (message: string) => void = () => undefined
): Promise<ResolvedVar[]> {
	const { depths, model, registers } = await frameFacts(ctx);
	const maxValueBytes = config.values.maxValueBytes();

	const anchor = await resolveFrameBase(ctx, depths, model, registers, log);
	const base = anchor?.address;
	const stackPointer = depths.stackPointer ?? model.stackPointer;
	log(
		`${ctx.doc.functionName}: frame base ${base === undefined ? 'unresolved' : formatAddr(base)}` +
			` (${anchor?.source ?? 'no source'}), ${stackPointer ?? 'stack pointer'}=` +
			`${describe(stackPointer ? registerValue(registers, stackPointer, model) : undefined)}` +
			`, spDepth=${depths.spDepth ?? 'none'}, fpDepth=${depths.fpDepth ?? 'none'}`
	);

	const addresses = new Map<ghidra.DecompVar, bigint>();
	for (const variable of ctx.doc.vars) {
		if (variable.kind === 'stack' && base !== undefined) {
			addresses.set(variable, base + BigInt(variable.offset ?? 0));
		}
		else if (variable.kind === 'memory' && variable.addr) {
			addresses.set(variable, toAddr(variable.addr) + ctx.delta);
		}
	}

	const block = await readStackBlock(ctx, addresses);
	const resolved: ResolvedVar[] = [];
	const growsDown = model.stackGrowsDown !== false;
	const sp = await liveStackPointer(ctx, depths, model, registers, log);
	const notLive: string[] = [];

	for (const variable of ctx.doc.vars) {
		const address = addresses.get(variable);
		const size = Math.min(Math.max(variable.size, 1), maxValueBytes);
		let bytes: Buffer | undefined;
		let registerWord: bigint | undefined;

		if (variable.kind === 'register') {
			registerWord = registerValue(registers, variable.reg ?? '', model);
			if (registerWord !== undefined) {
				bytes = wordBytes(registerWord, Math.min(size, 8), ctx.bigEndian);
			}
		}
		else if (address !== undefined) {
			bytes = block?.slice(address, size) ?? (await readMemory(ctx.session, address, size));
		}

		const stale =
			variable.kind === 'stack' &&
			address !== undefined &&
			sp !== undefined &&
			notWrittenYet(address, size, sp, growsDown);
		if (stale) {
			notLive.push(variable.name);
		}

		const note = noteFor(ctx, variable, base, bytes, stale);
		resolved.push({
			variable,
			value: stale
				? NOT_LIVE
				: bytes
					? await formatValue(ctx, variable, bytes)
					: '<unavailable>',
			location: locationLabel(variable, depths, model, address, sp),
			address,
			approximate: stale || variable.dynamic || isEarly(ctx, variable),
			raw: stale && bytes ? hexDump(bytes) : undefined,
			frameBase: variable.kind === 'stack' ? base : undefined,
			frameBaseSource: variable.kind === 'stack' ? anchor?.source : undefined,
			note,
		});
	}

	if (notLive.length > 0) {
		log(`  past the live stack pointer, not written yet: ${notLive.join(', ')}`);
	}

	resolved.sort(byGroupThenName);
	return resolved;
}

function describe(value: bigint | undefined): string {
	return value === undefined ? 'none' : formatAddr(value);
}

function byGroupThenName(a: ResolvedVar, b: ResolvedVar): number {
	const rank = (entry: ResolvedVar) => (entry.variable.param ? 0 : entry.variable.global ? 2 : 1);
	return rank(a) - rank(b) || a.variable.name.localeCompare(b.variable.name);
}

/** The variable may not exist yet - its storage starts being valid past where we stand. */
function isEarly(ctx: FrameContext, variable: ghidra.DecompVar): boolean {
	return variable.validFrom !== null && ctx.address < toAddr(variable.validFrom);
}

function noteFor(
	ctx: FrameContext,
	variable: ghidra.DecompVar,
	base: bigint | undefined,
	bytes: Buffer | undefined,
	stale: boolean
): string | undefined {
	if (variable.kind === 'unique' || variable.kind === 'hash') {
		return 'an intermediate value of the decompiler - it is nowhere in memory';
	}
	if (variable.kind === 'stack' && base === undefined) {
		return 'frame base unresolved: Ghidra does not know the stack depth and the return address is not on the stack';
	}
	if (variable.kind === 'register' && bytes === undefined) {
		return `the debugger did not report register ${variable.reg ?? '?'}`;
	}
	if (stale) {
		return (
			'the slot is past the live stack pointer - the program has not written it yet; ' +
			'the bytes there are left over from an earlier, deeper call'
		);
	}
	if (isEarly(ctx, variable)) {
		return 'before the point where the decompiler considers it initialized';
	}
	if (variable.dynamic) {
		return 'held in a register over part of the function only - the value is approximate';
	}
	return undefined;
}

/** One read for the whole frame instead of a separate one per variable. */
async function readStackBlock(
	ctx: FrameContext,
	addresses: Map<ghidra.DecompVar, bigint>
): Promise<{ slice(address: bigint, size: number): Buffer | undefined } | undefined> {
	let lo: bigint | undefined;
	let hi: bigint | undefined;
	for (const [variable, address] of addresses) {
		if (variable.kind !== 'stack') {
			continue;
		}
		const end = address + BigInt(Math.min(Math.max(variable.size, 1), config.values.maxValueBytes()));
		lo = lo === undefined || address < lo ? address : lo;
		hi = hi === undefined || end > hi ? end : hi;
	}
	if (lo === undefined || hi === undefined || hi - lo > BigInt(config.values.maxBlockReadBytes())) {
		return undefined;
	}

	const start = lo;
	const buffer = await readMemory(ctx.session, start, Number(hi - start));
	if (!buffer) {
		return undefined;
	}
	return {
		slice(address: bigint, size: number): Buffer | undefined {
			const offset = Number(address - start);
			if (offset < 0 || offset + size > buffer.length) {
				return undefined;
			}
			return buffer.subarray(offset, offset + size);
		},
	};
}

// --- formatting ---

function readInteger(bytes: Buffer, signed: boolean, bigEndian: boolean): bigint {
	const value = readWord(bytes, 0, bytes.length, bigEndian);
	return signed ? BigInt.asIntN(bytes.length * 8, value) : value;
}

/** A register value as the bytes it would have in the target's memory. */
function wordBytes(value: bigint, size: number, bigEndian: boolean): Buffer {
	const buffer = Buffer.alloc(size);
	let rest = BigInt.asUintN(size * 8, value);
	for (let i = 0; i < size; i++) {
		buffer[bigEndian ? size - 1 - i : i] = Number(rest & 0xffn);
		rest >>= 8n;
	}
	return buffer;
}

function withHex(value: bigint): string {
	if (value > -10n && value < 10n) {
		return value.toString();
	}
	const hex = value < 0n ? `-0x${(-value).toString(16)}` : `0x${value.toString(16)}`;
	return `${value} (${hex})`;
}

function hexDump(bytes: Buffer): string {
	const head = [...bytes.subarray(0, MAX_HEX_BYTES)]
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join(' ');
	return bytes.length > MAX_HEX_BYTES ? `${head} ...` : head;
}

function escapeChar(code: number): string {
	if (code === 0) {
		return '\\0';
	}
	if (code >= 0x20 && code < 0x7f) {
		return String.fromCharCode(code);
	}
	return `\\x${code.toString(16).padStart(2, '0')}`;
}

async function formatValue(
	ctx: FrameContext,
	variable: ghidra.DecompVar,
	bytes: Buffer
): Promise<string> {
	const bigEndian = ctx.bigEndian;
	switch (variable.typeClass) {
		case 'bool': {
			const value = readInteger(bytes, false, bigEndian);
			return value === 0n ? 'false' : value === 1n ? 'true' : withHex(value);
		}
		case 'char': {
			const code = Number(readInteger(bytes, false, bigEndian));
			return `'${escapeChar(code)}' (${code})`;
		}
		case 'float': {
			if (bytes.length >= 8) {
				return String(bigEndian ? bytes.readDoubleBE(0) : bytes.readDoubleLE(0));
			}
			if (bytes.length >= 4) {
				return String(bigEndian ? bytes.readFloatBE(0) : bytes.readFloatLE(0));
			}
			return hexDump(bytes);
		}
		case 'int':
			return withHex(readInteger(bytes, true, bigEndian));
		case 'uint':
		case 'enum':
			return withHex(readInteger(bytes, false, bigEndian));
		case 'ptr': {
			const target = readInteger(bytes, false, bigEndian);
			if (target === 0n) {
				return 'NULL';
			}
			const text = await readString(ctx, variable, target);
			return text === undefined ? formatAddr(target) : `${formatAddr(target)} ${text}`;
		}
		case 'struct':
		case 'array':
			return hexDump(bytes);
		default:
			// A class we have no branch for - including "other" from a plugin older than this
			// extension. At machine-word size it is a number far more often than it is a blob.
			return bytes.length >= 1 && bytes.length <= 8
				? withHex(readInteger(bytes, false, bigEndian))
				: hexDump(bytes);
	}
}

/** For character pointers pull in a piece of the string - the bare address says nothing. */
async function readString(
	ctx: FrameContext,
	variable: ghidra.DecompVar,
	target: bigint
): Promise<string | undefined> {
	if (variable.pointeeClass !== 'char') {
		return undefined;
	}
	const wide = (variable.pointeeSize ?? 1) >= 2;
	const buffer = await readMemory(ctx.session, target, config.values.maxStringBytes());
	if (!buffer) {
		return undefined;
	}

	let text = '';
	for (let i = 0; i + (wide ? 1 : 0) < buffer.length; i += wide ? 2 : 1) {
		const code = wide
			? ctx.bigEndian
				? buffer.readUInt16BE(i)
				: buffer.readUInt16LE(i)
			: buffer[i];
		if (code === 0) {
			return `"${text}"`;
		}
		text += escapeChar(code);
	}
	return `"${text}..."`;
}
