import * as vscode from 'vscode';

import { CallSite, DapInstruction, callsOnLine, pickCallSite } from './callSites';
import * as config from './config';
import { DecompiledDoc, formatAddr, toAddr } from './decompiled';
import * as ghidra from './ghidra';
import { LocalsProvider } from './localsView';
import {
	clearDepthCache,
	clearFrameCaches,
	clearProgramCaches,
	readMemory,
	readRegisters,
	readWord,
	registerModelOf,
	returnAddressOf,
} from './values';

const SCHEME = 'ghidra-decomp';

/**
 * Whether we are standing in a frame the debugger has no sources for. The stepping keys hang
 * off this in package.json, so which F10/F11 you get follows the frame, not whichever tab
 * happens to have the focus: in your own code VS Code steps by statements as always, and only
 * where the pseudocode is the truth do our own steps take over.
 */
const IN_DECOMPILED_FRAME = 'ghidraDbg.decompiledFrame';

let inDecompiledFrame: boolean | undefined;

function setDecompiledFrame(active: boolean): void {
	if (inDecompiledFrame === active) {
		return; // setContext is a round trip to the renderer - do not spam it on every step
	}
	inDecompiledFrame = active;
	void vscode.commands.executeCommand('setContext', IN_DECOMPILED_FRAME, active);
}

let out: vscode.OutputChannel;
let currentLineDecoration: vscode.TextEditorDecorationType;
let locals: LocalsProvider;

interface DapStackFrame {
	id: number;
	name: string;
	line: number;
	source?: { name?: string; path?: string; sourceReference?: number };
	instructionPointerReference?: string;
	moduleId?: number | string;
}

interface DapModule {
	id: number | string;
	name: string;
	path?: string;
}

interface SessionState {
	capabilities?: Record<string, unknown>;
	frames: Map<number, DapStackFrame>;
	modules?: Map<string, DapModule>;
	armed?: boolean;
	stopWaiters: Array<() => void>;
	lastThreadId?: number;
}

interface CachedDecompilation {
	/** the program in Ghidra - its pointer size and byte order are how memory is read */
	program: ghidra.GhidraProgram;
	/** The ranges are in Ghidra's static addresses. */
	min: bigint;
	max: bigint;
	/** runtime address - static address; non-zero when the loader relocated the module */
	delta: bigint;
	doc: DecompiledDoc;
	uri: vscode.Uri;
}

const sessions = new Map<string, SessionState>();
const docs = new Map<string, DecompiledDoc>();
const docChanged = new vscode.EventEmitter<vscode.Uri>();

/** Walking the stack hits the same functions over and over, and decompilation is not free. */
const decompCache: CachedDecompilation[] = [];

let programCache: ghidra.GhidraProgram[] | undefined;

function stateFor(id: string): SessionState {
	let state = sessions.get(id);
	if (!state) {
		state = { frames: new Map(), stopWaiters: [] };
		sessions.set(id, state);
	}
	return state;
}

function log(message: string): void {
	out.appendLine(message);
}

function requireSession(): vscode.DebugSession | undefined {
	const session = vscode.debug.activeDebugSession;
	if (!session) {
		vscode.window.showWarningMessage('No active debug session.');
		return undefined;
	}
	return session;
}

function normalizePath(value: string): string {
	return value.replace(/\\/g, '/').replace(/^\/+/, '').toLowerCase();
}

// --- resolving module -> program in Ghidra -> pseudocode ---

async function modulesFor(session: vscode.DebugSession): Promise<Map<string, DapModule>> {
	const state = stateFor(session.id);
	if (state.modules) {
		return state.modules;
	}
	// some adapters (cppvsdbg) reject an empty argument object, they want explicit values
	const response = await session.customRequest('modules', { startModule: 0, moduleCount: 0 });
	const map = new Map<string, DapModule>();
	for (const mod of (response?.modules ?? []) as DapModule[]) {
		map.set(String(mod.id), mod);
	}
	state.modules = map;
	return map;
}

const HEADER_BYTES = 16;

/** program in Ghidra -> (runtime address - static address) */
const moduleDeltas = new Map<string, bigint>();

/**
 * Not every adapter reports module bases - cppvsdbg does not - and the loader can relocate a
 * module when its preferred base is taken. So we find the base ourselves: images load on an
 * alignment boundary (ghidraDbg.modules.baseAlignment), so we walk back along those looking
 * for a header matching what Ghidra has at its own image base.
 */
async function deltaFor(
	session: vscode.DebugSession,
	program: ghidra.GhidraProgram,
	addressInModule: bigint
): Promise<bigint> {
	const known = moduleDeltas.get(program.name);
	if (known !== undefined) {
		return known;
	}

	const imageBase = toAddr(program.imageBase);
	const header = (await ghidra.readBytes(program.name, program.imageBase, HEADER_BYTES)).hex.toLowerCase();

	const alignment = config.modules.baseAlignment();
	const limit = config.modules.baseScanLimit();
	let candidate = (addressInModule / alignment) * alignment;
	for (let step = 0; step < limit && candidate > 0n; step++, candidate -= alignment) {
		const live = (await readMemory(session, candidate, HEADER_BYTES))?.toString('hex');
		if (live?.toLowerCase() === header) {
			const delta = candidate - imageBase;
			moduleDeltas.set(program.name, delta);
			log(
				`${program.name}: runtime base ${formatAddr(candidate)}, ` +
					`image base ${formatAddr(imageBase)}, delta ${delta === 0n ? '0' : formatAddr(delta)}`
			);
			return delta;
		}
	}
	throw new Error(
		`could not find the base of ${program.name} scanning down from ${formatAddr(addressInModule)} ` +
			`(${limit} steps of ${formatAddr(alignment)} - see ghidraDbg.modules.*)`
	);
}

async function programFor(modulePath: string): Promise<ghidra.GhidraProgram> {
	const needle = normalizePath(modulePath);
	if (!programCache) {
		programCache = await ghidra.listPrograms();
	}
	let hit = programCache.find((program) => normalizePath(program.path) === needle);
	if (!hit) {
		// the program may have just been opened in Ghidra - refresh once before giving up
		programCache = await ghidra.listPrograms();
		hit = programCache.find((program) => normalizePath(program.path) === needle);
	}
	if (!hit) {
		throw new Error(`Ghidra has no program open for ${modulePath}`);
	}
	return hit;
}

function uriFor(moduleName: string, doc: DecompiledDoc): vscode.Uri {
	const safeName = doc.functionName.replace(/[^A-Za-z0-9_]+/g, '_');
	return vscode.Uri.parse(`${SCHEME}:/${moduleName}/${safeName}_${doc.entry}.c`);
}

/** The inverse of uriFor: ghidra-decomp:/<module>/<name>_<entry>.c */
function parseUri(uri: vscode.Uri): { moduleName: string; entry: string } | undefined {
	const parts = uri.path.split('/').filter(Boolean);
	if (parts.length < 2) {
		return undefined;
	}
	const entry = parts[1].replace(/\.c$/, '').split('_').pop();
	return entry ? { moduleName: parts[0], entry } : undefined;
}

/**
 * VS Code remembers breakpoints between sessions, so after re-attaching we have a breakpoint
 * on a document we have not fetched yet. We rebuild it from the URI alone.
 */
async function ensureEntry(
	session: vscode.DebugSession,
	uri: vscode.Uri
): Promise<CachedDecompilation | undefined> {
	const key = uri.toString();
	const cached = decompCache.find((entry) => entry.uri.toString() === key);
	if (cached) {
		return cached;
	}

	const parsed = parseUri(uri);
	if (!parsed) {
		return undefined;
	}
	const modules = await modulesFor(session);
	const module = [...modules.values()].find((candidate) => candidate.name === parsed.moduleName);
	if (!module?.path) {
		return undefined;
	}

	const program = await programFor(module.path);
	// The delta cannot be computed without a runtime address, and here we only have the
	// static one from the URI. It settles by itself once you visit any frame of this module.
	const delta = moduleDeltas.get(program.name);
	if (delta === undefined) {
		throw new Error(`the base of ${program.name} is not known yet - enter a frame from this module`);
	}

	const staticEntry = toAddr(`0x${parsed.entry}`);
	const doc = DecompiledDoc.fromApi(await ghidra.decompile(program.name, formatAddr(staticEntry)));
	docs.set(key, doc);
	docChanged.fire(uri);

	const entry: CachedDecompilation = {
		program,
		min: doc.min,
		max: doc.max,
		delta,
		doc,
		uri,
	};
	decompCache.push(entry);
	return entry;
}

let syncTimer: ReturnType<typeof setTimeout> | undefined;
let syncChain: Promise<void> = Promise.resolve();

/**
 * A single F9 fires two events (remove + add), and setInstructionBreakpoints replaces the
 * whole list. Without debouncing and serializing, a sync carrying an empty list can overtake
 * the real one and silently disarm the breakpoint.
 */
function scheduleSync(session?: vscode.DebugSession): void {
	if (syncTimer) {
		clearTimeout(syncTimer);
	}
	syncTimer = setTimeout(() => {
		syncTimer = undefined;
		syncChain = syncChain.then(() => syncInstructionBreakpoints(session)).catch(() => undefined);
	}, 50);
}

/** Breakpoints the user set in the pseudocode, as runtime addresses. */
async function userBreakpointRefs(
	session: vscode.DebugSession
): Promise<{ refs: string[]; described: string[] }> {
	const refs: string[] = [];
	const described: string[] = [];

	for (const breakpoint of vscode.debug.breakpoints) {
		if (!(breakpoint instanceof vscode.SourceBreakpoint) || !breakpoint.enabled) {
			continue;
		}
		const uri = breakpoint.location.uri;
		if (uri.scheme !== SCHEME) {
			continue;
		}

		const line = breakpoint.location.range.start.line;
		try {
			const entry = await ensureEntry(session, uri);
			const staticAddress = entry?.doc.addressForLine(line);
			if (!entry || staticAddress === undefined) {
				log(`breakpoint on line ${line + 1} has no address - skipping`);
				continue;
			}
			const runtime = staticAddress + entry.delta;
			refs.push(formatAddr(runtime));
			described.push(`${entry.doc.functionName}:${line + 1} -> ${formatAddr(runtime)}`);
		}
		catch (err) {
			log(`breakpoint on line ${line + 1}: ${err}`);
		}
	}
	return { refs, described };
}

/**
 * Sends the full set of breakpoints, because the request replaces the whole list. `extra`
 * holds the temporary addresses used by stepping - those do not clutter the log.
 */
async function applyInstructionBreakpoints(
	session: vscode.DebugSession,
	extra: string[] = []
): Promise<void> {
	const { refs, described } = await userBreakpointRefs(session);
	const all = [...new Set([...refs, ...extra])];

	try {
		const response = await session.customRequest('setInstructionBreakpoints', {
			breakpoints: all.map((instructionReference) => ({ instructionReference })),
		});
		if (extra.length === 0) {
			const verified = (response?.breakpoints ?? []).filter((bp: any) => bp?.verified).length;
			log(`instruction breakpoints: sent ${all.length}, armed ${verified}`);
			described.forEach((entry) => log(`  ${entry}`));
		}
	}
	catch (err) {
		log(`setInstructionBreakpoints failed: ${err}`);
	}
}

async function syncInstructionBreakpoints(session?: vscode.DebugSession): Promise<void> {
	const target = session ?? vscode.debug.activeDebugSession;
	if (target) {
		await applyInstructionBreakpoints(target);
	}
}

/** The module a frame's code sits in - none at all for a trampoline or a JIT stub. */
async function moduleOf(
	session: vscode.DebugSession,
	frame: DapStackFrame
): Promise<DapModule | undefined> {
	const modules = await modulesFor(session);
	return frame.moduleId === undefined ? undefined : modules.get(String(frame.moduleId));
}

async function resolveFrame(
	session: vscode.DebugSession,
	frame: DapStackFrame
): Promise<{ entry: CachedDecompilation; address: bigint }> {
	const pointer = frame.instructionPointerReference;
	if (!pointer) {
		throw new Error('the frame carries no instruction address');
	}

	const module = await moduleOf(session, frame);
	if (!module?.path) {
		throw new Error(`could not determine the module for frame ${frame.name}`);
	}

	const program = await programFor(module.path);
	const delta = await deltaFor(session, program, toAddr(pointer));
	const address = toAddr(pointer) - delta;

	let hit = decompCache.find(
		(entry) => entry.program.name === program.name && entry.min <= address && address <= entry.max
	);
	if (!hit) {
		const fresh = DecompiledDoc.fromApi(await ghidra.decompile(program.name, formatAddr(address)));
		const freshUri = uriFor(module.name, fresh);
		docs.set(freshUri.toString(), fresh);
		docChanged.fire(freshUri);
		hit = { program, min: fresh.min, max: fresh.max, delta, doc: fresh, uri: freshUri };
		decompCache.push(hit);
	}
	return { entry: hit, address };
}

/** The editor group the pseudocode lives in; the Disassembly view goes to the one next to it. */
let pseudoColumn: vscode.ViewColumn | undefined;
let disassemblyOpened = false;
const typedDocs = new Set<string>();

/**
 * The pseudocode always returns to the same editor group. Without that it opens wherever the
 * focus happens to be - including the group holding the Disassembly view, and then the two
 * keep swapping tabs on every stop, which is exactly the flicker we are avoiding.
 */
async function openPseudocode(uri: vscode.Uri): Promise<vscode.TextEditor> {
	const key = uri.toString();
	const active = vscode.window.activeTextEditor;
	if (active?.document.uri.toString() === key && active.viewColumn === pseudoColumn) {
		return active; // already in front - do not reopen it
	}

	let textDocument = await vscode.workspace.openTextDocument(uri);
	if (!typedDocs.has(key)) {
		typedDocs.add(key);
		textDocument = await vscode.languages.setTextDocumentLanguage(textDocument, 'c');
	}

	const editor = await vscode.window.showTextDocument(textDocument, {
		preview: true,
		viewColumn: pseudoColumn,
	});
	pseudoColumn = editor.viewColumn ?? pseudoColumn;
	return editor;
}

/**
 * The Ghidra layout: pseudocode in one group, VS Code's Disassembly view in the one beside it.
 * Set up once per session - from then on the Disassembly view follows the current frame itself.
 */
async function ensureDisassemblySplit(editor: vscode.TextEditor, force = false): Promise<void> {
	const wanted = force || config.splitDisassembly();
	if (disassemblyOpened || !wanted) {
		return;
	}
	disassemblyOpened = true; // one attempt per session, also when it fails

	try {
		if (vscode.window.tabGroups.all.length < 2) {
			await vscode.commands.executeCommand('vscode.setEditorLayout', {
				orientation: 0,
				groups: [{}, {}],
			});
		}
		await vscode.commands.executeCommand(
			editor.viewColumn === vscode.ViewColumn.One
				? 'workbench.action.focusSecondEditorGroup'
				: 'workbench.action.focusFirstEditorGroup'
		);
		await vscode.commands.executeCommand('debug.action.openDisassemblyView');
		// back to the pseudocode, otherwise F10/F11 would land in the disassembly
		await vscode.window.showTextDocument(editor.document, {
			viewColumn: editor.viewColumn,
			preview: true,
		});
	}
	catch (err) {
		log(`disassembly split: ${err}`);
	}
}

async function showFrame(session: vscode.DebugSession, frame: DapStackFrame): Promise<void> {
	const { entry, address } = await resolveFrame(session, frame);
	const { doc, uri } = entry;

	// From here on the pseudocode is what the stepping keys act on.
	setDecompiledFrame(true);

	locals.setFrame({
		session,
		frameId: frame.id,
		threadId: currentThreadId(session),
		program: entry.program.name,
		pointerSize: entry.program.pointerSize,
		bigEndian: entry.program.bigEndian,
		delta: entry.delta,
		doc,
		address,
	});

	const editor = await openPseudocode(uri);
	await ensureDisassemblySplit(editor);

	const line = doc.lineForAddress(address);
	if (line === undefined) {
		log(`${doc.functionName}: could not map address ${formatAddr(address)} to any line`);
		editor.setDecorations(currentLineDecoration, []);
		return;
	}

	const range = editor.document.lineAt(line).range;
	editor.setDecorations(currentLineDecoration, [range]);
	editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
	editor.selection = new vscode.Selection(range.start, range.start);
	log(`${doc.functionName}: ${formatAddr(address)} -> line ${line + 1}`);
}

// --- session tracking ---

const trackerFactory: vscode.DebugAdapterTrackerFactory = {
	createDebugAdapterTracker(session: vscode.DebugSession): vscode.DebugAdapterTracker {
		const state = stateFor(session.id);
		return {
			onDidSendMessage(message: any): void {
				if (message.type === 'response' && message.command === 'initialize' && message.body) {
					state.capabilities = message.body;
					log(`\n=== capabilities [${session.type}] ===`);
					for (const key of [
						'supportsInstructionBreakpoints',
						'supportsModulesRequest',
						'supportsDisassembleRequest',
						'supportsReadMemoryRequest',
					]) {
						log(`  ${key.padEnd(32)}: ${message.body[key] === true}`);
					}
				}

				// new DLLs can show up later on - invalidate the module cache
				if (message.type === 'event' && message.event === 'module') {
					state.modules = undefined;
				}

				if (message.type === 'event' && message.event === 'continued') {
					locals.clear('The program is running - stop it to see the variables.');
					setDecompiledFrame(false); // nothing to step while it runs
				}

				if (message.type === 'event' && message.event === 'stopped') {
					if (typeof message.body?.threadId === 'number') {
						state.lastThreadId = message.body.threadId;
					}
					// Registers and values from the previous stop are stale now. Skipped during
					// our own stepping loop - otherwise we would recompute them per instruction.
					if (!stepping) {
						locals.invalidate();
					}
					state.stopWaiters.splice(0).forEach((resolve) => resolve());
					// By the first stop the modules are loaded, so only now does it make sense
					// to arm the breakpoints remembered from a previous session.
					if (!state.armed) {
						state.armed = true;
						scheduleSync(session);
					}
				}

				if (message.type === 'response' && message.command === 'stackTrace' && message.body?.stackFrames) {
					for (const frame of message.body.stackFrames as DapStackFrame[]) {
						state.frames.set(frame.id, frame);
					}
				}
			},
		};
	},
};

// --- diagnostic commands ---

function suggestedAddress(session: vscode.DebugSession): string | undefined {
	for (const frame of stateFor(session.id).frames.values()) {
		if (!frame.source?.path && frame.instructionPointerReference) {
			return frame.instructionPointerReference;
		}
	}
	return undefined;
}

async function cmdModules(): Promise<void> {
	const session = requireSession();
	if (!session) {
		return;
	}
	out.show(true);
	log(`\n=== modules [${session.type}] ===`);
	try {
		const modules = await modulesFor(session);
		for (const module of modules.values()) {
			log(`  id=${module.id} ${module.name} ${module.path ?? ''}`);
		}
	}
	catch (err) {
		log(`ERROR: ${err}`);
	}
}

async function cmdInstructionBreakpoint(): Promise<void> {
	const session = requireSession();
	if (!session) {
		return;
	}
	const address = await vscode.window.showInputBox({
		title: 'setInstructionBreakpoints',
		prompt: 'Runtime address in hex, e.g. 0x1009D2AD',
		value: suggestedAddress(session) ?? '',
	});
	if (!address) {
		return;
	}
	out.show(true);
	try {
		const response = await session.customRequest('setInstructionBreakpoints', {
			breakpoints: [{ instructionReference: address }],
		});
		log(`\n=== setInstructionBreakpoints @ ${address} ===`);
		log(JSON.stringify(response, null, 2));
	}
	catch (err) {
		log(`ERROR: ${err}`);
	}
}

/**
 * The whole value computation hangs on reading the stack and frame pointer of the selected
 * frame, and some adapters (cppvsdbg among them) have no dedicated request for that. This
 * command dumps raw what both paths return: the register scope and evaluating the register
 * pseudo-variables. Which registers those are comes from Ghidra, per processor.
 */
async function cmdRegisters(): Promise<void> {
	const session = requireSession();
	if (!session) {
		return;
	}
	const item = vscode.debug.activeStackItem;
	if (!(item instanceof vscode.DebugStackFrame)) {
		vscode.window.showWarningMessage('Select a frame in the call stack first.');
		return;
	}
	out.show(true);

	let program: ghidra.GhidraProgram | undefined;
	let model: ghidra.RegisterModel | undefined;
	try {
		const current = await frameFor(session, item.threadId, item.frameId);
		const resolved = current ? await resolveFrame(session, current) : undefined;
		program = resolved?.entry.program;
		model = program ? await registerModelOf(program.name) : undefined;
		log(
			`\n=== target [${program?.languageId ?? 'unknown language'}] ===\n` +
				`  stack pointer=${model?.stackPointer ?? '?'} frame pointer=${model?.framePointer ?? '?'} ` +
				`pointer size=${program?.pointerSize ?? '?'} ${program?.bigEndian ? 'big' : 'little'} endian`
		);
	}
	catch (err) {
		log(`\n=== target: no Ghidra program behind this frame (${err}) ===`);
	}
	const probes = [model?.stackPointer, model?.framePointer].filter(
		(name): name is string => Boolean(name)
	);

	log(`\n=== scopes [frame ${item.frameId}] ===`);
	try {
		const scopes = await session.customRequest('scopes', { frameId: item.frameId });
		for (const scope of (scopes?.scopes ?? []) as any[]) {
			log(`  ${scope.name} (ref=${scope.variablesReference})`);
			if (!scope.variablesReference) {
				continue;
			}
			const variables = await session.customRequest('variables', {
				variablesReference: scope.variablesReference,
			});
			for (const variable of ((variables?.variables ?? []) as any[]).slice(0, 40)) {
				log(`    ${variable.name} = ${variable.value} (ref=${variable.variablesReference ?? 0})`);
			}
		}
	}
	catch (err) {
		log(`  ERROR: ${err}`);
	}

	log('=== evaluate ===');
	for (const name of probes) {
		for (const expression of [`@${name.toLowerCase()}`, `$${name.toLowerCase()}`, name.toLowerCase()]) {
			try {
				const response = await session.customRequest('evaluate', {
					expression,
					frameId: item.frameId,
					context: 'watch',
				});
				log(`  ${expression} -> ${response?.result}`);
			}
			catch (err) {
				log(`  ${expression} -> ERROR: ${err}`);
			}
		}
	}

	clearFrameCaches();
	const registers = await readRegisters(session, item.frameId, probes);
	const listed = [...registers].map(([name, value]) => `${name}=${formatAddr(value)}`).join(' ');
	log(`=== recognized by the extension: ${listed || 'none'}`);

	log('=== call stack ===');
	try {
		const trace = await session.customRequest('stackTrace', {
			threadId: item.threadId,
			startFrame: 0,
			levels: 12,
		});
		for (const frame of (trace?.stackFrames ?? []) as DapStackFrame[]) {
			const marker = frame.id === item.frameId ? '>' : ' ';
			log(
				`${marker} id=${frame.id} ip=${frame.instructionPointerReference ?? 'none'} ` +
					`mod=${frame.moduleId ?? '-'} ${frame.name}`
			);
		}
	}
	catch (err) {
		log(`  ERROR: ${err}`);
	}

	// The frame base comes from the return address sitting somewhere in this dump.
	const stackPointer = model?.stackPointer;
	const sp = stackPointer ? registers.get(stackPointer.toUpperCase()) : undefined;
	if (stackPointer && sp !== undefined && program) {
		const stride = Math.max(program.pointerSize, 1);
		log(`=== stack from ${stackPointer}=${formatAddr(sp)} ===`);
		const buffer = await readMemory(session, sp, stride * 32);
		for (let offset = 0; buffer && offset + stride <= buffer.length; offset += stride) {
			const slot = readWord(buffer, offset, stride, program.bigEndian);
			log(`  ${formatAddr(sp + BigInt(offset))}: ${formatAddr(slot)}`);
		}
	}
}

/**
 * Whether "step into which call?" can work at all comes down to what the debugger's own
 * disassembler reports for the current line - above all, whether its instructions carry
 * line information.
 */
async function cmdLineDisassembly(): Promise<void> {
	const session = requireSession();
	if (!session) {
		return;
	}
	const item = vscode.debug.activeStackItem;
	if (!(item instanceof vscode.DebugStackFrame)) {
		vscode.window.showWarningMessage('Select a frame in the call stack first.');
		return;
	}
	const frame = await frameFor(item.session, item.threadId, item.frameId);
	if (!frame?.instructionPointerReference) {
		vscode.window.showWarningMessage('No data for this frame.');
		return;
	}

	out.show(true);
	log(
		`\n=== line disassembly [${frame.name}] ip=${frame.instructionPointerReference} ` +
			`line=${frame.line} source=${frame.source?.path ?? 'none'} ===`
	);
	// the raw request, not the helper: here the error itself is the interesting part
	let instructions: DapInstruction[] = [];
	try {
		const response = await session.customRequest('disassemble', {
			memoryReference: frame.instructionPointerReference,
			instructionOffset: 0,
			instructionCount: 40,
			resolveSymbols: true,
		});
		instructions = (response?.instructions ?? []) as DapInstruction[];
	}
	catch (err) {
		log(`  disassemble FAILED: ${err}`);
		return;
	}
	if (instructions.length === 0) {
		log('  the disassemble request returned an empty list');
		return;
	}
	instructions.forEach((instruction, index) => {
		log(
			`  ${String(index).padStart(2)} ${instruction.address} ` +
				`line=${instruction.line ?? '-'} loc=${instruction.location?.name ?? '-'} ` +
				`sym=${instruction.symbol ?? '-'} | ${instruction.instruction}`
		);
	});
	// the raw shape too, in case the adapter fills fields we are not reading
	log(`  raw[0..1]: ${JSON.stringify(instructions.slice(0, 2))}`);
}

async function cmdShowFrame(): Promise<void> {
	const session = requireSession();
	if (!session) {
		return;
	}
	const item = vscode.debug.activeStackItem;
	if (!(item instanceof vscode.DebugStackFrame)) {
		vscode.window.showWarningMessage('Select a frame in the call stack first.');
		return;
	}
	const frame = await frameFor(item.session, item.threadId, item.frameId);
	if (!frame) {
		vscode.window.showWarningMessage('No data for this frame.');
		return;
	}
	try {
		await showFrame(item.session, frame);
	}
	catch (err) {
		vscode.window.showErrorMessage(`Pseudocode: ${err}`);
		log(`ERROR: ${err}`);
	}
}

/**
 * After our own stepping VS Code does not bring the source file up: the continue and the
 * steps went out through customRequest, behind its back, so its debug model still believes
 * the session stands where it last saw it. Leaving the pseudocode is therefore ours to show.
 */
async function revealSource(frame: DapStackFrame): Promise<void> {
	const path = frame.source?.path;
	if (!path || !(await hasUsableSource(frame))) {
		return;
	}
	setDecompiledFrame(false); // back in code with sources - VS Code's own stepping fits again
	try {
		const document = await vscode.workspace.openTextDocument(vscode.Uri.file(path));
		const editor = await vscode.window.showTextDocument(document, {
			preview: true,
			viewColumn: pseudoColumn,
		});
		const line = Math.min(Math.max((frame.line ?? 1) - 1, 0), editor.document.lineCount - 1);
		const range = editor.document.lineAt(line).range;
		editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
		editor.selection = new vscode.Selection(range.start, range.start);

		// the highlight left in the pseudocode would claim we are still standing there
		vscode.window.visibleTextEditors
			.filter((candidate) => candidate.document.uri.scheme === SCHEME)
			.forEach((candidate) => candidate.setDecorations(currentLineDecoration, []));
	}
	catch (err) {
		log(`could not show ${path}:${frame.line}: ${err}`);
	}
}

/**
 * Our F10/F11 stay bound while a pseudocode tab is focused, and after returning from a
 * function without sources the debugger is back in code that has them while that tab is still
 * the active one. Stepping by pseudocode then makes no sense - and asking Ghidra about a
 * module that is not open there only produced an error and no step at all.
 */
async function plainStep(
	session: vscode.DebugSession,
	threadId: number,
	frame: DapStackFrame,
	kind: 'next' | 'stepIn'
): Promise<boolean> {
	if (!(await hasUsableSource(frame))) {
		return false;
	}
	try {
		await session.customRequest(kind, { threadId });
	}
	catch (err) {
		log(`step: ${err}`);
	}
	return true;
}

/**
 * After our step VS Code picks a frame to show on its own, and when the topmost one has no
 * sources it reaches for the first one that does - that is, back to the calling code.
 * We wait for it to do that and only then open the pseudocode.
 */
let stepping = false;

function delay(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForStop(
	session: vscode.DebugSession,
	timeoutMs = config.stepping.stopTimeoutMs()
): Promise<void> {
	const state = stateFor(session.id);
	return new Promise((resolve, reject) => {
		const waiter = () => {
			clearTimeout(timer);
			resolve();
		};
		const timer = setTimeout(() => {
			state.stopWaiters = state.stopWaiters.filter((entry) => entry !== waiter);
			reject(new Error('no stop within the expected time'));
		}, timeoutMs);
		state.stopWaiters.push(waiter);
	});
}

/**
 * Our stepping loop drives the session through many running/stopped transitions, and
 * VS Code clears activeStackItem then and does not always set it back. So the thread
 * comes primarily from the stopped events we observe.
 */
function currentThreadId(session: vscode.DebugSession): number | undefined {
	const item = vscode.debug.activeStackItem;
	if (item && item.session.id === session.id) {
		return item.threadId;
	}
	return stateFor(session.id).lastThreadId;
}

const sourceExists = new Map<string, boolean>();

/**
 * A PDB can point at sources that are not on this machine - that is the case for CRT
 * helpers like __chkstk. Handing such a frame to VS Code ends with an editor open error,
 * so we treat it as code without sources.
 */
async function hasUsableSource(frame: DapStackFrame): Promise<boolean> {
	const path = frame.source?.path;
	if (!path) {
		return false;
	}
	const cached = sourceExists.get(path);
	if (cached !== undefined) {
		return cached;
	}
	let exists = false;
	try {
		await vscode.workspace.fs.stat(vscode.Uri.file(path));
		exists = true;
	}
	catch {
		exists = false;
	}
	sourceExists.set(path, exists);
	return exists;
}

/**
 * The stack can be asked for only while the target is stopped, and after a step of ours it
 * is not always still stopped - the adapter refuses with "the operation cannot be performed
 * while the target process is running". That is a state, not a failure worth a popup.
 */
async function topFrame(session: vscode.DebugSession, threadId: number): Promise<DapStackFrame | undefined> {
	try {
		const trace = await session.customRequest('stackTrace', { threadId, startFrame: 0, levels: 1 });
		return trace?.stackFrames?.[0] as DapStackFrame | undefined;
	}
	catch (err) {
		log(`stackTrace: ${err}`);
		return undefined;
	}
}

/**
 * The frame map built from observed responses is only a shortcut - VS Code does not always
 * send stackTrace after a stop, so when an entry is missing we ask the debugger directly.
 */
async function frameFor(
	session: vscode.DebugSession,
	threadId: number,
	frameId: number
): Promise<DapStackFrame | undefined> {
	const state = stateFor(session.id);
	const cached = state.frames.get(frameId);
	if (cached) {
		return cached;
	}
	try {
		const trace = await session.customRequest('stackTrace', { threadId, startFrame: 0, levels: 200 });
		const frames = (trace?.stackFrames ?? []) as DapStackFrame[];
		frames.forEach((frame) => state.frames.set(frame.id, frame));
		const hit = frames.find((frame) => frame.id === frameId);
		if (!hit) {
			log(`frame ${frameId}: asked for the stack, got ${frames.length} frames, id=[${frames
				.map((frame) => frame.id)
				.join(', ')}]`);
		}
		return hit;
	}
	catch (err) {
		log(`could not fetch frame ${frameId}: ${err}`);
		return undefined;
	}
}

/**
 * VS Code steps with 'statement' granularity, and code without sources has no source lines, so such
 * a step runs away to code that does have them. We step by instructions ourselves until the
 * address lands on a different pseudocode line - a single instruction step would look like
 * a highlight standing still, because one line covers several of them.
 */
async function stepPseudocode(kind: 'next' | 'stepIn'): Promise<void> {
	const session = vscode.debug.activeDebugSession;
	if (!session) {
		log('step: no active debug session');
		return;
	}
	const threadId = currentThreadId(session);
	if (threadId === undefined) {
		log('step: unknown thread id - is the debugger stopped?');
		return;
	}
	if (stepping) {
		log('step: the previous step is still running - skipping');
		return;
	}
	stepping = true;
	try {
		await runStep(session, threadId, kind);
	}
	finally {
		stepping = false;
	}
}

async function runStep(
	session: vscode.DebugSession,
	threadId: number,
	kind: 'next' | 'stepIn'
): Promise<void> {
	let origin: { entry: CachedDecompilation; address: bigint };
	try {
		const frame = await topFrame(session, threadId);
		if (!frame) {
			log('step: no frame on top of the stack');
			return;
		}
		if (await plainStep(session, threadId, frame, kind)) {
			return;
		}
		origin = await resolveFrame(session, frame);
	}
	catch (err) {
		log(`step: could not establish the starting point (${err})`);
		return;
	}

	const startLine = origin.entry.doc.lineForAddress(origin.address);

	const maxSteps = config.stepping.maxInstructionSteps();
	for (let i = 0; i < maxSteps; i++) {
		const stopped = waitForStop(session);
		try {
			await session.customRequest(kind, { threadId, granularity: 'instruction' });
			await stopped;
		}
		catch (err) {
			log(`step: ${err}`);
			return;
		}

		const frame = await topFrame(session, threadId);
		const pointer = frame?.instructionPointerReference;
		if (!frame || !pointer) {
			return;
		}
		if (await hasUsableSource(frame)) {
			await revealSource(frame); // back in code with sources
			return;
		}

		// cached ranges are static, while the frame gives a runtime address
		const address = toAddr(pointer) - origin.entry.delta;
		const sameFunction = address >= origin.entry.min && address <= origin.entry.max;
		if (!sameFunction || origin.entry.doc.lineForAddress(address) !== startLine) {
			try {
				await delay(config.stepping.settleMs());
				await showFrame(session, frame);
			}
			catch (err) {
				// The step worked, we just have nothing to show - without this message it
				// looks as if the key did nothing.
				const reason = err instanceof Error ? err.message : String(err);
				log(`step: stopped in ${frame.name} (${pointer}), but with no pseudocode: ${reason}`);
				vscode.window.setStatusBarMessage(`Ghidra: ${reason}`, 6000);
			}
			return;
		}
	}

	log(`step: ${maxSteps} instructions without a line change - aborted`);
}

const MAX_SOURCE_LINE_INSTRUCTIONS = 40;

/**
 * The calls of the line the frame stands on. For code with sources the extent of the line
 * comes from the debugger: only the first instruction of a line group carries the line
 * number, the rest inherit it, so we stop at the first instruction that reports a different
 * one. For pseudocode the extent is the address range Ghidra gave us for that line.
 */
async function callSitesFor(
	session: vscode.DebugSession,
	frame: DapStackFrame
): Promise<CallSite[]> {
	const pointer = frame.instructionPointerReference;
	if (!pointer) {
		return [];
	}
	const ip = toAddr(pointer);

	if (frame.source?.path) {
		// disassemble numbers lines differently than stackTrace does - for a frame on line 36
		// its instructions report line 35 with endLine 36 - so the group is anchored on the
		// line of the first instruction instead of on the frame's. A missing line number
		// means "still the same line"; the cap guards against no line information at all.
		let reference: number | undefined;
		return callsOnLine(session, ip, (instruction, index) => {
			if (index >= MAX_SOURCE_LINE_INSTRUCTIONS) {
				return false;
			}
			if (instruction.line === undefined) {
				return true;
			}
			reference ??= instruction.line;
			return instruction.line === reference;
		});
	}

	const { entry, address } = await resolveFrame(session, frame);
	const line = entry.doc.lineForAddress(address);
	const range = line === undefined ? undefined : entry.doc.rangeForLine(line);
	if (!range) {
		return [];
	}
	const last = range.max + entry.delta;
	const resolve = async (target: bigint): Promise<string | undefined> => {
		try {
			const info = await ghidra.symbolAt(entry.program.name, formatAddr(target - entry.delta));
			return info.function ?? info.symbol ?? undefined;
		}
		catch {
			return undefined; // a target outside this module, or Ghidra does not know it
		}
	};
	return callsOnLine(session, ip, (instruction) => toAddr(instruction.address) <= last, resolve);
}

/**
 * Step over the instructions of the line up to the chosen call, then into it. Walking beats
 * a temporary breakpoint here: it stays inside this line and cannot let the target run away.
 */
async function stepIntoCall(
	session: vscode.DebugSession,
	threadId: number,
	site: CallSite
): Promise<boolean> {
	let reached = false;
	for (let i = 0; i < config.stepping.maxWalkSteps() && !reached; i++) {
		const frame = await topFrame(session, threadId);
		const pointer = frame?.instructionPointerReference;
		if (!pointer) {
			log('step into call: no frame on top of the stack');
			return false;
		}
		if (toAddr(pointer) === site.address) {
			reached = true;
			break;
		}
		const stopped = waitForStop(session);
		try {
			await session.customRequest('next', { threadId, granularity: 'instruction' });
			await stopped;
		}
		catch (err) {
			log(`step into call: ${err}`);
			return false;
		}
	}
	if (!reached) {
		log(`step into call: ${formatAddr(site.address)} not reached - the line branched around it`);
		return false;
	}

	const stopped = waitForStop(session);
	try {
		await session.customRequest('stepIn', { threadId, granularity: 'instruction' });
		await stopped;
	}
	catch (err) {
		log(`step into call: ${err}`);
		return false;
	}

	await showWhereWeLanded(session, threadId, 'step into call');
	return true;
}

/**
 * Step into, whatever the call leads to. A plain stepIn skips everything the adapter has no
 * sources for, so we step by instructions ourselves and then show what we found: your own
 * source when the call went there, the pseudocode from Ghidra when it went into a module
 * without sources, and neither when the line had nothing to enter - then we end up on the
 * next line, exactly as a normal step would.
 */
async function stepIntoBinary(): Promise<void> {
	const session = vscode.debug.activeDebugSession;
	if (!session) {
		log('stepIntoBinary: no active debug session');
		return;
	}
	const threadId = currentThreadId(session);
	if (threadId === undefined) {
		log('stepIntoBinary: unknown thread id - is the debugger stopped?');
		return;
	}
	if (stepping) {
		log('stepIntoBinary: the previous step is still running - skipping');
		return;
	}

	stepping = true;
	try {
		const start = await topFrame(session, threadId);

		// Walking the line up to the call and stepping in exactly there is what keeps us out
		// of the toolchain's own helpers: they are filtered out of the list, and we step over
		// them on the way. Stepping in blindly enters them instead, and every one of those
		// stops is seen by VS Code, which opens the source file they have no copy of - the
		// empty stack.cpp. More than one call also means a choice to offer, because an adapter
		// without stepInTargets (cppvsdbg has none) would always take the first.
		if (start) {
			let sites: CallSite[] = [];
			try {
				sites = await callSitesFor(session, start);
			}
			catch (err) {
				log(`step into: could not list the calls of this line (${err})`);
			}
			log(`step into: ${sites.length} call(s) on this line${sites.length > 1 ? ' - asking' : ''}`);
			if (sites.length > 1) {
				const chosen = await pickCallSite(sites);
				if (!chosen || (await stepIntoCall(session, threadId, chosen))) {
					return;
				}
				log('step into: falling back to stepping by instructions');
			}
			else if (sites.length === 1 && (await stepIntoCall(session, threadId, sites[0]))) {
				return;
			}
		}

		const startSource = start?.source?.path;
		const startLine = start?.line;
		const maxSteps = config.stepping.maxInstructionSteps();

		for (let i = 0; i < maxSteps; i++) {
			const stopped = waitForStop(session);
			try {
				await session.customRequest('stepIn', { threadId, granularity: 'instruction' });
				await stopped;
			}
			catch (err) {
				log(`stepIntoBinary: ${err}`);
				return;
			}

			const frame = await topFrame(session, threadId);
			if (!frame) {
				return;
			}

			if (!frame.source?.path) {
				// Same treatment as any other landing: a trampoline is stepped through first,
				// and what we end up in is shown as pseudocode - or as source, if it has any.
				await showWhereWeLanded(session, threadId, 'stepIntoBinary');
				return;
			}

			if (!(await hasUsableSource(frame))) {
				// A helper of the toolchain - the runtime checks of a Debug build, for one -
				// with debug information but no file on this machine to show. Leave it in one
				// go instead of grinding through it instruction by instruction.
				log(`stepIntoBinary: skipping ${frame.name} (${frame.source.path} does not exist)`);
				if (!(await leaveFrame(session, threadId, 'stepIntoBinary'))) {
					return;
				}
				closeMissingSourceTabs();
				continue;
			}

			if (frame.source.path !== startSource || frame.line !== startLine) {
				await revealSource(frame); // still in code with sources, just somewhere else
				return;
			}
		}
		log(`stepIntoBinary: ${maxSteps} instructions without reaching code that has no sources`);
	}
	finally {
		stepping = false;
	}
}

/**
 * Every stop is seen by VS Code too, and it opens the source of the frame on top - including
 * the file a toolchain helper points at and nobody has. We step out of such frames, but the
 * empty tab it opened in the meantime stays behind, so we close it again.
 */
function closeMissingSourceTabs(): void {
	for (const group of vscode.window.tabGroups.all) {
		for (const tab of group.tabs) {
			const input = tab.input;
			if (!(input instanceof vscode.TabInputText) || input.uri.scheme !== 'file') {
				continue;
			}
			if (sourceExists.get(input.uri.fsPath) === false) {
				void vscode.window.tabGroups.close(tab, false);
			}
		}
	}
}

/**
 * Leaves the frame on top of the stack. A plain stepOut is enough when the adapter can unwind
 * it; when it cannot - which is the case for code without sources - we break on the caller's
 * address instead and let it run there.
 */
async function leaveFrame(
	session: vscode.DebugSession,
	threadId: number,
	label: string
): Promise<boolean> {
	let frames: DapStackFrame[] = [];
	try {
		const trace = await session.customRequest('stackTrace', { threadId, startFrame: 0, levels: 2 });
		frames = (trace?.stackFrames ?? []) as DapStackFrame[];
	}
	catch (err) {
		log(`${label}: ${err}`);
		return false;
	}

	const target = frames[1]?.instructionPointerReference;
	const stopped = waitForStop(session, config.stepping.runTimeoutMs());
	try {
		if (target) {
			await applyInstructionBreakpoints(session, [target]);
			await session.customRequest('continue', { threadId });
		}
		else {
			await session.customRequest('stepOut', { threadId, granularity: 'instruction' });
		}
		await stopped;
		return true;
	}
	catch (err) {
		log(`${label}: could not leave ${frames[0]?.name ?? 'the frame'}: ${err}`);
		return false;
	}
	finally {
		if (target) {
			await applyInstructionBreakpoints(session); // drop the temporary one
		}
	}
}

/**
 * Where to break when the frame returns. The caller frame is not always usable: for
 * sourceless code the debugger hands us a synthetic frame with no address, and then the
 * return address is read off the stack, where it sits at the frame base.
 */
async function returnTarget(
	session: vscode.DebugSession,
	threadId: number,
	frames: DapStackFrame[],
	origin: { entry: CachedDecompilation; address: bigint },
	label: string
): Promise<string | undefined> {
	const carried = frames[1]?.instructionPointerReference;
	if (carried) {
		return carried;
	}
	const fromStack = await returnAddressOf({
		session,
		frameId: frames[0].id,
		threadId,
		program: origin.entry.program.name,
		pointerSize: origin.entry.program.pointerSize,
		bigEndian: origin.entry.program.bigEndian,
		delta: origin.entry.delta,
		doc: origin.entry.doc,
		address: origin.address,
	});
	log(
		fromStack === undefined
			? `${label}: no return address - leaving the function will not stop the program`
			: `${label}: the caller frame has no address, return address off the stack: ${formatAddr(fromStack)}`
	);
	return fromStack === undefined ? undefined : formatAddr(fromStack);
}

/**
 * A hook trampoline holds a handful of relocated instructions and a jump - long enough to
 * step through, short enough that this bound is generous. Past it, whatever we are in is not
 * a trampoline, and stopping beats stepping through the rest of the program one instruction
 * at a time.
 */
const MAX_UNMAPPED_STEPS = 32;

/**
 * Detour libraries (MinHook and friends) build their trampoline in memory that belongs to no
 * module, and so does a JIT. Stepping into a detoured function lands there first, and there
 * is nothing to show for such a frame: no module means no program in Ghidra, and the step
 * used to end on "could not determine the module". Step on instead - a few instructions later
 * the trampoline jumps into the real function, which is where you meant to go.
 */
async function stepPastUnmappedCode(
	session: vscode.DebugSession,
	threadId: number,
	label: string
): Promise<DapStackFrame | undefined> {
	let frame = await topFrame(session, threadId);
	for (let i = 0; frame && i < MAX_UNMAPPED_STEPS; i++) {
		if (frame.source?.path || (await moduleOf(session, frame))?.path) {
			return frame;
		}
		if (i === 0) {
			log(`${label}: ${frame.name} belongs to no module - a trampoline or a stub, stepping on`);
		}
		const stopped = waitForStop(session);
		try {
			await session.customRequest('stepIn', { threadId, granularity: 'instruction' });
			await stopped;
		}
		catch (err) {
			log(`${label}: ${err}`);
			return frame;
		}
		frame = await topFrame(session, threadId);
	}
	if (frame) {
		log(`${label}: still in code no module owns after ${MAX_UNMAPPED_STEPS} instructions`);
	}
	return frame;
}

/** Whatever we stopped on, show it: your own source, or the pseudocode from Ghidra. */
async function showWhereWeLanded(
	session: vscode.DebugSession,
	threadId: number,
	label: string
): Promise<void> {
	await delay(config.stepping.settleMs());
	const frame = await stepPastUnmappedCode(session, threadId, label);
	if (!frame) {
		return;
	}
	if (await hasUsableSource(frame)) {
		await revealSource(frame);
		return;
	}
	try {
		await showFrame(session, frame);
	}
	catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		log(`${label}: ${frame.name} without pseudocode: ${reason}`);
		vscode.window.setStatusBarMessage(`Ghidra: ${reason}`, 6000);
	}
}

/**
 * A step to the next pseudocode line. Instead of treading instruction by instruction -
 * which gave a dozen stops and as many editor jumps - we put temporary breakpoints on the
 * starts of all the other lines of the function plus on the return address, and let it run.
 * It stops once, on the line that actually comes next, so jumps and loops take care of
 * themselves.
 */
async function stepOverPseudoLine(): Promise<void> {
	const session = vscode.debug.activeDebugSession;
	if (!session) {
		log('stepOver: no active debug session');
		return;
	}
	const threadId = currentThreadId(session);
	if (threadId === undefined) {
		log('stepOver: unknown thread id - is the debugger stopped?');
		return;
	}
	if (stepping) {
		log('stepOver: the previous step is still running - skipping');
		return;
	}

	stepping = true;
	try {
		const trace = await session.customRequest('stackTrace', { threadId, startFrame: 0, levels: 2 });
		const frames = (trace?.stackFrames ?? []) as DapStackFrame[];
		if (frames.length === 0) {
			log('stepOver: empty stack');
			return;
		}

		if (await plainStep(session, threadId, frames[0], 'next')) {
			return;
		}

		const origin = await resolveFrame(session, frames[0]);
		const currentLine = origin.entry.doc.lineForAddress(origin.address);

		const targets = origin.entry.doc
			.lineStarts()
			.filter(({ line }) => line !== currentLine)
			.map(({ address }) => formatAddr(address + origin.entry.delta));

		// Without this, leaving the function would mean the target runs away without stopping -
		// and it comes back only when the same function is called again, which looks exactly
		// like being stuck in the pseudocode.
		const returnTo = await returnTarget(session, threadId, frames, origin, 'stepOver');
		if (returnTo) {
			targets.push(returnTo);
		}
		if (targets.length === 0) {
			log('stepOver: no target addresses in this function');
			return;
		}

		const stopped = waitForStop(session, config.stepping.runTimeoutMs());
		try {
			await applyInstructionBreakpoints(session, targets);
			await session.customRequest('continue', { threadId });
			await stopped;
		}
		catch (err) {
			log(`stepOver: ${err}`);
			return;
		}
		finally {
			await applyInstructionBreakpoints(session); // drop the temporary ones
		}

		await showWhereWeLanded(session, threadId, 'stepOver');
	}
	finally {
		stepping = false;
	}
}

async function stepOutPseudocode(): Promise<void> {
	const session = vscode.debug.activeDebugSession;
	if (!session) {
		log('stepOut: no active debug session');
		return;
	}
	const threadId = currentThreadId(session);
	if (threadId === undefined) {
		log('stepOut: unknown thread id');
		return;
	}
	if (stepping) {
		log('stepOut: the previous step is still running - skipping');
		return;
	}

	stepping = true;
	try {
		let frames: DapStackFrame[] = [];
		try {
			const trace = await session.customRequest('stackTrace', { threadId, startFrame: 0, levels: 2 });
			frames = (trace?.stackFrames ?? []) as DapStackFrame[];
		}
		catch (err) {
			log(`stepOut: ${err}`);
			return;
		}
		if (frames.length === 0) {
			log('stepOut: empty stack');
			return;
		}

		let target: string | undefined;
		if (!(await hasUsableSource(frames[0]))) {
			try {
				const origin = await resolveFrame(session, frames[0]);
				target = await returnTarget(session, threadId, frames, origin, 'stepOut');
			}
			catch (err) {
				log(`stepOut: no return address from Ghidra (${err})`);
			}
		}

		const stopped = waitForStop(session, config.stepping.runTimeoutMs());
		try {
			if (target) {
				// The adapter cannot step out of sourceless code - it fails to unwind the
				// frame, finds nowhere to break and simply resumes the target. We know where
				// the function returns to, so we break there ourselves.
				await applyInstructionBreakpoints(session, [target]);
				await session.customRequest('continue', { threadId });
			}
			else {
				await session.customRequest('stepOut', { threadId, granularity: 'instruction' });
			}
			await stopped;
		}
		catch (err) {
			log(`stepOut: ${err}`);
			return;
		}
		finally {
			if (target) {
				await applyInstructionBreakpoints(session); // drop the temporary one
			}
		}

		await showWhereWeLanded(session, threadId, 'stepOut');
	}
	finally {
		stepping = false;
	}
}

/** After renaming or retyping things in Ghidra the cache has to go and the decompilation be refetched. */
async function cmdRefresh(): Promise<void> {
	decompCache.length = 0;
	programCache = undefined;
	clearDepthCache();
	clearFrameCaches();
	clearProgramCaches();
	await cmdShowFrame();
}

// --- attaching to a process ---

/** The attach configuration from the workspace launch.json - by name, or the first attach one. */
function attachConfiguration(folder: vscode.WorkspaceFolder): vscode.DebugConfiguration | undefined {
	const wanted = config.attachConfiguration();
	const all =
		vscode.workspace
			.getConfiguration('launch', folder.uri)
			.get<vscode.DebugConfiguration[]>('configurations') ?? [];
	return wanted
		? all.find((config) => config?.name === wanted)
		: all.find((config) => config?.request === 'attach');
}

/**
 * VS Code has no Attach to Process action of its own - attaching means running an attach
 * configuration, and F5 only ever runs the one selected in the dropdown. This starts it by
 * name, so the configuration behaves exactly as it does from the dropdown, process picker
 * and all.
 */
async function cmdAttach(): Promise<void> {
	const folder = vscode.workspace.workspaceFolders?.[0];
	if (!folder) {
		vscode.window.showWarningMessage('No open folder - the attach configuration comes from its launch.json.');
		return;
	}
	const config = attachConfiguration(folder);
	if (!config) {
		vscode.window.showWarningMessage(`No attach configuration in ${folder.name}/.vscode/launch.json.`);
		return;
	}

	log(`attach: starting "${config.name}"`);
	await vscode.debug.startDebugging(folder, config.name);
}

/** Rebuilds the split by hand, e.g. after closing the Disassembly tab. */
async function cmdSplitDisassembly(): Promise<void> {
	const editor =
		vscode.window.visibleTextEditors.find((candidate) => candidate.document.uri.scheme === SCHEME) ??
		vscode.window.activeTextEditor;
	if (!editor) {
		vscode.window.showWarningMessage('Open the pseudocode of a frame without sources first.');
		return;
	}
	pseudoColumn = editor.viewColumn ?? pseudoColumn;
	disassemblyOpened = false;
	await ensureDisassemblySplit(editor, true);
}

/** The value of the variable under the cursor - the same one the Locals (Ghidra) panel shows. */
async function hoverValue(
	document: vscode.TextDocument,
	position: vscode.Position
): Promise<vscode.Hover | undefined> {
	const frame = locals.currentFrame();
	if (!frame || docs.get(document.uri.toString()) !== frame.doc) {
		return undefined; // pseudocode of a function other than the one we are standing in
	}
	const range = document.getWordRangeAtPosition(position);
	if (!range || !frame.doc.varNamed(document.getText(range))) {
		return undefined;
	}

	const entry = await locals.valueOf(document.getText(range));
	if (!entry) {
		return undefined;
	}
	const lines = [
		`\`${entry.variable.type} ${entry.variable.name}\` = \`${entry.approximate ? '≈ ' : ''}${entry.value}\``,
		'',
		`storage: \`${entry.location}\`${entry.address === undefined ? '' : ` (\`${formatAddr(entry.address)}\`)`}`,
	];
	if (entry.note) {
		lines.push('', `_${entry.note}_`);
	}
	return new vscode.Hover(new vscode.MarkdownString(lines.join('\n')), range);
}

export function activate(context: vscode.ExtensionContext): void {
	out = vscode.window.createOutputChannel('Ghidra Dbg');
	config.useLogger(log);
	currentLineDecoration = vscode.window.createTextEditorDecorationType({
		backgroundColor: new vscode.ThemeColor('editor.stackFrameHighlightBackground'),
		isWholeLine: true,
	});
	locals = new LocalsProvider(log, () => stepping);

	context.subscriptions.push(
		out,
		currentLineDecoration,

		vscode.debug.registerDebugAdapterTrackerFactory('*', trackerFactory),

		vscode.window.registerTreeDataProvider('ghidraDbg.locals', locals),
		vscode.languages.registerHoverProvider({ scheme: SCHEME }, { provideHover: hoverValue }),

		vscode.workspace.registerTextDocumentContentProvider(SCHEME, {
			onDidChange: docChanged.event,
			provideTextDocumentContent: (uri) =>
				docs.get(uri.toString())?.text ?? '// no decompiled code for this address',
		}),

		// Fires both on a stop and when you click a frame in the call stack.
		vscode.debug.onDidChangeActiveStackItem(async (item) => {
			if (!(item instanceof vscode.DebugStackFrame) || stepping) {
				return; // during our own step the loop shows the pseudocode itself
			}
			const frame = await frameFor(item.session, item.threadId, item.frameId);
			if (!frame) {
				log(`frame ${item.frameId} not found on the stack`);
				return;
			}
			if (frame.source?.path) {
				locals.clear('The frame has sources - its variables are in the Variables panel.');
				setDecompiledFrame(false);
				return; // it has a real source, VS Code will show it itself
			}
			try {
				await showFrame(item.session, frame);
			}
			catch (err) {
				const reason = err instanceof Error ? err.message : String(err);
				// No pseudocode means our stepping has nothing to work from either.
				setDecompiledFrame(false);
				log(`pseudocode skipped for ${frame.name}: ${reason}`);
				vscode.window.setStatusBarMessage(`Ghidra: ${reason}`, 6000);
			}
		}),

		vscode.debug.onDidChangeBreakpoints(() => scheduleSync()),

		vscode.debug.onDidTerminateDebugSession((session) => {
			sessions.delete(session.id);
			programCache = undefined;
			decompCache.length = 0;
			// module bases belong to one specific process, they do not carry over to the next
			moduleDeltas.clear();
			clearFrameCaches();
			locals.clear();
			setDecompiledFrame(false);
			pseudoColumn = undefined;
			disassemblyOpened = false;
		}),

		vscode.commands.registerCommand('ghidraDbg.showFrame', cmdShowFrame),
		vscode.commands.registerCommand('ghidraDbg.locals.refresh', () => locals.invalidate()),
		vscode.commands.registerCommand('ghidraDbg.splitDisassembly', cmdSplitDisassembly),
		vscode.commands.registerCommand('ghidraDbg.attach', cmdAttach),
		vscode.commands.registerCommand('ghidraDbg.spike.registers', cmdRegisters),
		vscode.commands.registerCommand('ghidraDbg.spike.lineDisassembly', cmdLineDisassembly),
		vscode.commands.registerCommand('ghidraDbg.refresh', cmdRefresh),
		vscode.commands.registerCommand('ghidraDbg.stepOver', stepOverPseudoLine),
		vscode.commands.registerCommand('ghidraDbg.stepInto', () => stepPseudocode('stepIn')),
		vscode.commands.registerCommand('ghidraDbg.stepOut', stepOutPseudocode),
		vscode.commands.registerCommand('ghidraDbg.stepIntoBinary', stepIntoBinary),
		vscode.commands.registerCommand('ghidraDbg.spike.modules', cmdModules),
		vscode.commands.registerCommand('ghidraDbg.spike.instructionBreakpoint', cmdInstructionBreakpoint),
		vscode.commands.registerCommand('ghidraDbg.showLog', () => out.show(true))
	);

	log('Ghidra Debug Bridge ready.');
}

export function deactivate(): void {
	sessions.clear();
	docs.clear();
}
