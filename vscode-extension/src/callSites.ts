import * as vscode from 'vscode';

import * as config from './config';
import { formatAddr, toAddr } from './decompiled';

/** One `call` instruction of the current line - a candidate for "step into which call?". */
export interface CallSite {
	address: bigint;
	/** the instruction as the debugger's disassembler prints it */
	text: string;
	label: string;
	detail?: string;
}

export interface DapInstruction {
	address: string;
	instruction: string;
	symbol?: string;
	line?: number;
	location?: { name?: string; path?: string };
}

/** Resolves a call target to a name when the debugger has no symbol for it. */
export type TargetResolver = (address: bigint) => Promise<string | undefined>;

export async function disassemble(
	session: vscode.DebugSession,
	start: bigint,
	count: number
): Promise<DapInstruction[]> {
	try {
		const response = await session.customRequest('disassemble', {
			memoryReference: formatAddr(start),
			instructionOffset: 0,
			instructionCount: count,
			resolveSymbols: true,
		});
		return (response?.instructions ?? []) as DapInstruction[];
	}
	catch {
		return [];
	}
}

/**
 * Some debuggers print the target's name right in the instruction, both for a direct call,
 * `call __RTC_CheckEsp (6E439A34h)`, and for one through the import table,
 * `call dword ptr [__imp_Some::Method (6EBF8828h)]`. What that looks like is the disassembler's
 * business, so the pattern is a setting (ghidraDbg.disassembly.namedCallPattern); `__imp_` is
 * noise the linker adds.
 */
function nameFromText(text: string): string | undefined {
	const name = text.match(config.disassembly.namedCallPattern())?.[1]?.replace(/^__imp_/, '');
	return name && /[A-Za-z_?$@]/.test(name) ? name : undefined;
}

/** `call 6E31A0B0h` and `call 0x6e31a0b0` have a target; `call dword ptr [eax+78h]` does not. */
function directTarget(text: string): bigint | undefined {
	if (text.includes('[')) {
		return undefined; // through a pointer - the target is only known once we are there
	}
	const hex = text.match(/\b0x([0-9a-fA-F]+)\b/) ?? text.match(/\b([0-9a-fA-F]{4,16})h\b/);
	try {
		return hex ? toAddr(`0x${hex[1]}`) : undefined;
	}
	catch {
		return undefined;
	}
}

/**
 * The calls of one line, in execution order. `sameLine` decides how far the line reaches -
 * for code with sources by the line numbers the debugger reports, for pseudocode by the
 * address range Ghidra gives us.
 */
export async function callsOnLine(
	session: vscode.DebugSession,
	start: bigint,
	sameLine: (instruction: DapInstruction, index: number) => boolean,
	resolve?: TargetResolver
): Promise<CallSite[]> {
	const instructions = await disassemble(session, start, config.disassembly.maxLineInstructions());
	const isCall = config.disassembly.callPattern();
	const isReturn = config.disassembly.returnPattern();
	const sites: CallSite[] = [];

	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (!sameLine(instruction, i)) {
			break;
		}
		const text = (instruction.instruction ?? '').trim();
		if (isReturn.test(text)) {
			break; // past the end of the function, whatever the line info says
		}
		if (!isCall.test(text)) {
			continue;
		}
		sites.push({
			address: toAddr(instruction.address),
			text,
			label: text,
		});
	}

	await Promise.all(sites.map((site) => describe(session, site, resolve)));
	// Helpers the toolchain wraps around calls of its own are not in anybody's source, and
	// stepping skips them anyway - which ones those are is a setting.
	const skip = config.disassembly.skipCallPattern();
	return sites.filter((site) => !skip.test(site.label));
}

/**
 * A bare `call 6E31A0B0h` says nothing about what you are stepping into, so we ask the
 * debugger what sits at the target, and Ghidra when the debugger has no symbols there.
 */
async function describe(
	session: vscode.DebugSession,
	site: CallSite,
	resolve?: TargetResolver
): Promise<void> {
	const named = nameFromText(site.text);
	if (named) {
		site.label = named;
		site.detail = formatAddr(site.address);
		return;
	}

	const target = directTarget(site.text);
	if (target === undefined) {
		site.label = site.text;
		site.detail = 'indirect call - the target is only known at this point';
		return;
	}

	const [instruction] = await disassemble(session, target, 1);
	const where = instruction?.location?.name;
	const line = instruction?.line;
	if (instruction?.symbol) {
		site.label = instruction.symbol;
		site.detail = where ? `${where}:${line ?? '?'}` : formatAddr(target);
		return;
	}

	const name = await resolve?.(target);
	site.label = name ?? `${formatAddr(target)}`;
	site.detail = name ? `${formatAddr(target)} (Ghidra)` : site.text;
}

export async function pickCallSite(sites: CallSite[]): Promise<CallSite | undefined> {
	const picked = await vscode.window.showQuickPick(
		sites.map((site, index) => ({
			label: `${index + 1}. ${site.label}`,
			description: site.detail,
			detail: site.text,
			site,
		})),
		{ title: 'Step into which call?', matchOnDescription: true }
	);
	return picked?.site;
}
