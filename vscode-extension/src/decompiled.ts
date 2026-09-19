import { Decompilation, DecompVar } from './ghidra';

/** Accepts both "1009d2ad", the way Ghidra writes it, and "0x000000001009D2AD" from a debug adapter. */
export function toAddr(raw: string): bigint {
	const text = raw.trim().toLowerCase();
	return BigInt(text.startsWith('0x') ? text : `0x${text}`);
}

/** Module deltas can be negative - a module can load below its image base - and "0x-c200000" is not a number. */
export function formatAddr(address: bigint): string {
	return address < 0n ? `-0x${(-address).toString(16)}` : `0x${address.toString(16)}`;
}

interface Row {
	min?: bigint;
	max?: bigint;
}

export class DecompiledDoc {
	private constructor(
		readonly functionName: string,
		readonly entry: string,
		readonly min: bigint,
		readonly max: bigint,
		readonly text: string,
		readonly vars: DecompVar[],
		private readonly rows: Row[]
	) {}

	static fromApi(source: Decompilation): DecompiledDoc {
		const rendered: string[] = [];
		const rows: Row[] = [];

		for (const line of source.lines) {
			rendered.push(' '.repeat(line.indent) + line.text);
			rows.push({
				min: line.min ? toAddr(line.min) : undefined,
				max: line.max ? toAddr(line.max) : undefined,
			});
		}

		return new DecompiledDoc(
			source.name,
			source.entry,
			toAddr(source.min),
			toAddr(source.max),
			rendered.join('\n'),
			source.vars ?? [],
			rows
		);
	}

	/** The variable with this name - for hovering over a word in the pseudocode. */
	varNamed(name: string): DecompVar | undefined {
		return this.vars.find((variable) => variable.name === name);
	}

	/**
	 * An address can fall into a gap between line ranges, because the decompiler folds
	 * single instructions into neighbouring expressions. So when nothing matches, take
	 * the last line that starts no further than the address we are looking for.
	 */
	lineForAddress(address: bigint): number | undefined {
		let fallback: number | undefined;
		let fallbackEnd: bigint | undefined;

		for (let i = 0; i < this.rows.length; i++) {
			const { min, max } = this.rows[i];
			if (min === undefined) {
				continue;
			}
			if (min <= address && max !== undefined && address <= max) {
				return i;
			}

			// Among the lines lying entirely before the address, the winner is the one that
			// ends closest to it - not the one with the highest start. Line ranges interleave,
			// so comparing starts picks the wrong line.
			const end = max ?? min;
			if (end <= address && (fallbackEnd === undefined || end > fallbackEnd)) {
				fallbackEnd = end;
				fallback = i;
			}
		}
		return fallback;
	}

	/** The address range of one line - what "the calls of this line" is measured against. */
	rangeForLine(line: number): { min: bigint; max: bigint } | undefined {
		const row = this.rows[line];
		return row?.min === undefined ? undefined : { min: row.min, max: row.max ?? row.min };
	}

	/** Lines that have a start address of their own, in order of appearance. */
	lineStarts(): Array<{ line: number; address: bigint }> {
		const result: Array<{ line: number; address: bigint }> = [];
		this.rows.forEach((row, line) => {
			if (row.min !== undefined) {
				result.push({ line, address: row.min });
			}
		});
		return result;
	}

	/** Lines without an address of their own (braces, blanks) anchor to the nearest one below that has one. */
	addressForLine(line: number): bigint | undefined {
		for (let i = line; i < this.rows.length; i++) {
			const min = this.rows[i].min;
			if (min !== undefined) {
				return min;
			}
		}
		return undefined;
	}
}
