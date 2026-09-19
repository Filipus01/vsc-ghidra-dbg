import * as vscode from 'vscode';

import { formatAddr } from './decompiled';
import { FrameContext, ResolvedVar, clearFrameCaches, computeValues } from './values';

type Node = GroupNode | VarNode | InfoNode;

interface GroupNode {
	kind: 'group';
	label: string;
	children: ResolvedVar[];
}

interface VarNode {
	kind: 'var';
	value: ResolvedVar;
}

interface InfoNode {
	kind: 'info';
	text: string;
}

const IDLE = 'Stop in a function without sources to see its variables.';

/**
 * Our own equivalent of Variables > Locals. The built-in panel cannot be fed from outside -
 * its content comes solely from the debug adapter's responses, and VS Code does not let an
 * extension add a scope to someone else's session.
 */
export class LocalsProvider implements vscode.TreeDataProvider<Node> {
	private readonly changed = new vscode.EventEmitter<Node | undefined>();
	readonly onDidChangeTreeData = this.changed.event;

	private frame: FrameContext | undefined;
	private values: ResolvedVar[] | undefined;
	private message = IDLE;

	constructor(
		private readonly log: (message: string) => void,
		/** true while a step of ours is in flight - see ensureValues */
		private readonly busy: () => boolean
	) {}

	/** The frame changed (another stop, or a click in the call stack). */
	setFrame(frame: FrameContext): void {
		this.frame = frame;
		this.values = undefined;
		// frame ids can repeat between stops, so the register cache is not to be trusted
		clearFrameCaches();
		this.changed.fire(undefined);
	}

	/** No frame with pseudocode - either code with sources, or the session moved on. */
	clear(message = IDLE): void {
		this.frame = undefined;
		this.values = undefined;
		this.message = message;
		this.changed.fire(undefined);
	}

	/** The values went stale, but the frame stays the same. */
	invalidate(): void {
		this.values = undefined;
		clearFrameCaches();
		this.changed.fire(undefined);
	}

	/** The value for a hover in the pseudocode - the same one the tree shows. */
	async valueOf(name: string): Promise<ResolvedVar | undefined> {
		const values = await this.ensureValues();
		return values?.find((entry) => entry.variable.name === name);
	}

	currentFrame(): FrameContext | undefined {
		return this.frame;
	}

	getTreeItem(node: Node): vscode.TreeItem {
		if (node.kind === 'info') {
			return new vscode.TreeItem(node.text, vscode.TreeItemCollapsibleState.None);
		}
		if (node.kind === 'group') {
			const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.Expanded);
			item.description = String(node.children.length);
			return item;
		}
		return variableItem(node.value);
	}

	async getChildren(node?: Node): Promise<Node[]> {
		if (node?.kind === 'group') {
			return node.children.map((value) => ({ kind: 'var', value }));
		}
		if (node) {
			return [];
		}

		if (!this.frame) {
			return [{ kind: 'info', text: this.message }];
		}
		const values = await this.ensureValues();
		if (!values) {
			return [{ kind: 'info', text: this.message }];
		}
		if (values.length === 0) {
			return [{ kind: 'info', text: 'Ghidra sees no variables in this function.' }];
		}

		const groups: GroupNode[] = [
			{ kind: 'group', label: 'Parameters', children: values.filter((v) => v.variable.param) },
			{
				kind: 'group',
				label: 'Locals',
				children: values.filter((v) => !v.variable.param && !v.variable.global),
			},
			{ kind: 'group', label: 'Globals', children: values.filter((v) => v.variable.global) },
		];
		return groups.filter((group) => group.children.length > 0);
	}

	private async ensureValues(): Promise<ResolvedVar[] | undefined> {
		if (!this.frame) {
			return undefined;
		}
		if (this.values) {
			return this.values;
		}
		// Mid-step the frame we hold is already gone: the scopes request then fails with
		// "error processing scopes", we get no registers and every value reads as garbage.
		// The values are recomputed once the step settles and sets the frame anew.
		if (this.busy()) {
			this.message = 'Stepping...';
			return undefined;
		}
		try {
			this.values = await computeValues(this.frame, this.log);
			return this.values;
		}
		catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			this.message = `Could not compute the values: ${reason}`;
			this.log(`locals: ${reason}`);
			return undefined;
		}
	}
}

function variableItem(entry: ResolvedVar): vscode.TreeItem {
	const item = new vscode.TreeItem(entry.variable.name, vscode.TreeItemCollapsibleState.None);
	item.description = `${entry.approximate ? '≈ ' : ''}${entry.value}`;
	item.iconPath = new vscode.ThemeIcon(entry.variable.global ? 'symbol-field' : 'symbol-variable');
	item.tooltip = tooltip(entry);
	item.contextValue = 'ghidraLocal';
	return item;
}

function tooltip(entry: ResolvedVar): vscode.MarkdownString {
	const lines = [
		`\`${entry.variable.type} ${entry.variable.name}\``,
		'',
		`value: \`${entry.value}\``,
		`storage: \`${entry.location}\``,
	];
	if (entry.address !== undefined) {
		lines.push(`address: \`${formatAddr(entry.address)}\``);
	}
	if (entry.frameBase !== undefined) {
		lines.push(
			`frame base: \`${formatAddr(entry.frameBase)}\`` +
				(entry.frameBaseSource ? ` (${entry.frameBaseSource})` : '')
		);
	}
	if (entry.raw) {
		lines.push(`bytes there: \`${entry.raw}\``);
	}
	if (entry.note) {
		lines.push('', `_${entry.note}_`);
	}
	return new vscode.MarkdownString(lines.join('\n'));
}
