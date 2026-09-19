# Ghidra Debug Bridge for Visual Studio Code

<p align="center"><img src="assets/logo.jpg" alt="Ghidra Debug Bridge logo"></p>

Debug code you have no sources for, without leaving VS Code. Stop in a stripped function and
instead of a disassembly view you get **Ghidra's pseudocode as the editor buffer** — with
breakpoints on its lines, stepping that follows those lines, and a Locals panel filled with
values read out of the live process.

```
 ┌───────────────────────────────┬──────────────────────────────┐
 │ Renderer::DrawFrame (Ghidra)  │ Disassembly                  │
 │                               │                              │
 │  undefined4 DrawFrame(int p)  │  6e31a0b0 push ebp           │
 │  {                            │  6e31a0b1 mov  ebp,esp       │
 │►   iVar1 = GetContext(p);     │► 6e31a0b3 call GetContext    │
 │    if (iVar1 == 0) {          │  6e31a0b8 test eax,eax       │
 └───────────────────────────────┴──────────────────────────────┘
   LOCALS (GHIDRA)     param_1 = 0x1a2b3c40   iVar1 = 0 (0x0)
```

The two halves talk over HTTP on loopback:

| | |
| --- | --- |
| `ghidra-plugin/` | a Ghidra plugin serving decompilation, line-to-address mapping, variable storage, the processor's register model, symbols and bytes |
| `vscode-extension/` | the VS Code extension: it drives whatever debug adapter the session uses, finds where each module really landed in the process, and maps addresses to pseudocode lines and back |

Nothing about a particular target is compiled in. The processor, the pointer size, the byte
order, the stack and frame pointer registers all come from Ghidra, per program; the rest is
settings.

## What it gives you

- **Pseudocode instead of a black box.** A frame with no source opens as a read-only `.c`
  buffer with the current line highlighted, next to VS Code's Disassembly view — the way
  Ghidra puts the Decompiler beside the Listing.
- **Breakpoints on pseudocode lines.** `F9` in that buffer becomes an instruction breakpoint
  at the address Ghidra maps the line to, and survives a restart of the session.
- **One F11, two worlds.** The stepping keys follow the frame you are standing in, not the
  tab that happens to have the focus. In your own code, `F11` walks the line to the call and
  steps in there: into your source when that is where it leads, into Ghidra's pseudocode when
  it leads into a module without sources — and it asks which call when the line has several.
  In the pseudocode, `F10` runs to the next *pseudocode* line (temporary breakpoints on every
  other line of the function, so loops and jumps take care of themselves) and `F11`/`Shift+F11`
  step in and out by those lines.
- **Locals for a frame the debugger cannot see into.** Parameters, locals and globals as
  Ghidra names and types them, with values read from the live process, plus the same value on
  hover over any identifier in the pseudocode.
- **Relocation handled.** The runtime base of each module is found by matching its header
  against the bytes Ghidra has, so an ASLR'd or rebased module lands on the right addresses.

## Requirements

- **Ghidra** — the plugin builds against whatever installation you point it at; developed
  against 12.1.x.
- **A JDK** — only to build the plugin. The build compiles for the Java level the
  installation asks for.
- **VS Code 1.90+**, and **Node.js 18+** to build the extension.
- **A debug adapter that carries its weight.** The extension needs `modules`, `readMemory`,
  `disassemble`, `setInstructionBreakpoints` and instruction-granularity stepping over DAP.
  Developed against `cppvsdbg` (Windows, x86); adapters missing one of those will lose the
  features that rest on it.
- The binary you are debugging **open in Ghidra's CodeBrowser** — the API serves the programs
  that are open, and matches them to modules by executable path.

## Install

### 1. The Ghidra plugin

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_x.y.z_PUBLIC ghidra-plugin/build.sh
```

No Gradle: the script reads the version and the Java level out of the installation, compiles
with plain `javac` and installs into the Ghidra user profile. It honours:

| Variable | Meaning |
| --- | --- |
| `GHIDRA_INSTALL_DIR` | the installation; optional when `ghidraRun` is on `PATH` |
| `JAVA_HOME` | JDK to build with; optional, `javac` from `PATH` otherwise |
| `JAVA_TARGET_RELEASE` | `--release` to compile for; the installation decides otherwise |
| `GHIDRA_EXTENSION_DIR` | where to install; the Ghidra user settings directory otherwise |
| `SKIP_INSTALL=1` | build only |

Restart Ghidra, then enable the plugin in CodeBrowser under *File > Configure > Configure All
Plugins > VscGhidraPlugin*. The log line `VscGhidraDbg: API listening on http://...` tells you
it is up.

### 2. The VS Code extension

```bash
cd vscode-extension
npm install
npm run compile
```

Press `F5` there to run it in an Extension Development Host, or package it with
[`vsce`](https://github.com/microsoft/vscode-vsce) and install the `.vsix`. To develop against
a real project, append its path to `args` in `.vscode/launch.json` — the host opens it as the
workspace, and its `launch.json` is where the attach configuration comes from.

## Using it

1. Open the binary in Ghidra (CodeBrowser, plugin enabled) and let the analysis finish.
2. In VS Code, start your debug session. `Ctrl+Alt+P` runs the first `"request": "attach"`
   configuration of the workspace, since VS Code has no Attach action of its own.
3. Stop anywhere in code without sources — on a breakpoint, or by pressing `F11` on a line
   that calls into it. The pseudocode opens by itself, and so does the **Locals (Ghidra)**
   panel in the Debug view.
4. Set breakpoints in the pseudocode, step by its lines, hover its variables.

| Key | In your own code | In the pseudocode |
| --- | --- | --- |
| `F11` | step into the call — your source, or the pseudocode when it has none | step into, by pseudocode lines |
| `F10` | VS Code's own step over | run to the next pseudocode line |
| `Shift+F11` | VS Code's own step out | step out, by the return address on the stack |
| `F9` | VS Code's own breakpoint | instruction breakpoint at the line's address |
| `Ctrl+Alt+P` | attach to process (while not debugging) | |

Which set you get is decided by a context key the extension keeps in step with the current
frame, so switching tabs never changes what a key does. Frames the compiler left debug
information for but no source file — the runtime checks of a Debug build, say — are stepped
over rather than into, so you never land in an empty editor.

The command palette has the rest under **Ghidra Dbg**: refreshing the pseudocode after you
rename or retype something in Ghidra, rebuilding the split with the Disassembly view, the log,
and a handful of `Diag -` commands that dump what the adapter answers — the first thing to
reach for when something does not line up.

## Configuration

### Extension — `ghidraDbg.*` in VS Code settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `apiUrl` | `http://127.0.0.1:18000` | where the Ghidra plugin listens |
| `requestTimeoutMs` | `30000` | how long to wait for Ghidra |
| `framePointerRegister` | *(empty)* | frame pointer of the target processor; empty means Ghidra guesses from the usual names |
| `splitDisassembly` | `true` | pseudocode and the Disassembly view side by side |
| `attachConfiguration` | *(empty)* | which attach configuration `Ctrl+Alt+P` starts |
| `modules.baseAlignment` | `65536` | boundary a module can load on — `4096` for page-aligned images |
| `modules.baseScanLimit` | `1024` | how far back to look for a module's base |
| `stepping.*` | | step ceilings and the timeouts of one step |
| `values.*` | | how much memory a variable, a string or a frame may be read with |
| `disassembly.callPattern` | x86/ARM/MIPS mnemonics | what a call looks like in the adapter's disassembly |
| `disassembly.returnPattern` | `ret`, `bx lr`, `jr $ra` | where the search for the calls of a line stops |
| `disassembly.skipCallPattern` | MSVC helpers | calls left out of *step into which call?* |
| `disassembly.namedCallPattern` | MASM syntax | how to read a name and a target address out of a call the disassembler already resolved |

The `disassembly.*` patterns are case-insensitive regular expressions matched against the text
the debug adapter prints. They are the one place a different processor or toolchain usually
needs a word: the defaults follow x86 and MSVC, because that is what `cppvsdbg` prints. Mind
the mnemonics that are both — `blr` returns on PowerPC and calls on AArch64.

### Plugin — *Edit > Tool Options > VS Code Debug Bridge*

| Option | Default | Meaning |
| --- | --- | --- |
| Listen address | `127.0.0.1` | anything wider hands everything the API can read to the network |
| Listen port | `18000` | `0` lets the OS pick one — the Ghidra log says which |
| Decompile timeout (seconds) | `60` | per function |

The defaults themselves can be moved with `VSC_GHIDRA_DBG_HOST`, `VSC_GHIDRA_DBG_PORT` and
`VSC_GHIDRA_DBG_DECOMPILE_TIMEOUT`, or the `-Dvscghidra.host`, `-Dvscghidra.port`,
`-Dvscghidra.decompileTimeout` system properties — which is what a scripted setup uses.

## How it works

1. The debug session reports a frame without sources. Its module path is matched against the
   programs open in Ghidra.
2. Ghidra's image base and the bytes of the module header are compared against the live
   process, walking back along `modules.baseAlignment` boundaries, until the runtime base is
   found — which is what makes a relocated module work.
3. The function is decompiled, and every line keeps the address range Ghidra gives it. That
   mapping is what breakpoints, stepping and the current-line highlight all use.
4. Values come from the frame base, in order of how much each source can be trusted: the frame
   pointer when Ghidra knows its depth, otherwise the return address found on the live stack,
   otherwise Ghidra's own stack depth. Each variable is then read from memory or cut out of
   the register it lives in.

### The HTTP API

Read-only, loopback by default; it never writes to the program. Useful on its own if you want
to drive Ghidra from something else.

| Endpoint | Gives you |
| --- | --- |
| `GET /programs` | open programs: path, image base, language, pointer size, byte order, stack pointer |
| `GET /decompile?program=&addr=` | pseudocode lines with their address ranges, plus every variable's storage |
| `GET /frame?program=&addr=[&fp=]` | stack and frame pointer depths relative to the function entry |
| `GET /registers?program=[&fp=]` | the processor's register model: which registers exist, and how narrow ones sit in their parents |
| `GET /symbol?program=&addr=` | function and symbol at an address |
| `GET /bytes?program=&addr=&len=` | bytes from the program image |

## Limitations

- Early days: version `0.0.1`, developed against one setup (Windows, x86, `cppvsdbg`). The
  Ghidra side is processor-agnostic by construction, but only x86 has been exercised.
- Processors that return through a link register (ARM, and others) have no return address on
  the stack, so the frame base falls back to what Ghidra's analysis says.
- Values are only as good as Ghidra's analysis. A variable held in a register over part of a
  function is marked approximate (`≈`), and the panel says why when a value cannot be trusted.
- Editing the pseudocode does nothing — it is a view of Ghidra, and rename or retype there,
  then run *Ghidra Dbg: Refresh pseudocode from Ghidra*.
- The API is read-only but unauthenticated: leave it on loopback unless you know exactly what
  the machine it runs on is exposed to.

## Repository layout

```
ghidra-plugin/      the Ghidra side: HTTP API, decompilation, line mapping, register model
  build.sh          Gradle-free build and install
vscode-extension/   the VS Code side
  src/extension.ts  session tracking, pseudocode documents, breakpoints, stepping
  src/values.ts     frame base, register reads, variable values
  src/ghidra.ts     the API client
  src/config.ts     every setting, in one place
```
