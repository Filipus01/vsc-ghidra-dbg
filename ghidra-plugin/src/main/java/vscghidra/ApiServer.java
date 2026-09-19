package vscghidra;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeWithCharset;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/** Small HTTP API on loopback. Read only - it never writes to the program. */
class ApiServer {

	private static final int DEPTH_CACHE_SIZE = 32;

	/**
	 * Frame pointer candidates, tried in this order and filtered by what the program's
	 * language actually has. A caller that knows its target better passes fp=<register>.
	 */
	private static final String[] FRAME_POINTER_NAMES =
		{ "RBP", "EBP", "BP", "FP", "X29", "R11", "R7", "S8", "R31" };

	private final PluginTool tool;
	private final int decompileTimeoutSeconds;
	private HttpServer http;
	private InetSocketAddress bound;

	/** Stack depths per function (keyed by entry point), oldest entries are evicted. */
	private final Map<Address, CallDepthChangeInfo> depthCache =
		new LinkedHashMap<>(16, 0.75f, true) {
			@Override
			protected boolean removeEldestEntry(Map.Entry<Address, CallDepthChangeInfo> eldest) {
				return size() > DEPTH_CACHE_SIZE;
			}
		};

	ApiServer(PluginTool tool, int decompileTimeoutSeconds) {
		this.tool = tool;
		this.decompileTimeoutSeconds = decompileTimeoutSeconds;
	}

	/** Binds where the caller says to - port 0 lets the OS pick one, see {@link #address()}. */
	void start(String host, int port) throws IOException {
		http = HttpServer.create(new InetSocketAddress(host, port), 0);
		http.createContext("/programs", ex -> handle(ex, this::programs));
		http.createContext("/registers", ex -> handle(ex, this::registers));
		http.createContext("/decompile", ex -> handle(ex, this::decompile));
		http.createContext("/frame", ex -> handle(ex, this::frame));
		http.createContext("/symbol", ex -> handle(ex, this::symbol));
		http.createContext("/bytes", ex -> handle(ex, this::bytes));
		http.setExecutor(null);
		http.start();
		bound = http.getAddress();
	}

	/** The address actually bound, known only after {@link #start}. */
	InetSocketAddress address() {
		return bound;
	}

	void stop() {
		if (http != null) {
			http.stop(0);
			http = null;
			bound = null;
		}
	}

	private interface Handler {
		String run(Map<String, String> query) throws Exception;
	}

	private void handle(HttpExchange exchange, Handler handler) throws IOException {
		String body;
		int code = 200;
		try {
			body = handler.run(query(exchange));
		}
		catch (Exception e) {
			code = 400;
			String message = e.getMessage() == null ? e.toString() : e.getMessage();
			body = "{\"error\":" + json(message) + "}";
		}
		byte[] payload = body.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(code, payload.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(payload);
		}
	}

	// --- endpoints ---

	private String programs(Map<String, String> query) {
		StringBuilder sb = new StringBuilder("[");
		boolean first = true;
		for (Program program : openPrograms()) {
			if (!first) {
				sb.append(',');
			}
			first = false;
			Language language = program.getLanguage();
			Register stackPointer = stackPointer(program);
			sb.append("{\"name\":").append(json(program.getName()))
				.append(",\"path\":").append(json(program.getExecutablePath()))
				.append(",\"imageBase\":").append(json(program.getImageBase().toString()))
				.append(",\"languageId\":").append(json(language.getLanguageID().getIdAsString()))
				.append(",\"processor\":").append(json(language.getProcessor().toString()))
				.append(",\"pointerSize\":").append(program.getDefaultPointerSize())
				.append(",\"bigEndian\":").append(language.isBigEndian())
				.append(",\"stackPointer\":")
				.append(stackPointer == null ? "null" : json(stackPointer.getName()))
				.append('}');
		}
		return sb.append(']').toString();
	}

	/**
	 * The processor's register model: which registers exist and how the narrow ones sit
	 * inside their parents. Debuggers report the full registers only, so this is what lets
	 * the extension cut AL out of EAX - or W0 out of X0 - without knowing any one processor.
	 */
	private String registers(Map<String, String> query) {
		Program program = findProgram(query);
		Language language = program.getLanguage();
		Register stackPointer = stackPointer(program);
		Register framePointer = framePointer(program, query.get("fp"));
		Register programCounter = language.getProgramCounter();

		StringBuilder sb = new StringBuilder("{\"stackPointer\":")
			.append(stackPointer == null ? "null" : json(stackPointer.getName()))
			.append(",\"framePointer\":")
			.append(framePointer == null ? "null" : json(framePointer.getName()))
			.append(",\"programCounter\":")
			.append(programCounter == null ? "null" : json(programCounter.getName()))
			.append(",\"pointerSize\":").append(program.getDefaultPointerSize())
			.append(",\"bigEndian\":").append(language.isBigEndian())
			.append(",\"registers\":[");

		boolean first = true;
		for (Register register : language.getRegisters()) {
			if (register.isProcessorContext() || register.isHidden()) {
				continue;
			}
			Register base = register.getBaseRegister();
			if (!first) {
				sb.append(',');
			}
			first = false;
			sb.append("{\"name\":").append(json(register.getName()))
				.append(",\"base\":").append(json(base == null ? register.getName() : base.getName()))
				.append(",\"offsetBits\":").append(register.getLeastSignificantBitInBaseRegister())
				.append(",\"bits\":").append(register.getBitLength())
				.append('}');
		}
		return sb.append("]}").toString();
	}

	private String decompile(Map<String, String> query) throws Exception {
		Program program = findProgram(query);
		Address address = parseAddress(program, query.get("addr"));
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			throw new IllegalArgumentException("no function at address " + address);
		}

		DecompInterface decompiler = new DecompInterface();
		try {
			if (!decompiler.openProgram(program)) {
				throw new IllegalStateException("the decompiler could not open the program");
			}
			DecompileResults results =
				decompiler.decompileFunction(function, decompileTimeoutSeconds, new ConsoleTaskMonitor());
			if (results == null || !results.decompileCompleted()) {
				throw new IllegalStateException(
					"decompilation failed: " + (results == null ? "no result" : results.getErrorMessage()));
			}

			StringBuilder sb = new StringBuilder();
			sb.append("{\"name\":").append(json(function.getName()))
				.append(",\"entry\":").append(json(function.getEntryPoint().toString()))
				.append(",\"min\":").append(json(function.getBody().getMinAddress().toString()))
				.append(",\"max\":").append(json(function.getBody().getMaxAddress().toString()))
				.append(",\"lines\":[");

			boolean first = true;
			for (ClangLine line : DecompilerUtils.toLines(results.getCCodeMarkup())) {
				if (!first) {
					sb.append(',');
				}
				first = false;
				appendLine(sb, line);
			}

			sb.append("],\"vars\":[");
			appendVars(sb, results.getHighFunction());
			return sb.append("]}").toString();
		}
		finally {
			decompiler.dispose();
		}
	}

	/**
	 * The text is assembled from tokens because ClangLine.toString() prefixes the line number.
	 * A line's addresses come from the range of the tokens that make it up.
	 */
	private static void appendLine(StringBuilder sb, ClangLine line) {
		StringBuilder text = new StringBuilder();
		Address min = null;
		Address max = null;
		for (ClangToken token : line.getAllTokens()) {
			text.append(token.getText());
			Address tokenMin = token.getMinAddress();
			Address tokenMax = token.getMaxAddress();
			if (tokenMin != null && (min == null || tokenMin.compareTo(min) < 0)) {
				min = tokenMin;
			}
			if (tokenMax != null && (max == null || tokenMax.compareTo(max) > 0)) {
				max = tokenMax;
			}
		}
		sb.append("{\"n\":").append(line.getLineNumber())
			.append(",\"indent\":").append(line.getIndent())
			.append(",\"text\":").append(json(text.toString()))
			.append(",\"min\":").append(min == null ? "null" : json(min.toString()))
			.append(",\"max\":").append(max == null ? "null" : json(max.toString()))
			.append('}');
	}

	/**
	 * The variables visible in the pseudocode together with where they actually live. The
	 * extension knows nothing about pcode - it gets a ready "stack+offset" or "register" and
	 * does the memory read itself, through the debugger.
	 */
	private static void appendVars(StringBuilder sb, HighFunction high) {
		if (high == null) {
			return;
		}
		boolean first = true;
		for (Iterator<HighSymbol> it = high.getLocalSymbolMap().getSymbols(); it.hasNext();) {
			if (!first) {
				sb.append(',');
			}
			first = false;
			appendVar(sb, it.next(), false);
		}
		for (Iterator<HighSymbol> it = high.getGlobalSymbolMap().getSymbols(); it.hasNext();) {
			if (!first) {
				sb.append(',');
			}
			first = false;
			appendVar(sb, it.next(), true);
		}
	}

	private static void appendVar(StringBuilder sb, HighSymbol symbol, boolean global) {
		DataType declared = symbol.getDataType();
		DataType type = baseType(declared);
		VariableStorage storage = symbol.getStorage();

		sb.append("{\"name\":").append(json(symbol.getName()))
			.append(",\"type\":").append(json(declared == null ? "?" : declared.getDisplayName()))
			.append(",\"typeClass\":").append(json(classify(type)))
			.append(",\"size\":").append(symbol.getSize())
			.append(",\"param\":").append(symbol.isParameter())
			.append(",\"global\":").append(global);

		// The storage is valid from this address on - before it the variable does not exist yet.
		Address pc = symbol.getPCAddress();
		sb.append(",\"validFrom\":")
			.append(pc == null || pc.equals(Address.NO_ADDRESS) ? "null" : json(pc.toString()));

		String kind = "other";
		if (storage == null || !storage.isValid()) {
			kind = "none";
		}
		else if (storage.isStackStorage()) {
			kind = "stack";
			sb.append(",\"offset\":").append(storage.getStackOffset());
		}
		else if (storage.isRegisterStorage()) {
			kind = "register";
			sb.append(",\"reg\":").append(json(storage.getRegister().getName()));
		}
		else if (storage.isMemoryStorage()) {
			kind = "memory";
			sb.append(",\"addr\":").append(json(storage.getMinAddress().toString()));
		}
		else if (storage.isHashStorage()) {
			kind = "hash";
		}
		else if (storage.isUniqueStorage()) {
			kind = "unique";
		}
		sb.append(",\"kind\":").append(json(kind));

		// A register holds the variable only over part of the function, so the value is approximate.
		sb.append(",\"dynamic\":").append(kind.equals("register") || kind.equals("unique") || kind.equals("hash"));

		if (type instanceof Pointer pointer) {
			DataType pointee = baseType(pointer.getDataType());
			sb.append(",\"pointee\":").append(json(pointee == null ? "void" : pointee.getDisplayName()))
				.append(",\"pointeeClass\":").append(json(classify(pointee)))
				.append(",\"pointeeSize\":").append(pointee == null ? 0 : Math.max(pointee.getLength(), 0));
		}
		sb.append('}');
	}

	/** Typedefs say nothing about representation - what matters is the type underneath. */
	private static DataType baseType(DataType type) {
		DataType current = type;
		for (int guard = 0; current instanceof TypeDef def && guard < 16; guard++) {
			current = def.getBaseDataType();
		}
		return current;
	}

	/** Coarse enough for the TypeScript side to know how to read the bytes. */
	private static String classify(DataType type) {
		if (type == null) {
			return "other";
		}
		if (type instanceof Pointer) {
			return "ptr";
		}
		if (type instanceof Enum) {
			return "enum";
		}
		if (type instanceof Structure || type instanceof Union) {
			return "struct";
		}
		if (type instanceof Array) {
			return "array";
		}
		if (type instanceof AbstractFloatDataType) {
			return "float";
		}
		if (type instanceof BooleanDataType) {
			return "bool";
		}
		// char and wchar_t are integers too, so they have to be checked before those
		if (type instanceof DataTypeWithCharset && type.getLength() >= 1 && type.getLength() <= 4) {
			return "char";
		}
		if (type instanceof AbstractIntegerDataType integer) {
			return integer.isSigned() ? "int" : "uint";
		}
		return "other";
	}

	/**
	 * Stack depth relative to the function entry, at the given PC. The extension turns this
	 * into the frame base: spEntry = framePointer - fpDepth (or stackPointer - spDepth), and
	 * a variable's address is spEntry + its offset. Which register is the frame pointer comes
	 * from the fp parameter, or from the usual names for this processor.
	 */
	private String frame(Map<String, String> query) {
		Program program = findProgram(query);
		Address pc = parseAddress(program, query.get("addr"));
		Function function = program.getFunctionManager().getFunctionContaining(pc);
		if (function == null) {
			throw new IllegalArgumentException("no function at address " + pc);
		}

		CallDepthChangeInfo depths = depthsFor(function);
		Integer sp = known(depths.getSPDepth(pc));

		Register framePointer = framePointer(program, query.get("fp"));
		Integer fp = framePointer == null ? null : known(depths.getRegDepth(pc, framePointer));

		Register stackPointer = stackPointer(program);
		return "{\"entry\":" + json(function.getEntryPoint().toString()) +
			",\"stackPointer\":" + (stackPointer == null ? "null" : json(stackPointer.getName())) +
			",\"spDepth\":" + (sp == null ? "null" : sp) +
			",\"framePointer\":" + (fp == null ? "null" : json(framePointer.getName())) +
			",\"fpDepth\":" + (fp == null ? "null" : fp) + "}";
	}

	private static Register stackPointer(Program program) {
		CompilerSpec spec = program.getCompilerSpec();
		return spec == null ? null : spec.getStackPointer();
	}

	/**
	 * The frame pointer register: the one the caller asked for, or the first of the usual
	 * names this processor actually has. The compiler spec does not name a frame pointer, so
	 * a name list is as far as guessing goes - hence the override.
	 */
	private static Register framePointer(Program program, String wanted) {
		Language language = program.getLanguage();
		if (wanted != null && !wanted.isBlank()) {
			Register asked = language.getRegister(wanted.trim());
			if (asked == null) {
				throw new IllegalArgumentException(
					"no register named " + wanted + " in " + language.getLanguageID());
			}
			return asked;
		}
		Register stackPointer = stackPointer(program);
		for (String name : FRAME_POINTER_NAMES) {
			Register candidate = language.getRegister(name);
			if (candidate != null && !candidate.equals(stackPointer)) {
				return candidate;
			}
		}
		return null;
	}

	private static Integer known(int depth) {
		return depth == Function.UNKNOWN_STACK_DEPTH_CHANGE || depth == Function.INVALID_STACK_DEPTH_CHANGE
				? null
				: depth;
	}

	/** The constructor runs symbolic propagation over the whole function - too costly per stop. */
	private CallDepthChangeInfo depthsFor(Function function) {
		Address entry = function.getEntryPoint();
		CallDepthChangeInfo cached = depthCache.get(entry);
		if (cached == null) {
			cached = new CallDepthChangeInfo(function);
			depthCache.put(entry, cached);
		}
		return cached;
	}

	private String symbol(Map<String, String> query) {
		Program program = findProgram(query);
		Address address = parseAddress(program, query.get("addr"));
		Function function = program.getFunctionManager().getFunctionContaining(address);
		Symbol primary = program.getSymbolTable().getPrimarySymbol(address);
		return "{\"address\":" + json(address.toString()) +
			",\"function\":" + (function == null ? "null" : json(function.getName())) +
			",\"entry\":" + (function == null ? "null" : json(function.getEntryPoint().toString())) +
			",\"symbol\":" + (primary == null ? "null" : json(primary.getName())) + "}";
	}

	/** For calibration: comparing these bytes with readMemory from the live process detects relocation. */
	private String bytes(Map<String, String> query) throws Exception {
		Program program = findProgram(query);
		Address address = parseAddress(program, query.get("addr"));
		int requested = Integer.parseInt(query.getOrDefault("len", "16"));
		byte[] buffer = new byte[Math.max(1, Math.min(requested, 4096))];
		int read = program.getMemory().getBytes(address, buffer);

		StringBuilder hex = new StringBuilder();
		for (int i = 0; i < read; i++) {
			hex.append(String.format("%02x", buffer[i]));
		}
		return "{\"address\":" + json(address.toString()) +
			",\"len\":" + read +
			",\"hex\":" + json(hex.toString()) + "}";
	}

	// --- helpers ---

	private Program[] openPrograms() {
		ProgramManager manager = tool.getService(ProgramManager.class);
		return manager == null ? new Program[0] : manager.getAllOpenPrograms();
	}

	/**
	 * Matching on path, not on name: a process can have two different files of the same name
	 * loaded at once - a proxy DLL next to the system one - so the name alone is ambiguous.
	 */
	private Program findProgram(Map<String, String> query) {
		Program[] all = openPrograms();
		String wanted = query.get("program");
		if (wanted == null || wanted.isBlank()) {
			if (all.length == 1) {
				return all[0];
			}
			throw new IllegalArgumentException("open programs: " + all.length + " - pass the program parameter");
		}

		String needle = normalize(wanted);
		for (Program program : all) {
			String path = normalize(program.getExecutablePath());
			if (path.equals(needle) || normalize(program.getName()).equals(needle)) {
				return program;
			}
		}
		for (Program program : all) {
			if (normalize(program.getExecutablePath()).endsWith("/" + needle)) {
				return program;
			}
		}
		throw new IllegalArgumentException("program not found: " + wanted);
	}

	/** Ghidra reports paths as /C:/..., DAP as C:\... - bring both to a common form. */
	private static String normalize(String value) {
		if (value == null) {
			return "";
		}
		String result = value.replace('\\', '/').toLowerCase();
		while (result.startsWith("/")) {
			result = result.substring(1);
		}
		return result;
	}

	/** Also accepts the padded form some debug adapters use, e.g. 0x000000001009D2AD. */
	private static Address parseAddress(Program program, String raw) {
		if (raw == null || raw.isBlank()) {
			throw new IllegalArgumentException("missing addr parameter");
		}
		String text = raw.trim().toLowerCase();
		if (text.startsWith("0x")) {
			text = text.substring(2);
		}
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseLong(text, 16));
	}

	private static Map<String, String> query(HttpExchange exchange) {
		Map<String, String> result = new HashMap<>();
		String raw = exchange.getRequestURI().getRawQuery();
		if (raw == null) {
			return result;
		}
		for (String pair : raw.split("&")) {
			int split = pair.indexOf('=');
			if (split > 0) {
				result.put(
					URLDecoder.decode(pair.substring(0, split), StandardCharsets.UTF_8),
					URLDecoder.decode(pair.substring(split + 1), StandardCharsets.UTF_8));
			}
		}
		return result;
	}

	private static String json(String value) {
		if (value == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		return sb.append('"').toString();
	}
}
