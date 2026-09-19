package vscghidra;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ghidra.framework.main.UtilityPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "VS Code debug bridge",
	description = "Serves decompilation with line-to-address mapping, variable storage, the " +
		"register model, symbols and bytes over HTTP, so a debugger front end can show " +
		"pseudocode for code it has no sources for."
)
public class VscGhidraPlugin extends Plugin implements OptionsChangeListener {

	static final String OPTIONS_NAME = "VS Code Debug Bridge";
	static final String HOST_OPTION = "Listen address";
	static final String PORT_OPTION = "Listen port";
	static final String TIMEOUT_OPTION = "Decompile timeout (seconds)";

	/**
	 * Defaults for the tool options. Reading them from the environment as well lets a scripted
	 * or headless setup move the bridge without touching the UI; once saved in the tool, the
	 * option wins.
	 */
	private static final String DEFAULT_HOST = setting("VSC_GHIDRA_DBG_HOST", "vscghidra.host", "127.0.0.1");
	private static final int DEFAULT_PORT =
		number(setting("VSC_GHIDRA_DBG_PORT", "vscghidra.port", null), 18000);
	private static final int DEFAULT_TIMEOUT =
		number(setting("VSC_GHIDRA_DBG_DECOMPILE_TIMEOUT", "vscghidra.decompileTimeout", null), 60);

	private ApiServer server;

	public VscGhidraPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		ToolOptions options = tool.getOptions(OPTIONS_NAME);
		options.registerOption(HOST_OPTION, DEFAULT_HOST, null,
			"Address the HTTP API binds to. 127.0.0.1 keeps it on this machine; anything wider " +
				"hands everything the API can read to the network.");
		options.registerOption(PORT_OPTION, DEFAULT_PORT, null,
			"Port the HTTP API listens on - the client's API URL has to point at it.");
		options.registerOption(TIMEOUT_OPTION, DEFAULT_TIMEOUT, null,
			"How long one decompilation may take before it is given up on.");
		options.addOptionsChangeListener(this);
		restart(options);
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		if (OPTIONS_NAME.equals(options.getName())) {
			restart(options);
		}
	}

	private void restart(ToolOptions options) {
		stopServer();
		String host = options.getString(HOST_OPTION, DEFAULT_HOST);
		int port = options.getInt(PORT_OPTION, DEFAULT_PORT);
		int timeout = options.getInt(TIMEOUT_OPTION, DEFAULT_TIMEOUT);
		try {
			server = new ApiServer(tool, timeout);
			server.start(host, port);
			Msg.info(this, "VscGhidraDbg: API listening on http://" + host + ":" +
				server.address().getPort());
		}
		catch (Exception e) {
			server = null;
			Msg.error(this, "VscGhidraDbg: could not listen on " + host + ":" + port +
				" - change it under Edit > Tool Options > " + OPTIONS_NAME, e);
		}
	}

	private void stopServer() {
		if (server != null) {
			server.stop();
			server = null;
		}
	}

	@Override
	protected void dispose() {
		tool.getOptions(OPTIONS_NAME).removeOptionsChangeListener(this);
		stopServer();
	}

	/** An environment variable, or a -D system property, or nothing. */
	private static String setting(String variable, String property, String fallback) {
		String value = System.getenv(variable);
		if (value == null || value.isBlank()) {
			value = System.getProperty(property);
		}
		return value == null || value.isBlank() ? fallback : value.trim();
	}

	private static int number(String value, int fallback) {
		try {
			return value == null ? fallback : Integer.parseInt(value);
		}
		catch (NumberFormatException e) {
			Msg.warn(VscGhidraPlugin.class, "VscGhidraDbg: not a number: " + value);
			return fallback;
		}
	}
}
