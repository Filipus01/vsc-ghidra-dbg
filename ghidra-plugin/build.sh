#!/usr/bin/env bash
# Builds the Ghidra extension without Gradle - plain javac + jar - and installs it into the
# Ghidra user profile. Nothing about any one machine is baked in: the installation tells us
# its version and the Java level it wants, and the rest comes from the environment.
#
#   GHIDRA_INSTALL_DIR    the Ghidra installation (the directory holding Ghidra/ and ghidraRun)
#                         - optional when ghidraRun is on PATH
#   JAVA_HOME             JDK to build with - optional, javac from PATH otherwise
#   JAVA_TARGET_RELEASE   --release to compile for - optional, the installation says otherwise
#   GHIDRA_EXTENSION_DIR  where to install - optional, the Ghidra user settings dir otherwise
#   SKIP_INSTALL=1        build only, do not install
set -euo pipefail

NAME=VscGhidraDbg

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

case "$(uname -s)" in
	MINGW*|MSYS*|CYGWIN*) windows=1; classpath_separator=';' ;;
	*) windows=0; classpath_separator=':' ;;
esac

# --- the Ghidra installation ---

ghidra="${GHIDRA_INSTALL_DIR:-}"
if [ -z "$ghidra" ] && command -v ghidraRun >/dev/null 2>&1; then
	ghidra="$(cd "$(dirname "$(command -v ghidraRun)")" && pwd)"
fi
if [ -z "$ghidra" ] || [ ! -d "$ghidra/Ghidra" ]; then
	echo "Ghidra installation not found${ghidra:+: $ghidra}." >&2
	echo "Set GHIDRA_INSTALL_DIR to the directory holding Ghidra/ and ghidraRun." >&2
	exit 1
fi

properties="$ghidra/Ghidra/application.properties"
[ -f "$properties" ] || { echo "not a Ghidra installation - no $properties" >&2; exit 1; }
property() { sed -n "s/^$1=//p" "$properties" | tr -d '\r' | head -1; }

version="$(property application.version)"
release="$(property application.release.name)"
# Ghidra runs on one specific Java level - compile for that one, whatever JDK we have here.
target_release="${JAVA_TARGET_RELEASE:-$(property application.java.compiler)}"
[ -n "$version" ] || { echo "no application.version in $properties" >&2; exit 1; }
release="${release:-PUBLIC}"
target_release="${target_release:-$(property application.java.min)}"
[ -n "$target_release" ] || { echo "no Java level in $properties - set JAVA_TARGET_RELEASE" >&2; exit 1; }

# --- the JDK ---

javac=""
jar=""
if [ -n "${JAVA_HOME:-}" ]; then
	for candidate in "$JAVA_HOME/bin/javac" "$JAVA_HOME/bin/javac.exe"; do
		if [ -x "$candidate" ]; then
			javac="$candidate"
			jar="${candidate%javac*}jar"
			break
		fi
	done
	[ -n "$javac" ] || { echo "no javac in JAVA_HOME: $JAVA_HOME" >&2; exit 1; }
elif command -v javac >/dev/null 2>&1; then
	javac="javac"
	jar="jar"
else
	echo "javac not found - set JAVA_HOME to a JDK $target_release or newer" >&2
	exit 1
fi

# --- build ---

classpath=""
for dir in "$ghidra"/Ghidra/Framework/*/lib "$ghidra"/Ghidra/Features/*/lib; do
	[ -d "$dir" ] && classpath="${classpath:+$classpath$classpath_separator}$dir/*"
done

rm -rf build
mkdir -p build/classes "build/$NAME/lib"

echo "[1/3] javac (Ghidra $version $release, release $target_release)"
"$javac" \
	--release "$target_release" \
	-nowarn \
	-classpath "$classpath" \
	-d build/classes \
	$(find src -name '*.java')

echo "[2/3] jar"
"$jar" --create --file "build/$NAME/lib/$NAME.jar" -C build/classes .

# Ghidra refuses an extension whose version does not match its own, so the file is generated
# rather than kept in the repository with one installation's version frozen into it.
sed "s/@GHIDRA_VERSION@/$version/" extension.properties.in > "build/$NAME/extension.properties"
cp Module.manifest "build/$NAME/"

if [ "${SKIP_INSTALL:-0}" = "1" ]; then
	echo
	echo "Built in: $here/build/$NAME (SKIP_INSTALL=1, not installed)"
	exit 0
fi

# --- install ---

echo "[3/3] install"
extensions="${GHIDRA_EXTENSION_DIR:-}"
if [ -z "$extensions" ]; then
	# Where Ghidra keeps per-user settings differs per platform, and it has moved between
	# releases - so take the first candidate that already exists, and only then guess.
	candidates=()
	if [ "$windows" = "1" ]; then
		candidates+=("$(printf '%s' "${APPDATA:-$HOME/AppData/Roaming}" | tr '\\' '/')/ghidra")
	else
		candidates+=("${XDG_CONFIG_HOME:-$HOME/.config}/ghidra" "$HOME/Library/ghidra" "$HOME/.ghidra")
	fi
	for root in "${candidates[@]}"; do
		if [ -d "$root/ghidra_${version}_${release}" ]; then
			extensions="$root/ghidra_${version}_${release}/Extensions"
			break
		fi
	done
	extensions="${extensions:-${candidates[0]}/ghidra_${version}_${release}/Extensions}"
fi

target="$extensions/$NAME"
mkdir -p "$extensions"
if ! rm -rf "$target" 2>/dev/null; then
	echo
	echo "Cannot overwrite: $target"
	echo "A running Ghidra holds the jar open - close it and run build.sh again."
	exit 1
fi
cp -r "build/$NAME" "$target"

echo
echo "Installed in: $target"
echo "Restart Ghidra, then in CodeBrowser: File > Configure > Configure All Plugins > VscGhidraPlugin"
echo "The listen address and port live under Edit > Tool Options > VS Code Debug Bridge."
