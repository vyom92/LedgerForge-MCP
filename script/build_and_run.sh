#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
app="${MCP_APP_DESTINATION:-$(dirname "$(dirname "$root")")/ChatGPT MCP.app}"
stage="$(mktemp -d "${TMPDIR:-/tmp}/chatgpt-mcp-app.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
bundle="$stage/ChatGPT MCP.app"
mkdir -p "$bundle/Contents/MacOS"
xcrun swiftc -swift-version 5 -O -parse-as-library -target arm64-apple-macos14.0 "$root"/native/App/*.swift "$root"/native/Services/*.swift "$root"/native/Views/*.swift -o "$bundle/Contents/MacOS/ChatGPTMCP"
mkdir -p "$stage/AppIcon.iconset" "$bundle/Contents/Resources"
for size in 16 32 128 256 512; do
    for scale in 1 2; do
        suffix=""
        if [[ "$scale" == 2 ]]; then suffix="@2x"; fi
        px=$((size * scale))
        /usr/bin/sips -z "$px" "$px" "$root/native/Resources/ChatGPTMCP.png" --out "$stage/AppIcon.iconset/icon_${size}x${size}${suffix}.png" >/dev/null
    done
done
/usr/bin/iconutil -c icns "$stage/AppIcon.iconset" -o "$bundle/Contents/Resources/AppIcon.icns"
cp "$root/native/Resources/maintenance.py" "$bundle/Contents/Resources/maintenance.py"
cp "$root/native/Info.plist" "$bundle/Contents/Info.plist"
relative="$(/usr/bin/python3 -c 'import os,sys;print(os.path.relpath(sys.argv[1],os.path.dirname(sys.argv[2])))' "${MCP_INSTALLED_ROOT:-$root}" "$app")"
/usr/bin/plutil -insert MCPInstallDirectory -string "$relative" "$bundle/Contents/Info.plist"
codesign --force --sign - --identifier local.chatgpt.mcp.control "$bundle"
codesign --verify --strict --deep "$bundle"
if [[ -e "$app" ]] && [[ "$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$app/Contents/Info.plist")" != local.chatgpt.mcp.control ]]; then
    echo "Application destination belongs to another bundle." >&2
    exit 1
fi
install_stage="$(mktemp -d "$(dirname "$app")/.mcp-native.XXXXXX")"
trap 'rm -rf "$stage" "$install_stage"' EXIT
fresh="$install_stage/ChatGPT MCP.app"
/usr/bin/ditto --norsrc --noextattr "$bundle" "$fresh"
/usr/bin/xattr -d com.apple.FinderInfo "$fresh" 2>/dev/null || true
codesign --verify --strict --deep "$fresh"
/usr/bin/python3 - "$fresh" "$app" <<'PYINSTALL'
import ctypes,os,sys
source,destination=map(os.fsencode,sys.argv[1:])
if os.path.lexists(destination):
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.renamex_np(source,destination,2):
        err=ctypes.get_errno()
        raise OSError(err,os.strerror(err))
else:
    os.rename(source,destination)
PYINSTALL
/usr/bin/xattr -d com.apple.FinderInfo "$app" 2>/dev/null || true
codesign --verify --strict --deep "$app"
if [[ "${1:-}" != "--build-only" ]]; then /usr/bin/open "$app"; fi
