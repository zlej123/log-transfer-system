#!/usr/bin/env bash
# Cross-compile the Windows GUI client (.exe) from Linux using zig cc.
#   requires: `zig` on PATH, or a python with `pip install ziglang`
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v zig >/dev/null 2>&1; then
  ZIG=(zig)
elif python3 -c "import ziglang" >/dev/null 2>&1; then
  ZIG=(python3 -m ziglang)
elif [ -n "${ZIG_PY:-}" ]; then
  ZIG=("$ZIG_PY" -m ziglang)
else
  echo "zig not found (install zig or: pip install ziglang)" >&2
  exit 1
fi

IMGUI=third_party/imgui
OUT=dist/windows
mkdir -p "$OUT"

"${ZIG[@]}" c++ -target x86_64-windows-gnu -std=c++17 -O2 \
  -DUNICODE -D_UNICODE \
  -I "$IMGUI" -I "$IMGUI/backends" \
  client/gui/main.cpp \
  "$IMGUI/imgui.cpp" \
  "$IMGUI/imgui_draw.cpp" \
  "$IMGUI/imgui_tables.cpp" \
  "$IMGUI/imgui_widgets.cpp" \
  "$IMGUI/backends/imgui_impl_win32.cpp" \
  "$IMGUI/backends/imgui_impl_dx11.cpp" \
  -lws2_32 -ld3d11 -ld3dcompiler_47 -ldxguid -ldwmapi -lgdi32 \
  -lcomdlg32 -lole32 -luuid -lshell32 -luser32 \
  -municode -mwindows -Wl,--subsystem,windows \
  -o "$OUT/log_client_gui.exe"

echo "built: $OUT/log_client_gui.exe"
ls -lh "$OUT/log_client_gui.exe"
