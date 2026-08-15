#!/usr/bin/env bash
# Cross-compile the mTLS Windows GUI and CLI clients with zig + CMake.
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v zig >/dev/null 2>&1; then
  ZIG_MODE=direct
  ZIG_BIN=$(command -v zig)
elif [ -n "${ZIG_PY:-}" ] && "$ZIG_PY" -c 'import ziglang' >/dev/null 2>&1; then
  ZIG_MODE=python
  ZIG_BIN=$ZIG_PY
elif python3 -c 'import ziglang' >/dev/null 2>&1; then
  ZIG_MODE=python
  ZIG_BIN=$(command -v python3)
else
  echo "zig not found (install zig or: pip install ziglang)" >&2
  exit 1
fi

WRAP=$(pwd)/build-windows-zig/wrappers
mkdir -p "$WRAP" dist/windows
if [ "$ZIG_MODE" = direct ]; then
  cat > "$WRAP/cc" <<EOF
#!/usr/bin/env bash
exec "$ZIG_BIN" cc -target x86_64-windows-gnu "\$@"
EOF
  cat > "$WRAP/cxx" <<EOF
#!/usr/bin/env bash
exec "$ZIG_BIN" c++ -target x86_64-windows-gnu "\$@"
EOF
else
  cat > "$WRAP/cc" <<EOF
#!/usr/bin/env bash
exec "$ZIG_BIN" -m ziglang cc -target x86_64-windows-gnu "\$@"
EOF
  cat > "$WRAP/cxx" <<EOF
#!/usr/bin/env bash
exec "$ZIG_BIN" -m ziglang c++ -target x86_64-windows-gnu "\$@"
EOF
fi
chmod +x "$WRAP/cc" "$WRAP/cxx"
export LGX_ZIG_CC="$WRAP/cc"
export LGX_ZIG_CXX="$WRAP/cxx"

cmake -S . -B build-windows-zig \
  -DCMAKE_TOOLCHAIN_FILE=scripts/zig-windows-toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows-zig --target log_client_gui log_client_cli -j"$(nproc)"
cp build-windows-zig/log_client_gui.exe dist/windows/
cp build-windows-zig/log_client_cli.exe dist/windows/

echo "built TLS clients:"
ls -lh dist/windows/log_client_gui.exe dist/windows/log_client_cli.exe
