#!/usr/bin/env bash
# Build the Linux server, CLI client and log generator.
set -euo pipefail
cd "$(dirname "$0")/.."
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release "$@"
cmake --build build -j"$(nproc)"
echo
echo "binaries:"
ls -lh build/log_server build/log_client_cli build/loggen
