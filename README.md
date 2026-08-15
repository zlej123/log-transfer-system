# Large Log Analysis & Transfer System

[![CI](https://github.com/zlej123/log-transfer-system/actions/workflows/ci.yml/badge.svg)](https://github.com/zlej123/log-transfer-system/actions/workflows/ci.yml)

A cross-platform client-server system that uploads a large (~500 MB) virtual
device log file from a **Windows client** to a **Linux server** over raw
TCP/IP, parses and analyzes it **while it is being received** (streaming),
and returns the aggregated statistics back to the client as `result.csv`.

| Component | Tech |
|---|---|
| Server (Linux) | C++17, Berkeley sockets, thread-per-connection, daemon mode |
| GUI Client (Windows) | C++17, Dear ImGui (Win32 + DirectX 11), worker-thread async I/O |
| CLI Client (Linux/Windows) | C++17, same transfer engine as the GUI (used for automated E2E tests) |
| Test log generator | C++17, deterministic, injects ~0.001% poisoned lines |

---

## 1. Repository layout

```
common/protocol.hpp        shared wire-protocol framing (header-only)
server/main.cpp            TCP daemon: accept loop, connection handling
server/net.hpp             RAII socket + robust send_all/recv_all helpers
server/parser.{hpp,cpp}    streaming LogAnalyzer (Task1/Task2 + poison handling)
client/core/transfer.hpp   cross-platform worker-thread transfer engine
client/gui/main.cpp        Dear ImGui Win32/DX11 GUI client
client/cli/main.cpp        headless CLI client (testing / automation)
tools/loggen.cpp           500 MB test-log generator (0.001% corrupted lines)
tests/test_parser.cpp      dependency-free unit tests for the streaming parser
tests/run_e2e.sh           automated end-to-end + robustness test script
scripts/build_linux.sh     builds server + CLI client + loggen
scripts/build_windows_client.sh   cross-compiles the Windows GUI .exe with zig
third_party/imgui/         vendored Dear ImGui (unmodified)
dist/                      pre-built binaries (Linux + Windows)
```

## 2. Build instructions

### 2.1 Linux (server, CLI client, log generator)

Requirements: `g++` >= 9 (C++17), `cmake` >= 3.16.

```bash
./scripts/build_linux.sh
# or manually:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Produces `build/log_server`, `build/log_client_cli`, `build/loggen`.

Optional sanitizer build (used for the leak-free verification):

```bash
cmake -S . -B build-asan -DENABLE_ASAN=ON && cmake --build build-asan -j
```

### 2.2 Windows GUI client

**Option A - cross-compile from Linux (how `dist/windows/*.exe` was built):**

```bash
# zig on PATH, or: pip install ziglang
./scripts/build_windows_client.sh
# -> dist/windows/log_client_gui.exe  (PE32+ GUI, statically linked, no DLLs needed)
```

**Option B - native build on Windows (Visual Studio 2019+):**

```bat
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release --target log_client_gui
```

## 3. Running

```bash
# server (foreground)
./build/log_server --port 45777 --workdir server_work
# server (background daemon: double-fork + setsid, logs to workdir/server.log,
#         pid written to workdir/server.pid)
./build/log_server --port 45777 --workdir server_work --daemon

# generate the 500 MB test log (contains ~0.001% intentionally corrupt lines)
./build/loggen --out test_log_500mb.log --size-mb 500

# CLI client
./build/log_client_cli <server-ip> 45777 test_log_500mb.log result.csv
```

GUI client: run `log_client_gui.exe`, enter the server IP/port, **Select Log
File...**, **Upload & Analyze** (live progress bars), then **Download Result
(Save As...)** when finished.

## 4. Network architecture

```
 Windows client                                Linux server (daemon)
 ┌───────────────────────────┐                 ┌──────────────────────────────┐
 │ UI thread (Dear ImGui)    │                 │ accept() loop (main thread)  │
 │   reads atomic counters   │                 │        │ one thread per conn │
 │        ▲                  │    TCP/IP       │        ▼                     │
 │ worker std::thread ───────┼────────────────►│ recv 64 KiB chunk ──┐        │
 │   64 KiB file chunks      │                 │      ▲              ▼        │
 │   progress -> atomics     │◄────────────────┼── send result.csv  LogAnalyzer│
 └───────────────────────────┘                 └──────────────────── (streaming)┘
```

* **Framing** - a fixed 16-byte little-endian header
  `[magic 'LGX1'][cmd][flags][name_len][payload_size]` followed by the file
  name and the raw payload stream. The response reuses the same frame with
  `cmd = RESULT_CSV`. Every header field is validated (magic, command range,
  name/payload size caps) before any allocation-affecting action.
* **Asynchronous client I/O** - the transfer runs entirely on a worker
  `std::thread`; the UI thread only reads `std::atomic` progress counters,
  so the window stays responsive during the whole 500 MB upload/download.
* **Cancellable connect with timeout** - the client connects in
  non-blocking mode and polls in 100 ms slices (10 s cap), so an
  unreachable server can neither hang the worker for minutes nor block the
  Cancel button.
* **Server concurrency** - accept loop + one detached worker thread per
  connection; every socket is an RAII object, and a per-connection guard
  keeps an active-connection count for graceful shutdown (SIGTERM/SIGINT).

## 5. Memory optimization strategy

The server **never** holds the file in memory:

1. Bytes are received into a single reusable **64 KiB chunk buffer**
   (`std::vector<char>`, allocated once per connection).
2. Each chunk is fed straight into the incremental `LogAnalyzer`, which only
   keeps a partial-line carry (`std::string`) between chunks.
3. Only bounded aggregates survive: `(module, hour) -> count` hash map,
   speed sum/count/min/max, line counters, and at most 200 malformed-line
   samples.
4. Hostile input cannot grow memory: lines longer than **64 KiB** are
   discarded in-flight without buffering, and the aggregate table is hard
   capped (`kMaxBucketEntries`), so even a file full of garbage keeps the
   footprint constant.

**Measured**: peak RSS (`VmHWM`) of the server while receiving + parsing the
real 500 MB file is **~4.2 MB** - well under the 50 MB recommendation.
The full receive-and-parse pass completes in ~0.6 s on the test machine.

## 6. Poisoned-data (exception) handling algorithm

The provided log contains ~0.001% deliberately corrupted lines. Parsing is a
hand-written validating scanner (no exceptions on the hot path, no regex):

1. **Strict positional timestamp check** - `[YYYY-MM-DD HH:MM:SS.mmm]` with
   per-character digit/separator validation plus range checks
   (month 1-12, hour 0-23, ...). Catches missing brackets, truncated or
   garbage timestamps.
2. **Bracket token scanner** for `[LEVEL]` and `[Module]` with charset and
   length limits - catches missing `]`, binary garbage, oversized tokens.
3. **Speed extraction** with `std::from_chars` (locale-free, non-throwing):
   requires `spd = <number>` / `spd: <number>`, rejects trailing junk
   (`spd=12.3x`), non-finite values (`NaN`, `inf`) and absurd magnitudes.
   A line that contains `spd` but no parsable value is treated as corrupt.
4. Any failed stage -> the line is **counted, sampled (first 200, control
   characters hex-escaped) into `workdir/parse_errors.log`, skipped**, and
   parsing continues to the end of the stream. A `catch`-all around each
   connection guarantees one bad stream can never bring the daemon down.
5. Structural safety nets: 64 KiB max line length (over-long lines are
   streamed to /dev/null, not buffered), capped aggregate tables, CRLF and
   missing-final-newline tolerance.

`result.csv` reports `total_lines / valid_lines / malformed_lines` so the
poison ratio is fully auditable.

## 7. STRICT CODING RULES compliance

* **Zero** occurrences of `new`, `delete`, `malloc`, `free`, `calloc`,
  `realloc` in all first-party sources (`server/`, `client/`, `common/`,
  `tools/`). The only textual matches are `= delete;` copy-suppression
  declarations, which are a compile-time RAII-enforcement idiom, not memory
  management. (`::freeaddrinfo` is the mandatory POSIX release call for
  `getaddrinfo` results and is wrapped in an RAII holder.)
* All buffers are `std::vector`/`std::string`/`std::array`; sockets, file
  descriptors, Winsock lifetime, `addrinfo` results, worker threads and the
  connection counter are all RAII objects - every early-return / error path
  releases its resources automatically.
* Verified leak-free with AddressSanitizer + LeakSanitizer across normal
  transfers, mid-transfer disconnects, and SIGTERM shutdown: **0 leaks**.
* Third-party vendored code (`third_party/imgui`, unmodified upstream
  Dear ImGui) manages its own memory internally and is outside the
  first-party rule scope.

## 8. Robustness test matrix (all automated, all passing)

| Scenario | Result |
|---|---|
| 500 MB upload -> parse -> result.csv round trip | OK, ~0.6 s, output verified against an independent Python reimplementation (100% match) |
| Server peak memory during 500 MB stream | 4.2 MB (`VmHWM`) |
| 59 poisoned lines in 6,185,997 | all 59 detected, skipped, logged; zero crashes |
| Client SIGKILL at ~30% of upload | server logs `connection lost mid-upload`, frees resources, keeps serving |
| Random garbage bytes sent to the port | rejected at header validation, connection dropped |
| Server SIGKILL mid-upload | client exits gracefully with a clear error (no crash) |
| ASan/LSan build, incl. aborted transfers | 0 errors, 0 leaks |
| Daemon mode | detached session (`setsid`), pid file, file logging, clean SIGTERM stop |
| Empty file / file without trailing newline | handled correctly |
| Connect to unroutable address | fails fast (10 s cap), cancellable mid-connect |
| Real Windows process -> WSL2 Linux server, 500 MB | result byte-identical to Linux-native run |

## 9. Automated tests & CI

```bash
cd build && ctest --output-on-failure
```

* `parser_unit` - unit tests covering every poison category (missing
  brackets, binary garbage, truncated timestamps, `spd=NaN??`, glued junk,
  out-of-range values), CRLF / missing-final-newline, byte-by-byte chunk
  boundary equivalence, the 64 KiB over-long-line guard and the aggregate
  hard cap.
* `e2e` - spins up a real server, uploads a generated poisoned log, checks
  the returned CSV against the generator's ground truth, SIGKILLs a client
  mid-upload, throws random garbage at the port, verifies deterministic
  results afterwards, and asserts the client fails fast (<=15 s) on an
  unroutable address.

GitHub Actions runs four jobs on every push: forbidden-keyword scan,
Release build + ctest, ASan/LSan build + ctest (a leak fails the build),
and the zig cross-compile of the Windows GUI client.

## 10. result.csv format

```
# Task1: event count per module grouped by hour
module,hour,count
Engine,2026-02-14 00,360407
...
# Task2: average speed over lines containing 'spd'
metric,value
spd_line_count,1855546
average_speed,90.028523
min_speed,0.000000
max_speed,180.000000
# Summary
metric,value
total_lines,6185997
valid_lines,6185938
malformed_lines,59
bytes_processed,524288023
```
