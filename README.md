# Large Log Analysis & Transfer System

[![CI](https://github.com/zlej123/log-transfer-system/actions/workflows/ci.yml/badge.svg)](https://github.com/zlej123/log-transfer-system/actions/workflows/ci.yml)

A production-oriented C++17 client/server application that securely transfers
large virtual-device logs from Windows to Linux, verifies their integrity,
parses them with bounded memory, and returns an atomically published CSV.

## Highlights

- **Mutual TLS 1.3** with certificate-chain validation, server hostname
  verification, an authorized client subject, and mandatory ALPN `lgx/2`.
  There is no plaintext or LGX1 downgrade path.
- **Persistent upload resume** with a server-generated 256-bit opaque token.
  A disconnect or server restart continues from the server's authoritative
  durably committed manifest offset rather than retransmitting the prefix.
- **End-to-end SHA-256** for the complete input and returned CSV. Parsing never
  starts until the complete spool passes verification; a result is staged and
  atomically replaces the destination only after its size and digest match.
- **Fixed-size bounded thread pool**, bounded admission queue, queue-age limit,
  per-session deadlines, same-upload exclusive lease, disk reservation quota,
  partial-count cap and stale-state TTL.
- **Streaming analysis** with one reusable 64 KiB buffer. The 500 MiB file is
  never loaded into memory.
- **Poison-line containment**: malformed records are counted and skipped while
  processing continues. Payload samples are disabled by default.
- **Windows GUI** in C++17 with Dear ImGui/Win32/DirectX 11. Hashing, DNS/TCP,
  TLS, resume negotiation, upload and download all execute on a worker thread.
- No prohibited manual-allocation/deallocation keyword token appears anywhere
  in first-party C++ source, including comments.

## Components

| Component | Technology |
|---|---|
| Linux server | C++17, Berkeley sockets, `signalfd`/`poll`, bounded worker pool |
| Windows GUI | C++17, Dear ImGui, Win32, DirectX 11 |
| CLI client | Same cross-platform C++17 transfer engine as the GUI |
| TLS / SHA-256 | Vendored Mbed TLS 3.6.4 (Apache-2.0) |
| Test log generator | Deterministic C++17 regression-data generator |

## Quick start

### 1. Build on Linux

Requirements: CMake 3.16+, a C++17 compiler, Python 3 (vendored Mbed TLS
configuration), POSIX threads, and the `openssl` CLI for test certificates. TLS libraries are vendored.

```bash
./scripts/build_linux.sh
```

This creates:

- `build/log_server`
- `build/log_client_cli`
- `build/loggen`

### 2. Generate local test PKI material

```bash
./scripts/generate_test_certs.sh certs
```

This produces a development CA plus server/client certificates. The server
certificate contains `DNS:localhost` and `IP:127.0.0.1`; the client certificate
has subject `CN=lgx-client` and `clientAuth` EKU.

> The generated keys are for local testing only and are ignored by Git. Use
> organization-managed PKI, protected key storage and a deliberate client
> subject authorization policy in production.

### 3. Start the server

```bash
./build/log_server \
  --port 45777 \
  --workdir server_work \
  --cert certs/server.crt \
  --key certs/server.key \
  --client-ca certs/ca.crt \
  --allowed-client-subject "CN=lgx-client" \
  --threads 4 --queue 32
```

Daemon mode:

```bash
./build/log_server [same options] --daemon
```

Under systemd, prefer the supervised unit instead of `--daemon`:

```bash
sudo install -m 0644 packaging/systemd/log-transfer-server.service \
    /etc/systemd/system/
sudo systemctl enable --now log-transfer-server.service
```

See [`packaging/systemd/README.md`](packaging/systemd/README.md) for the service
account, TLS material layout, sandbox settings and failure behavior.

The private work directory and upload store use mode `0700`; daemon-created
files inherit mode `0600`. `server.pid` is removed during graceful shutdown.

### 4. Generate and transfer a 500 MiB log

```bash
./build/loggen --out test_log_500mb.log --size-mb 500

./build/log_client_cli 127.0.0.1 45777 test_log_500mb.log result.csv \
  certs/ca.crt certs/client.crt certs/client.key localhost
```

CLI argument order:

```text
log_client_cli <host> <port> <log> [result] [ca] [client-cert] [client-key] [TLS-server-name]
```

The TLS server name is verified against the certificate SAN independently of
the address used to connect. This allows, for example, connecting to a WSL IP
while verifying the configured name `localhost` in a private test deployment.

## Windows GUI client

Run `dist/windows/log_client_gui.exe` and select:

1. Server address and port
2. TLS server name
3. Server CA certificate
4. Client certificate and private key
5. Log file
6. **Upload & Analyze**
7. **Download Result (Save As...)**

Separate progress bars show the source SHA-256 pass, encrypted upload (including
the resumed offset), and verified result download. Closing or cancelling the
window signals the worker; socket operations poll at one-second intervals and
all owned resources are released through RAII.

### Native Windows build

```bat
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release --target log_client_gui log_client_cli
```

### Linux-to-Windows cross-build

```bash
# zig on PATH, or: pip install ziglang
./scripts/build_windows_client.sh
```

Mbed TLS is linked into the executables, so separate TLS DLLs are not required.

## Architecture

```text
Windows client                                  Linux daemon
┌──────────────────────────────┐                ┌─────────────────────────────┐
│ GUI thread                   │                │ poll(listener, signalfd)    │
│  reads atomic progress       │                │       │ try_submit          │
│           ▲                  │  mTLS 1.3      │       ▼                     │
│ worker thread                ├───────────────►│ bounded queue (Q)           │
│  SHA-256 source pass         │                │       ▼                     │
│  resume negotiation          │                │ fixed workers (N)           │
│  stream suffix               │                │  private .part spool        │
│  verify result + atomic move │◄───────────────┤  SHA verify + stream parse  │
└──────────────────────────────┘                └─────────────────────────────┘
```

### Bounded concurrency and shutdown

The old detached-thread-per-connection model has been replaced by an owning
`BoundedThreadPool`:

- fixed worker count (`--threads`, default 4)
- fixed queue capacity (`--queue`, default 32)
- non-blocking admission; overflow is immediately closed
- queued sockets older than ten seconds are discarded
- active sockets are held by shared connection-state ownership, preventing file
  descriptor reuse races during shutdown
- SIGINT/SIGTERM are consumed via `signalfd` in ordinary process context
- shutdown closes admission, clears queued owners, calls `shutdown()` on active
  sockets, and joins every worker before logger/store destruction

Server-side upload idle and absolute deadlines prevent a peer from retaining a
worker indefinitely. The aggregate table is capped at 20,000 keys per job, and
the pool bounds the process-wide multiplier.

## LGX2 protocol

Every application byte is inside mutually authenticated TLS 1.3 with negotiated
ALPN `lgx/2`. The fixed 16-byte header uses network byte order:

```text
magic[4] = "LGX2"
command:u8 | flags:u8 | name_length:u16 | payload_size:u64
```

Unknown commands, reserved flags, names above 1024 bytes and payloads above
8 GiB are rejected before payload processing.

### Upload / resume state machine

```text
Client                                      Server
UPLOAD_INIT(size, name, SHA256, token)  ->  validate identity + quotas
                                        <-  RESUME_INFO(offset, opaque token)
seek(offset); stream [offset, size)      ->  append private spool
                                        ->  recompute SHA256 over complete spool
                                        ->  parse complete verified spool in 64 KiB chunks
                                        <-  RESULT_CSV(name, SHA256, bytes)
verify into staging file; atomic publish
```

An all-zero token creates a session. The server returns a cryptographically
random 256-bit token, stored by the client in a restrictive sidecar (`0600`
on POSIX; inherited user ACL on Windows) bound to the
local file digest, TLS server name, port and CA-file digest. Server paths are derived only from the token, never the
display filename. On reconnect:

- token, name, size and digest must all match the manifest
- the server alone chooses the offset from the durable manifest checkpoint
- only one connection may own a token; a contender receives `ServerBusy`
- every 4 MiB checkpoint follows `fdatasync(spool)` -> synced manifest
  staging -> atomic rename -> parent-directory `fsync`
- restart recovery trusts only the manifest's committed offset and truncates any
  uncommitted spool tail before accepting a suffix
- completed uploads cache their result and its immutable digest, making retry
  after a lost result response idempotent
- a full-file digest mismatch discards the partial and invalidates the sidecar

Only spool bytes through the durable manifest offset are trusted. After any
resume, the complete file is read
from byte zero into a fresh analyzer, so parser carry/discard state cannot be
omitted or counted twice at the resume boundary.

Stable structured error codes distinguish protocol, resume, checksum, busy,
storage and internal failures. See [`docs/protocol-v2.md`](docs/protocol-v2.md).

## Integrity and atomic publication

1. The client hashes the same open input stream it subsequently uploads.
2. The claimed SHA-256 is sent in `UPLOAD_INIT` inside mTLS.
3. After exact-size receipt, the server rereads the private spool in bounded
   chunks and computes SHA-256 while feeding the parser.
4. A mismatch is terminal for that session; no parser result is published.
5. The server hashes the CSV and sends its digest before the CSV bytes.
6. The client writes a token-scoped staging file, verifies size and digest, and
   atomically replaces the requested result. A prior valid result survives a
   failed or tampered download.

NIST SHA-256 vectors (empty, `abc`, one million `a` bytes) and live source
mutation are covered by automated tests.

## Memory and storage bounds

- 64 KiB receive/read buffer per active connection
- 64 KiB maximum logical log line; an oversized line is discarded without
  accumulating its contents
- 20,000 maximum module/hour aggregate keys per analyzer
- 50 maximum poison samples retained in memory
- bounded workers and queue
- 8 GiB per-file protocol ceiling
- 20 GiB default logical reservation quota (`--max-storage-gb`)
- 100 active partials by default (`--max-partials`)
- completed+partial manifest count capped relative to the partial quota
- 24-hour stale cache/partial cleanup at startup and new-session admission
  (`--resume-ttl-hours`)

Measured with the supplied `BYDA_Test_Log_500MB.log` (506,286,814 bytes):

| Measurement | Result |
|---|---:|
| Linux server peak RSS (`VmHWM`) | **≤ 5.2 MiB** |
| Client peak RSS | **≤ 4.7 MiB** |
| Full client operation (pre-hash + mTLS upload + verify/parse + result) | **6.7–9.34 s** |
| Server SHA verification + streaming analysis | **2.09–2.25 s** |
| Parsed records | **3,483,502 valid / 26 malformed** |
| Speed records | **580,661; average 137,500.000000** |
| Result correctness | all **125 module/hour buckets** equal an independent streaming oracle |

## Poison-data algorithm

Supported records (the first is the supplied assignment corpus; the second
keeps the original regression-data format compatible):

```text
[YYYY-MM-DD_HH:MM:SS.ffffff][id][tid][pid] BYDA::Module: ... spd[137500.0] ...
[YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] [Module] ... spd=12.34 ...
```

The hot path is a non-throwing validating scanner:

- strict field positions and separators
- real calendar validation, including leap-year/month-day rules
- bounded numeric metadata and qualified `BYDA::Module` names
- known typed BYDA payload fields (`nodeUID`, `rfLane`) validated as integers
- dialect-specific standalone `spd` parsing with duplicate-field rejection
- locale-independent `std::from_chars`, finite/range/trailing-junk validation
- chunk-invariant overlong-line rejection (including a complete oversized line
  delivered in one network read)
- CRLF and missing-final-newline support

Malformed/blank/ambiguous lines increment the audit counters and are skipped.
The first 50 sanitized samples exist in memory for diagnostics, but payload
sample persistence requires the explicit `--log-poison-samples` option.

## Automated verification

```bash
cd build && ctest --output-on-failure
```

CTest includes:

1. `parser_unit`: legacy and supplied BYDA grammars, poison categories,
   calendar semantics, dialect-specific speed boundaries, byte-by-byte chunk
   equivalence, both one-shot/chunked 100 KiB lines, hard aggregate cap.
2. `protocol_unit`: golden network-order frame, all truncated header lengths,
   invalid magic/command/flags, filename sanitization and NIST SHA-256 vectors.
3. `thread_pool_unit`: `N=2/Q=2` backpressure, worker maximum and bounded active
   socket shutdown/join.
4. `upload_store_unit`: completed-cache retry, persisted result digest
   corruption rejection, manifest reload, uncommitted-tail truncation,
   short-spool/missing-cache/stale-staging recovery, on-admission TTL cleanup,
   deletion-failure retention and orphan charging.
5. `e2e`: generated ephemeral PKI, mTLS success, wrong CA/name, empty server
   identity, untrusted client and mismatched certificate/key rejection,
   plaintext rejection, symlink/duplicate-workdir exclusion, live source
   mutation, deterministic TLS fault injection, SIGKILL/restart resume,
   simultaneous resume contention, lost-result cached retry, post-generation
   cache tamper rejection, cooperative verify cancellation, accept-flood
   SIGTERM, byte-identical baseline, and connect timeout.

GitHub Actions runs:

- strict first-party source scan
- Linux Release tests
- ASan/UBSan + LeakSanitizer tests
- ThreadSanitizer tests
- Windows GUI + CLI zig cross-build

The full E2E suite also passes under ASan/UBSan. TSan is run on the native Ubuntu
CI runner; some WSL kernels cannot start its shadow-memory runtime.

## Strict coding-rule compliance

- First-party C++ source under `server/`, `client/`, `common/`, `tools/` and
  `tests/` contains **zero whole-word occurrences** of every prohibited manual
  allocation/deallocation token, including comments.
- Buffers use `std::array`, `std::vector` and `std::string`.
- Socket handles, TLS/X.509/key/RNG contexts, files, threads, queue tasks,
  upload leases and temporary artifacts are immediately owned by RAII types.
- Copying of unique owners is inaccessible; move semantics transfer ownership.
- All early-return, exception, disconnect, cancellation and shutdown paths have
  been exercised under sanitizers.
- Vendored Dear ImGui and Mbed TLS are third-party projects governed by their
  own licenses and excluded from the first-party keyword policy.

## Repository layout

```text
common/protocol.hpp          LGX2 frame codec and validation
common/hash.hpp              RAII SHA-256 helper
common/tls.hpp               TLS 1.3/mTLS RAII transport
server/main.cpp              signalfd accept loop, TLS handler, workflow
server/thread_pool.hpp       bounded owning worker pool
server/upload_store.hpp      token manifests, quotas, resume/cache leases
server/parser.{hpp,cpp}      bounded incremental analyzer
client/core/transfer.hpp     worker transfer/resume/integrity engine
client/gui/main.cpp          Dear ImGui Win32/DX11 UI
client/cli/main.cpp          automation/console client
tools/loggen.cpp             deterministic large-log generator
tests/                       unit, E2E and fault-injection tests
scripts/                     Linux/Windows builds and test PKI generation
packaging/systemd/           supervised service unit and deployment guide
third_party/imgui/           Dear ImGui source
third_party/mbedtls/         Mbed TLS 3.6.4 source
dist/                        prebuilt Linux and Windows binaries
docs/protocol-v2.md          wire/state specification
docs/requirements-compliance.md  assignment requirement mapping (Korean)
```

## License

First-party code is MIT licensed. Dear ImGui is MIT licensed. Mbed TLS 3.6.4 is
Apache-2.0 licensed; its license is included under `third_party/mbedtls/LICENSE`.
