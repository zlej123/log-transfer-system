# LGX2 Protocol Specification

## Transport and identity

LGX2 runs only inside TLS 1.3. Both endpoints present X.509 certificates and
validate the peer against configured trust anchors. The client validates the
configured server DNS/IP identity. The server additionally compares the
verified client subject with its authorization setting. ALPN must negotiate
exactly `lgx/2`; absent or different ALPN terminates the session. Plain TCP,
LGX1 and TLS fallback are not accepted.

One upload transaction is processed per TLS connection.

## Header

All integers use network byte order. Each message begins with:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII `LGX2` |
| 4 | 1 | command |
| 5 | 1 | flags / structured error code |
| 6 | 2 | UTF-8 name length |
| 8 | 8 | payload size or resume offset |

The decoder rejects:

- a short header
- wrong magic
- command outside 1..4
- nonzero flags except a defined `ERROR_TEXT` code
- name length above 1024
- payload above 8 GiB

Command semantics further require zero names on resume/error frames, error
payloads at most 1024 bytes, and result payloads at most 64 MiB.

## Commands

### 1 — `UPLOAD_INIT`

Header:

- `name_length`: display filename length
- `payload_size`: complete logical file size
- flags: zero

Body:

```text
name[name_length]
file_sha256[32]
resume_token[32]
```

An all-zero token requests a distinct session. Otherwise it must name a valid,
unexpired manifest whose verified client principal, sanitized name, size and SHA-256 match. The display filename never determines a filesystem path.

### 2 — `RESUME_INFO`

Header:

- name length: zero
- payload size: server-authoritative durable manifest offset
- flags: zero

Body:

```text
resume_token[32]
```

The offset must not exceed the complete size. The client persists the token in
a restrictive sidecar bound to the local SHA-256 plus TLS server name, port and
CA-file digest, seeks exactly to the returned
offset, and streams bytes through EOF. The server appends only under an
exclusive per-token lease. A competing writer gets `SERVER_BUSY`.

After exact-size receipt, the server streams the complete spool through SHA-256
and the analyzer from byte zero. This intentionally makes reconnect boundaries
irrelevant to parser state. Only a digest match permits result generation.

### 3 — `RESULT_CSV`

Header:

- name length: result display name length (`result.csv`)
- payload size: CSV byte length
- flags: zero

Body:

```text
name[name_length]
result_sha256[32]
csv[payload_size]
```

The client writes to a token-scoped staging path, hashes while receiving,
checks exact length and digest, then atomically replaces the destination. The
resume sidecar is removed only after that publication succeeds.

A completed server manifest caches the CSV. Reconnecting with the same token
returns offset=`file_size` followed by the same result. The server recomputes
and compares the cached bytes with the digest persisted at generation time
before delivery, making a lost result response idempotent.

### 4 — `ERROR_TEXT`

Header payload size is the bounded UTF-8 message length. `flags` is one of:

| Value | Meaning |
|---:|---|
| 1 | protocol violation |
| 2 | invalid/expired resume state |
| 3 | complete-file SHA-256 mismatch |
| 4 | session busy |
| 5 | storage/quota failure |
| 6 | contained internal failure |

Messages are capped at 1024 bytes by the server. Unknown error codes are a
protocol error. A resume/checksum error removes the client sidecar; a transient
busy/network error preserves it.

## Persistent state

The private server upload directory uses files derived exclusively from the
256-bit token encoded as lowercase hexadecimal:

```text
<token>.meta   version, token, input/result digests, size, durable offset,
               state, display name, authenticated principal
<token>.part   unverified bytes
<token>.csv    verified cached result
```

The server workdir is owner-validated with symlinked components rejected, is
held by a process-wide exclusive lock, and it plus the upload directory are
forced to mode 0700. A daemon umask of 077 protects artifacts.
Each checkpoint synchronizes the spool, synchronizes a manifest staging file,
renames it, then synchronizes the parent directory. Recovery truncates bytes
past the manifest offset. Result/manifest publication uses the same durable
staging and directory-sync sequence. Partial
and completed state is removed after its configured TTL during startup cleanup
and opportunistically on new-session admission.
Logical size reservation, active partial count and total record count are
bounded.

## Failure rules

- TLS/identity/ALPN failure: close without application processing.
- Header/meta truncation: close; no unbounded allocation.
- Upload disconnect: synchronize the received prefix, commit its offset, and
  retain token state.
- Server restart: load the durable manifest, reject a short spool, truncate
  any tail past its committed offset, then resume.
- Offset greater than local source size: client aborts.
- Name/size/digest/token mismatch: fatal resume error.
- SHA mismatch: discard untrusted spool and manifest; never publish a CSV.
- Result disconnect: retain completed cache and client token; retry redelivers.
- Cached-result digest failure: remove the unusable session, invalidate the
  client sidecar, and require a distinct re-upload.
- Shutdown: stop admission, close queued and active sockets, join all workers.

## Resource policy defaults

- TLS handshake: 15-second absolute deadline
- initial application fields: 10 seconds each
- upload idle: 30 seconds
- upload absolute deadline: max(300 seconds, size / 1 MiB/s + 60 seconds)
- fixed 4 workers and 32 queued sessions
- 20 GiB partial reservation plus accounting for cached/orphan artifacts
- 100 partial uploads and a related total-manifest cap
- 24-hour startup and on-admission TTL cleanup
- 64 KiB I/O chunks and log-line limit
