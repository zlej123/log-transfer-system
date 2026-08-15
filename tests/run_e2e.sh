#!/usr/bin/env bash
# mTLS, integrity, resume/restart and fault-injection end-to-end test.
set -euo pipefail
BUILD=${1:-build}
PORT=0
PROXY_PORT=0
WORK=$(mktemp -d)
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ "${LGX_KEEP_TEST_WORK:-0}" = 1 ]; then
    echo "preserved test workdir: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

"$(dirname "$0")/../scripts/generate_test_certs.sh" "$WORK/certs" >/dev/null
"$(dirname "$0")/../scripts/generate_test_certs.sh" "$WORK/wrong-certs" >/dev/null

start_server() {
  "$BUILD/log_server" --port "$PORT" --workdir "$WORK/server" \
    --cert "$WORK/certs/server.crt" --key "$WORK/certs/server.key" \
    --client-ca "$WORK/certs/ca.crt" --threads 2 --queue 4 \
    >>"$WORK/server-console.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 100); do
    if [ -s "$WORK/server/server.port" ] &&
       grep -q 'TLS log_server' "$WORK/server-console.log" 2>/dev/null; then
      PORT=$(cat "$WORK/server/server.port")
      if [ "$PORT" -le 57000 ]; then PROXY_PORT=$(( PORT + 8000 ));
      else PROXY_PORT=$(( PORT - 8000 )); fi
      return
    fi
    kill -0 "$SERVER_PID" 2>/dev/null || {
      cat "$WORK/server-console.log"; exit 1;
    }
    sleep .05
  done
  echo "server readiness timeout"; exit 1
}
stop_server() {
  kill -TERM "$SERVER_PID"
  wait "$SERVER_PID"
  SERVER_PID=""
}
client() {
  "$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$1" "$2" \
    "$WORK/certs/ca.crt" "$WORK/certs/client.crt" \
    "$WORK/certs/client.key" localhost
}

# A malformed key must fail before the listener starts.
printf 'not a key\n' > "$WORK/bad.key"
if "$BUILD/log_server" --port "$PORT" --workdir "$WORK/bad-server" \
    --cert "$WORK/certs/server.crt" --key "$WORK/bad.key" \
    --client-ca "$WORK/certs/ca.crt" >/dev/null 2>&1; then
  echo "server accepted invalid TLS key"; exit 1
fi
if "$BUILD/log_server" --port "$PORT" --workdir "$WORK/mismatch-server" \
    --cert "$WORK/certs/server.crt" --key "$WORK/wrong-certs/server.key" \
    --client-ca "$WORK/certs/ca.crt" >/dev/null 2>&1; then
  echo "server accepted a mismatched certificate/key pair"; exit 1
fi
mkdir -p "$WORK/real-workdir"
ln -s "$WORK/real-workdir" "$WORK/symlink-workdir"
if "$BUILD/log_server" --port "$PORT" --workdir "$WORK/symlink-workdir" \
    --cert "$WORK/certs/server.crt" --key "$WORK/certs/server.key" \
    --client-ca "$WORK/certs/ca.crt" >/dev/null 2>&1; then
  echo "server accepted a symlinked workdir"; exit 1
fi

start_server

# A second process may not inspect or mutate the same persistent store.
set +e
timeout 2 "$BUILD/log_server" --port "$PROXY_PORT" --workdir "$WORK/server" \
  --cert "$WORK/certs/server.crt" --key "$WORK/certs/server.key" \
  --client-ca "$WORK/certs/ca.crt" >/dev/null 2>&1
SECOND_RC=$?
set -e
[ "$SECOND_RC" -ne 0 ] && [ "$SECOND_RC" -ne 124 ]
kill -0 "$SERVER_PID"
echo "[e2e] duplicate workdir owner rejected before store access"

# Normal authenticated/encrypted round trip.
"$BUILD/loggen" --out "$WORK/log.log" --size-mb 30 --seed 42 > "$WORK/gen.txt"
POISON=$(grep -oP '\d+(?= poison lines)' "$WORK/gen.txt")
client "$WORK/log.log" "$WORK/result.csv" >/dev/null
TOTAL=$(grep '^total_lines' "$WORK/result.csv" | cut -d, -f2)
MALFORMED=$(grep '^malformed_lines' "$WORK/result.csv" | cut -d, -f2)
LINES=$(wc -l < "$WORK/log.log")
[ "$TOTAL" = "$LINES" ]
[ "$MALFORMED" = "$POISON" ]
echo "[e2e] mTLS round trip OK (lines=$TOTAL malformed=$MALFORMED)"

# Wrong server trust anchor must fail closed and publish no result.
if "$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" \
    "$WORK/wrong.csv" "$WORK/wrong-certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
    >/dev/null 2>&1; then
  echo "wrong CA unexpectedly succeeded"; exit 1
fi
[ ! -e "$WORK/wrong.csv" ]
echo "[e2e] wrong CA rejected"

# Correct CA with a mismatched DNS identity must also fail closed.
if "$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" \
    "$WORK/wrong-name.csv" "$WORK/certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/certs/client.key" wrong.example \
    >/dev/null 2>&1; then
  echo "wrong TLS server name unexpectedly succeeded"; exit 1
fi
[ ! -e "$WORK/wrong-name.csv" ]
echo "[e2e] wrong TLS server identity rejected"
if "$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" \
    "$WORK/empty-name.csv" "$WORK/certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/certs/client.key" "" \
    >/dev/null 2>&1; then
  echo "empty TLS server name unexpectedly succeeded"; exit 1
fi
[ ! -e "$WORK/empty-name.csv" ]
echo "[e2e] empty TLS server identity rejected"

# A client certificate issued by another CA must be rejected by the server.
if "$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" \
    "$WORK/wrong-client.csv" "$WORK/certs/ca.crt" \
    "$WORK/wrong-certs/client.crt" "$WORK/wrong-certs/client.key" localhost \
    >/dev/null 2>&1; then
  echo "untrusted client certificate unexpectedly succeeded"; exit 1
fi
[ ! -e "$WORK/wrong-client.csv" ]
echo "[e2e] untrusted client certificate rejected"
if "$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" \
    "$WORK/mismatched-client.csv" "$WORK/certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/wrong-certs/client.key" localhost \
    >/dev/null 2>&1; then
  echo "client accepted mismatched certificate/key pair"; exit 1
fi
[ ! -e "$WORK/mismatched-client.csv" ]
echo "[e2e] mismatched client certificate/key rejected before transfer"

# Plaintext input has no downgrade path and cannot harm the daemon.
head -c 5000 /dev/urandom > "$WORK/garbage.bin"
timeout 3 bash -c "cat '$WORK/garbage.bin' > /dev/tcp/127.0.0.1/$PORT" || true
sleep .2
kill -0 "$SERVER_PID"
echo "[e2e] plaintext/garbage rejected; server survived"

# Source mutation after the pre-hash must be caught by the server's full-file
# digest check; no result or stale resume secret may survive.
"$BUILD/loggen" --out "$WORK/mutate.log" --size-mb 40 --seed 77 >/dev/null
"$BUILD/test_checksum_rejection" 127.0.0.1 "$PORT"   "$WORK/mutate.log" "$WORK/mutate.csv" "$WORK/certs/ca.crt"   "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost
[ ! -e "$WORK/mutate.csv" ]
echo "[e2e] source mutation rejected by SHA-256 verification"

# Cancel after upload completion but before result receipt. The prior result
# must survive, and reconnect must retrieve the cached verified CSV at EOF.
"$BUILD/loggen" --out "$WORK/retry.log" --size-mb 60 --seed 88 >/dev/null
"$BUILD/test_result_retry" 127.0.0.1 "$PORT" \
  "$WORK/retry.log" "$WORK/retry.csv" "$WORK/certs/ca.crt" \
  "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost
[ -s "$WORK/retry.csv" ]
echo "[e2e] lost-result retry returned verified cached CSV atomically"
# Corruption after generation must be detected against the manifest digest;
# the failed retry preserves the prior destination and invalidates its token.
RETRY_TOKEN=$(python3 - "$WORK/retry.csv.cachedtoken" <<'PY'
import pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
print(raw[40:72].hex())
PY
)
python3 - "$WORK/server/uploads/$RETRY_TOKEN.csv" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[0] ^= 1
path.write_bytes(data)
PY
cp "$WORK/retry.csv.cachedtoken" "$WORK/retry.csv.lgxresume"
cp "$WORK/retry.csv" "$WORK/retry-prior.csv"
if "$BUILD/log_client_cli" 127.0.0.1 "$PORT" \
    "$WORK/retry.log" "$WORK/retry.csv" "$WORK/certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
    >/dev/null 2>&1; then
  echo "corrupted cached result unexpectedly succeeded"; exit 1
fi
cmp "$WORK/retry.csv" "$WORK/retry-prior.csv"
[ ! -e "$WORK/retry.csv.lgxresume" ]
client "$WORK/retry.log" "$WORK/retry.csv" >/dev/null
echo "[e2e] cached-result corruption rejected and session safely renewed"

# Deterministic resume: drop TLS after persisted progress, restart server,
# continue from its authoritative offset and compare with uninterrupted output.
"$BUILD/loggen" --out "$WORK/resume.log" --size-mb 80 --seed 99 >/dev/null
python3 "$(dirname "$0")/tcp_drop_proxy.py" "$PROXY_PORT" "$PORT" 8388608 \
  >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 100); do
  grep -q READY "$WORK/proxy.log" 2>/dev/null && break
  sleep .02
done
if "$BUILD/log_client_cli" 127.0.0.1 "$PROXY_PORT" \
    "$WORK/resume.log" "$WORK/resumed.csv" "$WORK/certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
    >"$WORK/first-attempt.log" 2>&1; then
  echo "fault proxy did not interrupt upload"; exit 1
fi
wait "$PROXY_PID" 2>/dev/null || true
for _ in $(seq 1 100); do
  PART=$(find "$WORK/server/uploads" -name '*.part' -size +0c -print -quit 2>/dev/null || true)
  [ -n "${PART:-}" ] && grep -q 'resumable state retained' "$WORK/server-console.log" && break
  sleep .05
done
[ -n "${PART:-}" ] || { echo "partial upload was not retained"; exit 1; }
[ -f "$WORK/resumed.csv.lgxresume" ]
PARTIAL_SIZE=$(stat -c %s "$PART")
[ "$PARTIAL_SIZE" -gt 0 ]
kill -KILL "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
start_server
# Hold the resumed writer through a throttled relay, then present the same
# opaque token concurrently. Exactly one writer may own the upload lease.
cp "$WORK/resumed.csv.lgxresume" "$WORK/contender.csv.lgxresume"
python3 "$(dirname "$0")/tcp_drop_proxy.py" "$PROXY_PORT" "$PORT" 0 1 2 \
  >"$WORK/slow-proxy.log" 2>&1 &
SLOW_PROXY_PID=$!
for _ in $(seq 1 100); do
  grep -q READY "$WORK/slow-proxy.log" 2>/dev/null && break
  sleep .02
done
"$BUILD/log_client_cli" 127.0.0.1 "$PROXY_PORT" \
  "$WORK/resume.log" "$WORK/resumed.csv" "$WORK/certs/ca.crt" \
  "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
  >"$WORK/resume-attempt.log" 2>&1 &
RESUME_PID=$!
WRITER_ACTIVE=0
for _ in $(seq 1 200); do
  CURRENT_SIZE=$(stat -c %s "$PART" 2>/dev/null || echo 0)
  if [ "$CURRENT_SIZE" -gt "$PARTIAL_SIZE" ] && kill -0 "$RESUME_PID" 2>/dev/null; then
    WRITER_ACTIVE=1
    break
  fi
  sleep .02
done
[ "$WRITER_ACTIVE" = 1 ] || { echo "resumed writer did not acquire lease"; exit 1; }
if "$BUILD/log_client_cli" 127.0.0.1 "$PROXY_PORT" \
    "$WORK/resume.log" "$WORK/contender.csv" "$WORK/certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
    >"$WORK/contender.log" 2>&1; then
  echo "simultaneous resume writer unexpectedly succeeded"; exit 1
fi
grep -q 'upload currently active' "$WORK/contender.log"
wait "$RESUME_PID"
wait "$SLOW_PROXY_PID"
RESUME_OFFSET=$(tr '\r' '\n' < "$WORK/resume-attempt.log" |
  grep -o 'resume=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
[ "$RESUME_OFFSET" -gt 0 ]
[ ! -e "$WORK/resumed.csv.lgxresume" ]
rm -f "$WORK/contender.csv.lgxresume"
client "$WORK/resume.log" "$WORK/baseline.csv" >/dev/null
cmp "$WORK/resumed.csv" "$WORK/baseline.csv"
BYTES=$(grep '^bytes_processed' "$WORK/resumed.csv" | cut -d, -f2)
SIZE=$(stat -c %s "$WORK/resume.log")
[ "$BYTES" = "$SIZE" ]
echo "[e2e] restart/resume OK (offset=$RESUME_OFFSET, result identical)"

# SIGTERM during the post-upload digest/parse pass must be cooperative. The
# fully synced spool remains resumable at EOF and completes after restart.
"$BUILD/loggen" --out "$WORK/verify-stop.log" --size-mb 200 --seed 111 >/dev/null
"$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/verify-stop.log" \
  "$WORK/verify-stop.csv" "$WORK/certs/ca.crt" \
  "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
  >"$WORK/verify-stop-client.log" 2>&1 &
VERIFY_CLIENT_PID=$!
VERIFY_SIZE=$(stat -c %s "$WORK/verify-stop.log")
VERIFY_META=""
for _ in $(seq 1 500); do
  VERIFY_META=$(grep -l '^name=verify-stop.log$' "$WORK/server/uploads"/*.meta \
    2>/dev/null | head -1 || true)
  if [ -n "$VERIFY_META" ] && grep -q "^offset=$VERIFY_SIZE$" "$VERIFY_META"; then
    break
  fi
  sleep .01
done
[ -n "$VERIFY_META" ] && grep -q "^offset=$VERIFY_SIZE$" "$VERIFY_META"
kill -TERM "$SERVER_PID"
VERIFY_STOPPED=0
for _ in $(seq 1 100); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then VERIFY_STOPPED=1; break; fi
  sleep .05
done
[ "$VERIFY_STOPPED" = 1 ] || { echo "verify pass ignored SIGTERM"; exit 1; }
wait "$SERVER_PID"
SERVER_PID=""
wait "$VERIFY_CLIENT_PID" 2>/dev/null || true
[ -f "$WORK/verify-stop.csv.lgxresume" ]
start_server
"$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/verify-stop.log" \
  "$WORK/verify-stop.csv" "$WORK/certs/ca.crt" \
  "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
  >"$WORK/verify-retry.log" 2>&1
grep -Eq "resume=$VERIFY_SIZE" "$WORK/verify-retry.log"
echo "[e2e] SIGTERM cancelled verify promptly and EOF resume completed"

# Unroutable addresses must fail within the global 10-second connect cap.
START=$(date +%s)
if "$BUILD/log_client_cli" 10.255.255.1 "$PORT" "$WORK/log.log" \
    "$WORK/unreachable.csv" "$WORK/certs/ca.crt" \
    "$WORK/certs/client.crt" "$WORK/certs/client.key" localhost \
    >/dev/null 2>&1; then
  echo "unroutable address unexpectedly succeeded"; exit 1
fi
ELAPSED=$(( $(date +%s) - START ))
[ "$ELAPSED" -le 15 ]
echo "[e2e] connect failed fast (${ELAPSED}s)"

# A continuously replenished plaintext backlog must not starve signalfd, and
# active handshake sockets must be shut down before the owning pool joins.
python3 - "$PORT" <<'PY' >"$WORK/flood.log" 2>&1 &
import socket, sys, time
port = int(sys.argv[1])
sockets = []
end = time.time() + 8
while time.time() < end:
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=0.1)
        sockets.append(sock)
        if len(sockets) > 700:
            sockets.pop(0).close()
    except OSError:
        pass
PY
FLOOD_PID=$!
sleep .4
kill -TERM "$SERVER_PID"
STOPPED=0
for _ in $(seq 1 100); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then STOPPED=1; break; fi
  sleep .05
done
if [ "$STOPPED" -ne 1 ]; then
  kill -KILL "$SERVER_PID" 2>/dev/null || true
  echo "server did not stop promptly under accept flood"; exit 1
fi
wait "$SERVER_PID"
SERVER_PID=""
kill "$FLOOD_PID" 2>/dev/null || true
wait "$FLOOD_PID" 2>/dev/null || true
echo "[e2e] SIGTERM remained prompt under accept flood"

echo "E2E OK"
