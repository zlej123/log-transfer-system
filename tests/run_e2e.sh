#!/usr/bin/env bash
# End-to-end test: real server + real client + robustness scenarios.
#   usage: tests/run_e2e.sh <build-dir>
set -euo pipefail
BUILD=${1:-build}
PORT=$(( (RANDOM % 10000) + 40000 ))
WORK=$(mktemp -d)
SRV=""
cleanup() {
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "[e2e] workdir=$WORK port=$PORT"

# 30 MB deterministic log with poison lines
"$BUILD/loggen" --out "$WORK/log.log" --size-mb 30 --seed 42 > "$WORK/gen.txt"
cat "$WORK/gen.txt"
POISON=$(grep -oP '\d+(?= poison lines)' "$WORK/gen.txt")

"$BUILD/log_server" --port "$PORT" --workdir "$WORK/srv" &
SRV=$!
sleep 0.5

# --- 1. normal round trip -------------------------------------------------
"$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" "$WORK/result.csv"
grep -q "average_speed" "$WORK/result.csv"

# totals must equal the generator's line count; malformed must equal poison
TOTAL=$(grep '^total_lines' "$WORK/result.csv" | cut -d, -f2)
MALF=$(grep '^malformed_lines' "$WORK/result.csv" | cut -d, -f2)
WC=$(wc -l < "$WORK/log.log")
[ "$TOTAL" = "$WC" ]      || { echo "line count mismatch: $TOTAL != $WC"; exit 1; }
[ "$MALF" = "$POISON" ]   || { echo "poison mismatch: $MALF != $POISON"; exit 1; }
echo "[e2e] round trip OK (lines=$TOTAL malformed=$MALF)"

# --- 2. client killed mid-upload: server must survive -----------------------
"$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" /dev/null \
    > /dev/null 2>&1 &
CPID=$!
sleep 0.05
kill -9 "$CPID" 2>/dev/null || true
wait "$CPID" 2>/dev/null || true
sleep 0.5
kill -0 "$SRV" || { echo "server died after client kill"; exit 1; }
echo "[e2e] server survived client SIGKILL mid-upload"

# --- 3. garbage bytes: server must reject and survive -----------------------
head -c 5000 /dev/urandom > "$WORK/garbage.bin"
timeout 3 bash -c "cat '$WORK/garbage.bin' > /dev/tcp/127.0.0.1/$PORT" || true
sleep 0.3
kill -0 "$SRV" || { echo "server died on garbage input"; exit 1; }
echo "[e2e] server survived random garbage stream"

# --- 4. still fully functional; result deterministic -------------------------
"$BUILD/log_client_cli" 127.0.0.1 "$PORT" "$WORK/log.log" "$WORK/result2.csv"
cmp "$WORK/result.csv" "$WORK/result2.csv"
echo "[e2e] post-fault result byte-identical"

# --- 5. connect timeout: unroutable address must fail fast, not hang ---------
START=$(date +%s)
"$BUILD/log_client_cli" 10.255.255.1 "$PORT" "$WORK/log.log" /dev/null \
    > /dev/null 2>&1 && { echo "expected failure"; exit 1; }
ELAPSED=$(( $(date +%s) - START ))
[ "$ELAPSED" -le 15 ] || { echo "connect hang: ${ELAPSED}s"; exit 1; }
echo "[e2e] unroutable connect failed fast (${ELAPSED}s <= 15s)"

echo "E2E OK"
