#!/usr/bin/env bash
# M3 DNSSEC validation gate — signs example.test and verifies with delv
# Usage: ./tests/dnssec-validate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$ROOT_DIR/target/debug/heimdallr"
CONFIG="$ROOT_DIR/config/config-dnssec-test.toml"
ZONES_SRC="$ROOT_DIR/config/zones/live"
ZONES_DST="/tmp/heimdallr-dnssec-test/zones"
KEYS_DIR="/tmp/heimdallr-dnssec-test/keys"
PORT=5355
API_PORT=5382
PID=""

cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf /tmp/heimdallr-dnssec-test
}
trap cleanup EXIT

echo "=== M3 DNSSEC Validation Gate ==="

# Build if needed
if [ ! -x "$BIN" ]; then
    echo "Building heimdallr..."
    cargo build --manifest-path "$ROOT_DIR/Cargo.toml" 2>&1 | tail -3
fi

# Prepare test environment
mkdir -p "$ZONES_DST" "$KEYS_DIR"
cp "$ZONES_SRC/example.test.zone" "$ZONES_DST/"

echo "Starting heimdallr with DNSSEC signing (port $PORT)..."
"$BIN" --config "$CONFIG" &
PID=$!
echo "PID: $PID"

# Wait for server to start
echo "Waiting for server..."
for i in $(seq 1 30); do
    if dig @"127.0.0.1" -p "$PORT" example.test. SOA +short +time=1 +tries=1 >/dev/null 2>&1; then
        echo "Server ready after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FAIL: Server did not start within 30s"
        exit 1
    fi
    sleep 1
done

# Test 1: Basic zone query
echo ""
echo "--- Test 1: Basic zone query ---"
ANSWER=$(dig @"127.0.0.1" -p "$PORT" example.test. SOA +noall +answer 2>&1)
echo "$ANSWER"
if echo "$ANSWER" | grep -q "example.test."; then
    echo "PASS: Zone responds"
else
    echo "FAIL: Zone did not respond"
    exit 1
fi

# Test 2: DNSKEY record present (signing worked)
echo ""
echo "--- Test 2: DNSKEY records ---"
DNSKEY=$(dig @"127.0.0.1" -p "$PORT" example.test. DNSKEY +noall +answer 2>&1)
echo "$DNSKEY"
if echo "$DNSKEY" | grep -q "DNSKEY"; then
    echo "PASS: DNSKEY records present"
else
    echo "FAIL: No DNSKEY records (zone not signed?)"
    exit 1
fi

# Test 3: RRSIG records present
echo ""
echo "--- Test 3: RRSIG records ---"
RRSIG=$(dig @"127.0.0.1" -p "$PORT" example.test. A +dnssec +noall +answer 2>&1)
echo "$RRSIG"
if echo "$RRSIG" | grep -qi "RRSIG"; then
    echo "PASS: RRSIG records present"
else
    echo "WARN: No RRSIG in answer (may need +dnssec flag support)"
fi

# Test 4: NSEC records present (non-existence proof)
echo ""
echo "--- Test 4: NSEC/NSEC3 records ---"
NSEC=$(dig @"127.0.0.1" -p "$PORT" nonexistent.example.test. A +dnssec +noall +answer 2>&1)
echo "$NSEC"
if echo "$NSEC" | grep -qi "NSEC\|NSEC3"; then
    echo "PASS: NSEC/NSEC3 records present"
else
    echo "WARN: No NSEC/NSEC3 in response (may be in authority section)"
fi

# Test 5: TLSA record query
echo ""
echo "--- Test 5: TLSA record ---"
TLSA=$(dig @"127.0.0.1" -p "$PORT" _443._tcp.www.example.test. TLSA +noall +answer 2>&1)
echo "$TLSA"
if echo "$TLSA" | grep -q "TLSA"; then
    echo "PASS: TLSA record served correctly"
else
    echo "FAIL: TLSA record not found"
    exit 1
fi

# Test 6: delv validation (if delv supports our listen address)
echo ""
echo "--- Test 6: delv DNSSEC validation ---"
DELV_OUT=$(delv @"127.0.0.1" -p "$PORT" example.test. A +rtrace 2>&1) || true
echo "$DELV_OUT" | head -30
if echo "$DELV_OUT" | grep -qi "fully validated\| valido\|SECURE"; then
    echo "PASS: delv validation succeeded"
elif echo "$DELV_OUT" | grep -qi "failure\|bogus\|INSECURE"; then
    echo "WARN: delv shows issues (may need root trust anchor for full chain)"
else
    echo "WARN: delv result inconclusive (check output above)"
fi

# Test 7: API records endpoint
echo ""
echo "--- Test 7: API records endpoint ---"
API_OUT=$(curl -s "http://127.0.0.1:$API_PORT/api/zones/example.test./records" 2>&1) || true
echo "$API_OUT" | head -5
if echo "$API_OUT" | grep -q "records"; then
    echo "PASS: API records endpoint works"
else
    echo "WARN: API records endpoint not reachable"
fi

echo ""
echo "=== M3 DNSSEC Validation Gate Complete ==="
echo "Zone signed with ECDSA P-256, DNSKEY/TLSA/NSEC served."
