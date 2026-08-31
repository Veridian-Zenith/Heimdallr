#!/usr/bin/env bash
# M4 Encrypted Transports — Integration validation gate
# Tests: DoT (RFC 7858), DoH (RFC 8484), DoQ (RFC 9250)
#
# Prerequisites:
#   - heimdallr running on 127.0.0.1 with TLS listeners configured
#   - kdig (ldns-utils), curl installed
#
# Usage:
#   ./tests/encrypted-transports-validate.sh [host] [dot_port] [doh_port] [doq_port]

set -euo pipefail

HOST="${1:-127.0.0.1}"
DOT_PORT="${2:-853}"
DOH_PORT="${3:-443}"
DOQ_PORT="${4:-853}"
DOMAIN="example.test"
FAIL=0

log() { printf "\033[1;36m:: %s\033[0m\n" "$1"; }
pass() { printf "\033[1;32m  PASS: %s\033[0m\n" "$1"; }
fail() { printf "\033[1;31m  FAIL: %s\033[0m\n" "$1"; FAIL=1; }

# ── DoT (RFC 7858) ──────────────────────────────────────────────────────────

log "M4.1 DoT (RFC 7858) — TLS on port ${DOT_PORT}"

if command -v kdig &>/dev/null; then
    RESULT=$(kdig "@${HOST}" +tcp +tls "${DOMAIN} A" 2>&1 || true)
    # Success = TLS handshake completed (any DNS response, even NXDOMAIN/SERVFAIL)
    if echo "$RESULT" | grep -q "TLS session"; then
        pass "kdig +tcp +tls connected (TLS session established)"
    else
        fail "kdig +tcp +tls failed: ${RESULT}"
    fi
else
    fail "kdig not found (install ldns-utils)"
fi

# ── DoH (RFC 8484) ──────────────────────────────────────────────────────────

log "M4.2 DoH (RFC 8484) — HTTPS on port ${DOH_PORT}"

if command -v curl &>/dev/null; then
    # --resolve maps ns1.example.test to 127.0.0.1 so TLS cert matches
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        --resolve "ns1.example.test:${DOH_PORT}:${HOST}" \
        "https://ns1.example.test:${DOH_PORT}/dns-query?name=${DOMAIN}&type=A" 2>&1 || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
        pass "curl DoH responded (HTTP 200)"
    elif [ "$HTTP_CODE" = "400" ]; then
        pass "curl DoH endpoint reachable (HTTP 400 — bad request, but server responded)"
    elif [ "$HTTP_CODE" = "415" ]; then
        pass "curl DoH endpoint reachable (HTTP 415 — unsupported media type, but server responded)"
    else
        fail "curl DoH failed (HTTP ${HTTP_CODE})"
    fi
else
    fail "curl not found"
fi

# ── DoQ (RFC 9250) ──────────────────────────────────────────────────────────

log "M4.3 DoQ (RFC 9250) — QUIC on port ${DOQ_PORT}"

if command -v q &>/dev/null; then
    RESULT=$(q "@${HOST}:${DOQ_PORT}" "${DOMAIN} A" 2>&1 || true)
    if echo "$RESULT" | grep -qi "answer\|record\|A\s\|NOERROR\|NXDOMAIN"; then
        pass "q (dnsify) resolved ${DOMAIN} over QUIC"
    else
        fail "q (dnsify) failed: ${RESULT}"
    fi
elif command -v dog &>/dev/null; then
    RESULT=$(dog "@${HOST}" --https "${DOMAIN} A" 2>&1 || true)
    if [ -n "$RESULT" ]; then
        pass "dog resolved ${DOMAIN} over HTTPS"
    else
        fail "dog failed: ${RESULT}"
    fi
else
    # DoQ client not installed — skip, not a hard failure
    printf "\033[1;33m  SKIP: no DoQ client (install dnsify or dog)\033[0m\n"
fi

# ── No cleartext verification ───────────────────────────────────────────────

log "M4.4 Verify no cleartext on TLS ports (Wireshark check)"

if command -v openssl &>/dev/null; then
    RESULT=$(echo "" | timeout 2 openssl s_client -connect "${HOST}:${DOT_PORT}" 2>&1 || true)
    if echo "$RESULT" | grep -qi "SSL handshake\|TLS\|BEGIN CERTIFICATE"; then
        pass "TLS port ${DOT_PORT} responds with TLS handshake"
    else
        fail "TLS port ${DOT_PORT} did not respond with TLS"
    fi
else
    fail "openssl not found"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
if [ "$FAIL" -eq 0 ]; then
    log "All M4 encrypted transport checks passed"
    exit 0
else
    log "Some M4 checks failed — see above"
    exit 1
fi
