#!/bin/sh
set -eu

apk add --no-cache curl > /dev/null 2>&1

# Wait for the full chain: test → DNS → caddy (TLS + WAF) → app
echo "Waiting for chain..."
READY=0
for i in $(seq 1 30); do
  if curl -sk https://app.test.internal 2>/dev/null | grep -q "nginx"; then
    READY=1
    break
  fi
  sleep 1
done

if [ "$READY" = "0" ]; then
  echo "FAIL: chain did not become ready within 30s"
  exit 1
fi

PASS=0
FAIL=0

run_test() {
  name="$1"
  shift
  printf "  %-44s" "$name"
  if "$@"; then
    echo "PASS"
    PASS=$((PASS + 1))
  else
    echo "FAIL"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "Running tests..."
echo ""

# DNS resolves app.test.internal to the caddy container
run_test "DNS resolution" \
  sh -c 'nslookup app.test.internal 172.20.0.2 2>/dev/null | grep -q "172.20.0.10"'

# HTTPS happy path: TLS terminates, WAF passes legitimate traffic, backend responds
run_test "HTTPS happy path" \
  sh -c 'curl -sk https://app.test.internal | grep -q "nginx"'

# Health endpoint on port 8080 (independent of main listener)
run_test "Health endpoint" \
  sh -c 'curl -sf http://172.20.0.10:8080/cgi-bin/health | grep -q "ok"'

# Caddy redirects plain HTTP to HTTPS
run_test "HTTP -> HTTPS redirect" \
  sh -c '
    code=$(curl -s -o /dev/null -w "%{http_code}" http://app.test.internal)
    [ "$code" = "308" ] || [ "$code" = "301" ] || [ "$code" = "302" ]
  '

# SQLi pattern in query string — CRS rule 942100 (libinjection) should trigger
run_test "SQL injection blocked" \
  sh -c '
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://app.test.internal/?id=1%27%20OR%20%271%27=%271")
    [ "$code" = "403" ]
  '

# XSS pattern in query string — CRS rule 941xxx catches script tags
run_test "XSS blocked" \
  sh -c '
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://app.test.internal/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    [ "$code" = "403" ]
  '

# Path traversal — CRS rule 930100 (LFI)
# --path-as-is prevents curl from normalising ../../ before sending
run_test "Path traversal blocked" \
  sh -c '
    code=$(curl -sk --path-as-is -o /dev/null -w "%{http_code}" https://app.test.internal/../../etc/passwd)
    [ "$code" = "403" ]
  '

# Scanner User-Agent — CRS rule 913100 catches known scanner UAs
run_test "Scanner User-Agent blocked" \
  sh -c '
    code=$(curl -sk -A "sqlmap/1.0" -o /dev/null -w "%{http_code}" https://app.test.internal/)
    [ "$code" = "403" ]
  '

echo ""
echo "$PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
