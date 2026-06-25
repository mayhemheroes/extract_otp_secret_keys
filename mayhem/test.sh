#!/usr/bin/env bash
#
# extract_otp_secret_keys/mayhem/test.sh — behavioral oracle for scito/extract_otp_secrets.
#
# It RUNS the real CLI (via the /mayhem/run-cli launcher built by mayhem/build.sh) over the bundled
# example export and ASSERTS the decoded output (known-answer test): the CSV must carry the project's
# documented example secret/issuer/type. This exercises the SAME pipeline the fuzzer drives —
# file read -> otpauth-migration URL parse -> base64 decode -> protobuf MigrationPayload deserialize
# -> OTP/secret rendering — so a no-op/neutered program (no output, or wrong output) FAILS here.
# It never builds; it only runs the pre-built launcher.
#
# Anti-reward-hack note: run-cli lives at /mayhem (a NON-system path), so the verify-repo sabotage
# neuter (_exit(0) on non-system exes) trips it -> empty output -> assertions fail -> detected.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

CLI="$SRC/run-cli"
EXPORT="$SRC/example_export.txt"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASS=0; FAIL=0
check() { # check <name> <condition-rc>
  if [ "$2" -eq 0 ]; then echo "PASS: $1"; PASS=$((PASS+1)); else echo "FAIL: $1"; FAIL=$((FAIL+1)); fi
}

if [ ! -x "$CLI" ]; then
  echo "missing $CLI — run mayhem/build.sh first" >&2
  emit_ctrf "extract-otp-secrets-knownanswer" 0 1 0; exit 2
fi
if [ ! -f "$EXPORT" ]; then
  echo "missing $EXPORT" >&2
  emit_ctrf "extract-otp-secrets-knownanswer" 0 1 0; exit 2
fi

echo "=== running CLI on example_export.txt (CSV to stdout) ==="
CSV="$("$CLI" "$EXPORT" --csv - -q 2>/dev/null)"
echo "$CSV" | head -3

# Known answers documented in the project's example_output.csv.
grep -qE '^name,secret,issuer,type,counter,url' <<<"$CSV"; check "CSV header is present" $?
grep -q '7KSQL2JTUDIS5EF65KLMRQIIGY' <<<"$CSV";          check "decoded TOTP secret matches" $?
grep -q 'raspberrypi' <<<"$CSV";                          check "issuer 'raspberrypi' decoded" $?
grep -q ',hotp,4,' <<<"$CSV";                             check "HOTP entry with counter=4 decoded" $?
# Exactly the documented number of OTP rows (6) — guards against truncated/over-parsed output.
rows="$(grep -c '7KSQL2JTUDIS5EF65KLMRQIIGY' <<<"$CSV" || true)"
[ "${rows:-0}" -eq 6 ]; check "all 6 example OTP rows decoded (got ${rows:-0})" $?

echo "=== running CLI on example_export.txt (JSON to stdout) ==="
JSON="$("$CLI" "$EXPORT" --json - -q 2>/dev/null)"
grep -q '"secret": "7KSQL2JTUDIS5EF65KLMRQIIGY"' <<<"$JSON"; check "JSON output carries the secret" $?

emit_ctrf "extract-otp-secrets-knownanswer" "$PASS" "$FAIL" 0
