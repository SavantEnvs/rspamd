#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

BUILD="$SRC/mayhem/build-test"
TESTBIN="$BUILD/test/rspamd-test-cxx"
RSPAMADM="$BUILD/src/rspamadm/rspamadm"
for b in "$TESTBIN" "$RSPAMADM"; do
  [ -x "$b" ] || { echo "missing $b — mayhem/build.sh should have built it" >&2; emit_ctrf "rspamd" 0 1 0; exit 1; }
done

# 1) rspamd's own C++ unit suite (doctest): parse the per-test-case summary.
out="$(mktemp)"
(cd "$BUILD/test" && "$TESTBIN" >"$out" 2>&1)
rc=$?
tail -5 "$out"
line="$(grep -E '^\[doctest\] test cases:' "$out" | tail -1)"
passed=0; failed=0; skipped=0
if [ -n "$line" ]; then
  passed="$(echo "$line"  | sed -E 's/.*\| *([0-9]+) passed.*/\1/')"
  failed="$(echo "$line"  | sed -E 's/.*\| *([0-9]+) failed.*/\1/')"
  skipped="$(echo "$line" | sed -E 's/.*\| *([0-9]+) skipped.*/\1/')"
else
  failed=1
fi
# a non-zero exit with a clean summary is still a failure; a summary with zero passes is not a pass
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
[ "$passed" -gt 100 ] || failed=$(( failed + 1 ))
rm -f "$out"

# 2) known-answer probes through the built rspamadm (the sabotage shim makes every binary exit 0 without
#    output, so each probe compares the real output against a known value).
export LUA_PATH="$SRC/lualib/?.lua;$SRC/lualib/?/?.lua;$SRC/lualib/?/init.lua"
probe() {  # probe <name> <expected> <lua expression printing one value>
  local name="$1" want="$2" lua="$3" got
  got="$("$RSPAMADM" lua -e "$lua" 2>/dev/null | tail -1)"
  if [ "$got" = "$want" ]; then
    passed=$(( passed + 1 ))
  else
    echo "PROBE FAIL $name: want '$want' got '$got'" >&2
    failed=$(( failed + 1 ))
  fi
}
probe sha256-abc ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  'local h=require "rspamd_cryptobox_hash"; print(h.create_specific("sha256"):update("abc"):hex())'
probe blake2b-empty 786a02f742015903c6c6fd852552d272 \
  'local h=require "rspamd_cryptobox_hash"; print(h.create_specific("blake2"):update(""):hex():sub(1,32))'
probe base64 aGVsbG8= 'print(require("rspamd_util").encode_base64("hello"))'
probe mail-address "foo@Example.COM|Foo Bar|Example.COM" \
  'local a=require("rspamd_util").parse_mail_address("Foo Bar <foo@Example.COM>"); print(a[1].addr.."|"..a[1].name.."|"..a[1].domain)'

emit_ctrf "rspamd-test-cxx+rspamadm" "$passed" "$failed" "$skipped"
