#!/usr/bin/env bash
#
# extract_otp_secret_keys/mayhem/build.sh — build the Atheris fuzz target for scito/extract_otp_secrets.
#
# This is a PYTHON (Atheris/libFuzzer) project, so the "build" is:
#   1) install the Python runtime deps + atheris, OFFLINE, from the wheelhouse the Dockerfile baked
#      into /opt/toolchains/python/wheelhouse (air-gapped, re-runnable — SPEC §6.5);
#   2) compile a tiny ELF launcher (launcher.c) so the Mayhem target `cmd` is a native executable
#      (Mayhem rejects script targets; fuzz-smoke checks the ELF magic). The launcher exec's
#      `python3 mayhem/fuzz_extract.py "$@"`, forwarding libFuzzer flags to Atheris.
#        - /mayhem/fuzz_extract             : the Mayhem libFuzzer target (Atheris iterates).
#        - /mayhem/fuzz_extract-standalone  : run-once reproducer (Atheris replays one file arg).
#        - /mayhem/run-cli                  : the CLI runner mayhem/test.sh uses as its oracle.
#
# NOTE on sanitizers: the fuzzed code is Python; coverage/instrumentation come from Atheris
# (atheris.instrument_imports), not from clang $SANITIZER_FLAGS — those apply to native C/C++ code,
# of which this project has none. We still thread $SANITIZER_FLAGS/$DEBUG_FLAGS into the launcher
# compile so the spec's debug-info contract (DWARF < 4) holds on every emitted ELF.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= builds without sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem triage can read symbols (clang-19's plain -g emits DWARF-5).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${SRC:=/mayhem}"
: "${WHEELHOUSE:=/opt/toolchains/python/wheelhouse}"
export SANITIZER_FLAGS DEBUG_FLAGS CC SRC WHEELHOUSE
OUT=/mayhem

cd "$SRC"

# ── 1) Python deps — OFFLINE from the baked wheelhouse (idempotent; "already satisfied" on re-run) ──
PYREQ=(atheris colorama qrcode protobuf opencv-contrib-python-headless numpy Pillow)
if [ -d "$WHEELHOUSE" ]; then
  python3 -m pip install --user --break-system-packages --no-index --find-links "$WHEELHOUSE" "${PYREQ[@]}"
else
  # First build only (no wheelhouse yet): allow the network. The Dockerfile bakes the wheelhouse so
  # the air-gapped PATCH re-run takes the --no-index branch above.
  python3 -m pip install --user --break-system-packages "${PYREQ[@]}"
fi

# Sanity: the harnessed module must import (graceful pyzbar/qreader fallback is expected/desired —
# the QR-image path is out of scope; the text-export parser is what we fuzz).
PYTHONPATH="$SRC/src" python3 -c 'import atheris, extract_otp_secrets' \
  || { echo "FATAL: extract_otp_secrets failed to import" >&2; exit 1; }

# ── 2) Native ELF launchers ─────────────────────────────────────────────────────────────────────
# Sanitizing a 30-line exec shim is pointless (and would drag the ASan runtime into the python child),
# so the launcher is built WITHOUT $SANITIZER_FLAGS but WITH $DEBUG_FLAGS (DWARF-3) to satisfy the
# debug-info contract. The Python code itself is instrumented by Atheris.
"$CC" $DEBUG_FLAGS -O1 \
    -DHARNESS_PATH="\"$SRC/mayhem/fuzz_extract.py\"" \
    -o "$OUT/fuzz_extract" "$SRC/mayhem/launcher.c"

# Standalone run-once reproducer: same binary (Atheris replays a single file argument).
cp -f "$OUT/fuzz_extract" "$OUT/fuzz_extract-standalone"

# CLI runner for the test oracle: exec's the real extract_otp_secrets CLI. Because it lives at a
# NON-system path, the anti-reward-hack neuter (LD_PRELOAD _exit(0) on non-system exes) trips it,
# making mayhem/test.sh a genuinely behavioral oracle.
"$CC" $DEBUG_FLAGS -O1 \
    -DHARNESS_PATH="\"$SRC/src/extract_otp_secrets.py\"" \
    -o "$OUT/run-cli" "$SRC/mayhem/launcher.c"

echo "build.sh complete:"
ls -la "$OUT/fuzz_extract" "$OUT/fuzz_extract-standalone" "$OUT/run-cli"
