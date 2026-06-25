#!/usr/bin/env python3
#
# Atheris harness for scito/extract_otp_secrets.
#
# Fuzzed surface: the text-input parser pipeline `main([file]) -> extract_otps ->
# extract_otps_from_files -> get_otp_urls_from_file -> get_payload_from_otp_url`, i.e. the
# `otpauth-migration://offline?data=<base64 proto>` line parser: URL parsing, base64 decode and
# the protobuf `MigrationPayload` deserializer — the code that consumes attacker-controlled export
# files. Camera/QR-image decoding (cv2/qreader) is NOT exercised (needs a webcam / image).
#
# Upstream renamed the project extract_otp_secret_keys -> extract_otp_secrets and moved the module
# to src/extract_otp_secrets.py; this harness imports the current module name.
import atheris
import contextlib
import io
import logging
import os
import sys
import tempfile
from pathlib import Path

# The module lives in src/ — make it importable.
SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

with atheris.instrument_imports():
    import extract_otp_secrets as eos  # noqa: E402

# Silence the tool's logging/prints during fuzzing.
logging.disable(logging.CRITICAL)


@contextlib.contextmanager
def _muted():
    save_out, save_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    try:
        yield
    finally:
        sys.stdout, sys.stderr = save_out, save_err


# Reuse one scratch file per process to avoid churn.
_fd, _INFILE = tempfile.mkstemp(suffix=".txt")
os.close(_fd)


def _cleanup():
    try:
        os.unlink(_INFILE)
    except OSError:
        pass


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    with open(_INFILE, "wb") as f:
        f.write(data)
    try:
        with _muted():
            # --csv /dev/null so the write path runs without creating artifacts; -q stays quiet.
            eos.main([_INFILE, "-q", "--csv", os.devnull])
    except SystemExit:
        # The tool exits 1 when no OTPs are found — expected for most inputs.
        return
    except (ValueError, OSError, UnicodeError):
        # base64 / decode / IO errors on malformed input are not bugs in the harnessed parser.
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    try:
        atheris.Fuzz()
    finally:
        _cleanup()


if __name__ == "__main__":
    main()
