#!/usr/bin/env python3

import atheris
import binascii
import contextlib
import fileinput
import google.protobuf.message
import io
import logging
import os
import random
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


# Patch the source code to use a version of fileinput that doesn't rely on global state
# Makes this program fuzzable
fileinput.input = fileinput.FileInput

# Since this isn't a module, we must inject the parent directory into the import path
source_dir = Path(os.path.dirname(os.path.abspath(__file__))).parent.absolute()
sys.path.insert(1, str(source_dir))

with atheris.instrument_imports():
    import extract_otp_secret_keys
    from extract_otp_secret_keys import extract_otps

# No logging
logging.disable(logging.CRITICAL)

# Another patch needed to initialize global variables
try:
    extract_otp_secret_keys.main(['infile'])
except Exception:
    pass

@contextlib.contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

@dataclass
class FakeArgObject:
    infile: str
    json: bool
    csv: bool
    printqr: bool
    saveqr: bool
    verbose: bool
    quiet: bool

# Build fake object to bypass argparse
fake_args = FakeArgObject('uninit', False, False, False, False, False, True)

@atheris.instrument_func
def raise_sometimes(e, percent: int):
    """
    Optionally raise an exception by a percentile
    """
    if random.randint(0, 100) <= percent:
        raise e
@atheris.instrument_func
def TestOneInput(data):
    data = data.decode('utf-8', errors='ignore').encode()

    try:
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.seek(0)
            f.flush()
            fake_args.infile = f.name
            with nostdout():
                extract_otps(fake_args)
    except binascii.Error:
        return -1
    except ValueError as e:
        if 'bad query' in str(e):
            # This is raised too often to even be fuzzable, as urllib exceptions were not caught by the target
            return -1
        raise_sometimes(e, 1)
    except SystemExit:
        # The program exits with 1 if it can't find any OTPs, which is expected
        return -1
    except Exception as e:
        raise_sometimes(e, 1)

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
