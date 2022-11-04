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
fileinput.input = lambda x: x

# Since this isn't a module, we must inject the parent directory into the import path
source_dir = Path(os.path.dirname(os.path.abspath(__file__))).parent.absolute()
sys.path.insert(1, str(source_dir))

# with atheris.instrument_imports():
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
    infile: object
    json: bool
    csv: bool
    printqr: bool
    saveqr: bool
    verbose: bool
    quiet: bool

# Build fake object to bypass argparse
fake_args = FakeArgObject('uninit', False, False, False, False, False, True)

@atheris.instrument_func
def raise_sometimes(e):
    """
    Optionally raise an exception by a percentile
    """
    if random.getrandbits(4) == 0:
        raise e

@atheris.instrument_func
def TestOneInput(data):
    data = data.decode('utf-8', errors='ignore')

    try:
        with io.StringIO(data) as f:
            fake_args.infile = f
            with nostdout():
                extract_otps(fake_args)
    except SystemExit:
        # The program exits with 1 if it can't find any OTPs, which is expected
        return -1
    except Exception as e:
        raise_sometimes(e)

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
