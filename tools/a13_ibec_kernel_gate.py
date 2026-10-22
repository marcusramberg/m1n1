#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Apply the one-word D431/22H352 inner kernel-validation bypass."""

import argparse
import hashlib
import os
from pathlib import Path
import tempfile


SOURCE_SIZE = 2_658_672
SOURCE_SHA256 = "7bf59a1ed8ccbad0614f4c2090916f5578b281e8251a63a1b36fe747384d36d0"
OUTPUT_SHA256 = "60ec93712f8bdd1796c6cb871724e066c0890eb859bb0e050dc1e532bfdb9592"
PATCH_OFFSET = 0x640D8
BEFORE = bytes.fromhex("33 01 f8 36")  # tbz w19, #31, 0x640fc
AFTER = bytes.fromhex("09 00 00 14")   # b 0x640fc
CONTEXT_OFFSET = 0x640A0
CONTEXT = bytes.fromhex(
    "f1 03 00 b9 e0 03 1c aa 71 fd ff 97 f3 03 00 aa "
    "e0 03 1c aa e1 03 19 aa e2 03 1a aa e3 03 1b aa "
    "17 00 00 94 a0 89 89 52 20 c9 a7 72 01 00 80 52 "
    "42 22 01 94 00 00 80 52 33 01 f8 36 60 05 00 90 "
    "00 00 06 91 63 04 00 f0 63 60 08 91 02 44 00 91 "
    "e1 03 00 aa f9 ad 01 94 00 00 80 12 fd 7b 50 a9 "
    "f4 4f 4f a9"
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patch_ibec(source):
    """Return the patched bytes, rejecting anything but the exact audited input."""
    if len(source) != SOURCE_SIZE:
        raise ValueError(f"unexpected source size: {len(source)}")
    actual = digest(source)
    if actual != SOURCE_SHA256:
        raise ValueError(f"unexpected source SHA-256: {actual}")
    if source[CONTEXT_OFFSET:CONTEXT_OFFSET + len(CONTEXT)] != CONTEXT:
        raise ValueError("audited validation context differs")
    if source[PATCH_OFFSET:PATCH_OFFSET + len(BEFORE)] != BEFORE:
        raise ValueError("audited branch instruction differs")

    output = bytearray(source)
    output[PATCH_OFFSET:PATCH_OFFSET + len(AFTER)] = AFTER
    output = bytes(output)
    changed = [index for index, pair in enumerate(zip(source, output))
               if pair[0] != pair[1]]
    expected_changed = [PATCH_OFFSET + index for index, pair in enumerate(zip(BEFORE, AFTER))
                        if pair[0] != pair[1]]
    if changed != expected_changed:
        raise AssertionError("output contains changes outside the audited instruction")
    if OUTPUT_SHA256 is not None and digest(output) != OUTPUT_SHA256:
        raise AssertionError("derived output SHA-256 differs")
    return output


def write_atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    source = arguments.source.read_bytes()
    output = patch_ibec(source)
    write_atomic(arguments.output, output)
    print(f"source sha256={digest(source)}")
    print(f"output sha256={digest(output)}")
    print(f"patched 0x{PATCH_OFFSET:x}: {BEFORE.hex()} -> {AFTER.hex()}")


if __name__ == "__main__":
    main()
