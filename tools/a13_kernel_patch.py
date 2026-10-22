#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Patch the audited iOS 18.7.8 / 22H352 D431 kernel and emit an img4 bpatch."""

import argparse
import hashlib
import os
from pathlib import Path
import tempfile


SOURCE_SIZE = 60_522_496
SOURCE_SHA256 = "e38e65d8b8e31d693bad81e83221ed6453355974639118ae409056017d6fdda9"
OUTPUT_SHA256 = "1ad58e767de00f947d139c6993aeab3d9658376c92a0f75176e3f3d69a6b383b"
PATCHES = (
    (0x02271890, bytes.fromhex("7f 23 03 d5"), bytes.fromhex("20 00 80 d2")),
    (0x02271894, bytes.fromhex("ff c3 00 d1"), bytes.fromhex("42 00 00 b4")),
    (0x02271898, bytes.fromhex("f4 4f 01 a9"), bytes.fromhex("40 00 00 f9")),
    (0x0227189C, bytes.fromhex("fd 7b 02 a9"), bytes.fromhex("c0 03 5f d6")),
    (0x025DA02C, bytes.fromhex("5f 24 03 d5"), bytes.fromhex("20 00 80 52")),
    (0x025DA030, bytes.fromhex("48 95 00 d0"), bytes.fromhex("ff 0f 5f d6")),
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
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


def patch_kernel(source):
    if len(source) != SOURCE_SIZE:
        raise ValueError(f"unexpected kernel size: {len(source)}")
    actual = sha256(source)
    if actual != SOURCE_SHA256:
        raise ValueError(f"unexpected stock kernel SHA-256: {actual}")

    output = bytearray(source)
    bpatch = []
    for offset, old, new in PATCHES:
        if source[offset:offset + len(old)] != old:
            raise ValueError(f"unexpected bytes at kernel offset 0x{offset:x}")
        output[offset:offset + len(new)] = new
        bpatch.extend(f"{offset + i:#x} 0x{before:02x} 0x{after:02x}"
                      for i, (before, after) in enumerate(zip(old, new)))

    result = bytes(output)
    if sha256(result) != OUTPUT_SHA256:
        raise AssertionError("patched kernel SHA-256 differs from audited output")
    return result, ("\n".join(bpatch) + "\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("patched", type=Path)
    parser.add_argument("bpatch", type=Path)
    args = parser.parse_args()
    raw = args.source.read_bytes()
    patched, diff = patch_kernel(raw)
    atomic_write(args.patched, patched)
    atomic_write(args.bpatch, diff)
    print(f"stock sha256={sha256(raw)}")
    print(f"patched sha256={sha256(patched)}")
    print(f"img4 patch bytes={sum(len(old) for _, old, _ in PATCHES)}")


if __name__ == "__main__":
    main()
