#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify native IMG4 repack preserves the audited D431 kernel and ticket."""

import hashlib
from pathlib import Path
import sys

from pyimg4 import IMG4, IM4P, IM4M


def digest(data):
    return hashlib.sha256(data).hexdigest()


def properties(im4p):
    return [(item.fourcc, item.value) for item in (im4p.properties or [])]


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: a13_img4_verify.py STOCK.im4p OUTPUT.img4 PATCHED.raw IM4M")
    stock_path, output_path, raw_path, manifest_path = map(Path, sys.argv[1:])
    stock = IM4P(stock_path.read_bytes())
    wrapped = IMG4(output_path.read_bytes())
    expected_raw = raw_path.read_bytes()
    manifest = IM4M(manifest_path.read_bytes())

    if stock.fourcc != "rkrn" or wrapped.im4p.fourcc != "rkrn":
        raise ValueError("kernel payload type changed")
    if stock.description != wrapped.im4p.description:
        raise ValueError("kernel description changed")
    if properties(stock) != properties(wrapped.im4p):
        raise ValueError("kernel PAYP properties changed")
    if wrapped.im4m.output() != manifest.output():
        raise ValueError("IMG4 manifest differs from the pinned input ticket")

    wrapped.im4p.payload.decompress()
    actual_raw = wrapped.im4p.payload.data
    if actual_raw != expected_raw:
        raise ValueError("native IMG4 payload differs from patched raw kernel")
    if digest(actual_raw) != "1ad58e767de00f947d139c6993aeab3d9658376c92a0f75176e3f3d69a6b383b":
        raise ValueError("unexpected patched kernel hash")

    print(f"PASS: native IMG4, 8 PAYP properties, ticket and payload sha256={digest(actual_raw)}")


if __name__ == "__main__":
    main()
