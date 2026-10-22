#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline tests for the exact D431/22H352 iBEC kernel-gate patch."""

import hashlib
from unittest.mock import patch

import a13_ibec_kernel_gate as gate


def expect_value_error(callable_):
    try:
        callable_()
    except ValueError:
        return
    raise AssertionError("invalid input accepted")


def test_a13_ibec_kernel_gate():
    prefix = b"guarded-prefix"
    suffix = b"guarded-suffix"
    context_offset = len(prefix)
    patch_offset = context_offset + 4
    before = b"\x33\x01\xf8\x36"
    after = b"\x09\x00\x00\x14"
    context = b"keep" + before + b"cleanup"
    source = prefix + context + suffix
    expected = bytearray(source)
    expected[patch_offset:patch_offset + 4] = after
    expected = bytes(expected)

    values = {
        "SOURCE_SIZE": len(source),
        "SOURCE_SHA256": hashlib.sha256(source).hexdigest(),
        "OUTPUT_SHA256": hashlib.sha256(expected).hexdigest(),
        "CONTEXT_OFFSET": context_offset,
        "CONTEXT": context,
        "PATCH_OFFSET": patch_offset,
        "BEFORE": before,
        "AFTER": after,
    }
    with patch.multiple(gate, **values):
        assert gate.patch_ibec(source) == expected
        expect_value_error(lambda: gate.patch_ibec(source[:-1]))
        corrupt = bytearray(source)
        corrupt[-1] ^= 1
        expect_value_error(lambda: gate.patch_ibec(bytes(corrupt)))

    # A matching whole-file hash is not enough if the audited local context is wrong.
    wrong_context = bytearray(source)
    wrong_context[context_offset] ^= 1
    wrong_context = bytes(wrong_context)
    values["SOURCE_SHA256"] = hashlib.sha256(wrong_context).hexdigest()
    with patch.multiple(gate, **values):
        expect_value_error(lambda: gate.patch_ibec(wrong_context))


if __name__ == "__main__":
    test_a13_ibec_kernel_gate()
    print("PASS: exact source, context, instruction and output guards")
