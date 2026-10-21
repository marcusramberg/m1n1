#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline checks with synthetic files; no Apple tools, mounts or network."""

import hashlib
import json
from pathlib import Path
import plistlib
import tempfile

import a13_ramdisk


def test_a13_ramdisk():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        inputs = root / "inputs"
        inputs.mkdir()
        ramdisk = inputs / "arm64eSURamDisk.dmg"
        ramdisk.write_bytes(b"test image, not bootable")
        original_digest = a13_ramdisk.MANIFEST_SHA256
        for version, build, product, model, chip, board, valid in [
            ("18.7.8", "22H352", "iPhone12,5", "d431ap", "0x8030", "0x02", True),
            ("18.6.2", "22H352", "iPhone12,5", "d431ap", "0x8030", "0x02", False),
            ("18.7.8", "22H355", "iPhone12,5", "d431ap", "0x8030", "0x02", False),
            ("18.7.8", "22H352", "iPhone12,3", "d431ap", "0x8030", "0x02", False),
            ("18.7.8", "22H352", "iPhone12,5", "d421ap", "0x8030", "0x02", False),
            ("18.7.8", "22H352", "iPhone12,5", "d431ap", "0x8020", "0x02", False),
            ("18.7.8", "22H352", "iPhone12,5", "d431ap", "0x8030", "0x04", False),
        ]:
            data = plistlib.dumps({
                "ProductVersion": version, "ProductBuildVersion": build,
                "SupportedProductTypes": [product],
                "BuildIdentities": [{"Info": {"DeviceClass": model},
                                     "ApChipID": chip, "ApBoardID": board}],
            })
            # Synthetic fixture digest only; no production override is exposed by the CLI.
            a13_ramdisk.MANIFEST_SHA256 = hashlib.sha256(data).hexdigest()
            (inputs / "BuildManifest.plist").write_bytes(data)
            try:
                result = a13_ramdisk.check_inputs(inputs)
            except ValueError:
                assert not valid
            else:
                assert valid and result == ramdisk.resolve()
        a13_ramdisk.MANIFEST_SHA256 = "0" * 64
        try:
            a13_ramdisk.check_inputs(inputs)
        except ValueError as error:
            assert "SHA-256" in str(error)
        else:
            raise AssertionError("Bad manifest hash accepted")
        a13_ramdisk.MANIFEST_SHA256 = original_digest

        image = root / "image"
        daemons = image / "System/Library/LaunchDaemons"
        daemons.mkdir(parents=True)
        (daemons / "local.plist").write_bytes(b"stock plist")
        outside = root / "outside.plist"
        outside.write_bytes(b"must not be copied")
        (daemons / "external.plist").symlink_to(outside)
        (image / "linked-directory").symlink_to(root, target_is_directory=True)
        output = root / "inspection"
        a13_ramdisk.inspect_image(image, output)
        assert (output / "files/System/Library/LaunchDaemons/local.plist").read_bytes() == b"stock plist"
        assert not (output / "files/System/Library/LaunchDaemons/external.plist").exists()
        inventory = json.loads((output / "inventory.json").read_text())
        assert any(x.get("symlink") == str(outside) for x in inventory)
        assert (daemons / "local.plist").read_bytes() == b"stock plist"
        try:
            a13_ramdisk.inspect_image(image, image / "output")
        except ValueError:
            pass
        else:
            raise AssertionError("Inspection output inside source accepted")


if __name__ == "__main__":
    test_a13_ramdisk()
    print("PASS: target/hash rejection, read-only copying and symlink isolation")
