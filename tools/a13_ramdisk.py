#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate and inspect stock D431 ramdisk inputs; never boot or modify them."""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys

MANIFEST_SHA256 = "e6700d332f009faf1d31823a541cdeabdea7a114e56821d67c2e2e065124a445"


def check_inputs(directory):
    manifest, = Path(directory).rglob("BuildManifest.plist")
    data = manifest.read_bytes()
    if hashlib.sha256(data).hexdigest() != MANIFEST_SHA256:
        raise ValueError("Unexpected Apple BuildManifest SHA-256")
    info = plistlib.loads(data)
    if (info["ProductVersion"], info["ProductBuildVersion"]) != ("18.7.8", "22H352"):
        raise ValueError("Expected iOS 18.7.8 / 22H352")
    if "iPhone12,5" not in info["SupportedProductTypes"]:
        raise ValueError("Manifest does not support iPhone12,5")
    identity, = [b for b in info["BuildIdentities"]
                 if b["Info"]["DeviceClass"] == "d431ap"]
    if (int(identity["ApChipID"], 0), int(identity["ApBoardID"], 0)) != (0x8030, 2):
        raise ValueError("Expected D431 chip 0x8030 / board 0x02")
    ramdisk, = Path(directory).rglob("arm64eSURamDisk.dmg")
    return ramdisk.resolve()


def inspect_image(mountpoint, output):
    root = Path(mountpoint).resolve()
    out = Path(output).resolve()
    if out == root or root in out.parents:
        raise ValueError("Inspection output must be outside mounted image")
    out.mkdir(parents=True, exist_ok=True)
    inventory = []

    def unreadable(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        dirs.sort()
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root)
            entry = {"path": relative.as_posix()}
            if path.is_symlink():
                entry["symlink"] = os.readlink(path)
            else:
                stat = path.stat()
                entry.update(mode=oct(stat.st_mode), uid=stat.st_uid,
                             gid=stat.st_gid, size=stat.st_size)
                if path.is_file() and ("LaunchDaemons" in relative.parts
                                       or "APFS.framework" in relative.parts
                                       or name in ("SystemVersion.plist", "rc", "fstab", "launchd.conf")):
                    destination = out / "files" / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, destination)
            inventory.append(entry)
    (out / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "check":
        print(check_inputs(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "inspect":
        inspect_image(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: a13_ramdisk.py check INPUTS | inspect MOUNTPOINT OUTPUT")
