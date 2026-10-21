#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate D431 inputs and prepare a runner-local UART image; never boot it."""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys

MANIFEST_SHA256 = "e6700d332f009faf1d31823a541cdeabdea7a114e56821d67c2e2e065124a445"
RAMROD_SHA256 = "1567833fcb826947da3df6249e214f0feefa032d208249497f00a1c579e508fd"
PROBE_JOB = {
    "Label": "local.a13-uart-probe",
    "ProgramArguments": ["/usr/local/bin/a13-uart-probe"],
    "RunAtLoad": True,
    "UserName": "root",
    "StandardInPath": "/dev/null",
    "StandardOutPath": "/dev/console",
    "StandardErrorPath": "/dev/console",
    "Umask": 0o077,
}


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


def prepare_image(mountpoint, probe):
    root = Path(mountpoint).resolve()
    if os.geteuid() != 0 or root == Path("/") or not root.is_mount():
        raise ValueError("Preparation requires root and a separate mounted image")
    jobs = root / "System/Library/LaunchDaemons"
    disabled = jobs.with_name("LaunchDaemons.stock-disabled")
    bindir = root / "usr/local/bin"
    binary = bindir / "a13-uart-probe"
    version = root / "System/Library/CoreServices/SystemVersion.plist"
    for path in (jobs, disabled, bindir, binary, version):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError(f"Unsafe image path: {path}")
    info = plistlib.loads(version.read_bytes())
    if (info["ProductName"], info["ProductVersion"], info["ProductBuildVersion"]) != (
            "iPhone OS", "18.7.8", "22H352"):
        raise ValueError("Unexpected restore-root version")
    ramrod = jobs / "com.apple.ramrod.plist"
    if ramrod.is_symlink() or hashlib.sha256(ramrod.read_bytes()).hexdigest() != RAMROD_SHA256 or disabled.exists():
        raise ValueError("Expected unmodified stock ramrod launch job")
    data = Path(probe).read_bytes()
    if len(data) < 32 or data[:8] != bytes.fromhex("cffaedfe0c000001"):
        raise ValueError("Probe must be a 64-bit ARM Mach-O executable")
    names = sorted(p.name for p in jobs.iterdir())
    jobs.rename(disabled)
    jobs.mkdir(mode=0o755)
    bindir.mkdir(parents=True, exist_ok=True)
    os.chown(jobs, 0, 0)
    os.chown(bindir, 0, 0)
    # shortcut: use stock image free space; grow only if installation reports ENOSPC.
    binary.write_bytes(data)
    binary.chmod(0o755)
    os.chown(binary, 0, 0)
    job = jobs / "local.a13-uart-probe.plist"
    job.write_bytes(plistlib.dumps(PROBE_JOB))
    job.chmod(0o644)
    os.chown(job, 0, 0)
    print("Disabled stock launch jobs:", ", ".join(names))
    verify_image(root, probe)


def verify_image(mountpoint, probe):
    root = Path(mountpoint).resolve()
    jobs = root / "System/Library/LaunchDaemons"
    if sorted(p.name for p in jobs.iterdir()) != ["local.a13-uart-probe.plist"]:
        raise ValueError("Unexpected active launch job")
    job = jobs / "local.a13-uart-probe.plist"
    if plistlib.loads(job.read_bytes()) != PROBE_JOB or job.stat().st_mode & 0o777 != 0o644:
        raise ValueError("Unexpected probe launch configuration")
    binary = root / "usr/local/bin/a13-uart-probe"
    if binary.read_bytes() != Path(probe).read_bytes() or binary.stat().st_mode & 0o777 != 0o755:
        raise ValueError("Installed probe differs from signed build")
    disabled = jobs.with_name("LaunchDaemons.stock-disabled") / "com.apple.ramrod.plist"
    if hashlib.sha256(disabled.read_bytes()).hexdigest() != RAMROD_SHA256:
        raise ValueError("Disabled stock launch job missing or changed")
    print("PASS: only fixed UART probe active; stock ramrod job preserved but disabled")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "check":
        print(check_inputs(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "inspect":
        inspect_image(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "prepare":
        prepare_image(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "verify":
        verify_image(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: a13_ramdisk.py check INPUTS | inspect MOUNT OUTPUT | prepare/verify MOUNT PROBE")
