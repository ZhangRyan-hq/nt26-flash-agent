#!/usr/bin/env python3
"""Offline dependency and distribution checks; never enumerate/open devices."""
import hashlib
import importlib
import json
import platform
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def integrity():
    checked = 0
    failures = []
    seen = set()
    try:
        lines = (ROOT / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        if not lines:
            raise ValueError("Empty checksum manifest")
        for line in lines:
            digest, separator, name = line.partition("  ")
            relative = Path(name)
            if (not separator or len(digest) != 64 or
                    any(c not in "0123456789abcdef" for c in digest) or
                    not name or relative.is_absolute() or ".." in relative.parts or
                    name in seen):
                raise ValueError("Invalid checksum manifest entry")
            seen.add(name)
            target = ROOT / relative
            try:
                if not target.resolve().is_relative_to(ROOT):
                    raise ValueError("File resolves outside package")
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                if actual != digest:
                    failures.append({"file": name, "error": "sha256_mismatch"})
            except (OSError, ValueError) as exc:
                failures.append({"file": name, "error": str(exc)})
            checked += 1
        for required in ("SKILL.md", "agent-tool.json", "scripts/nt26-flash",
                         "tool/nt26flash/__main__.py",
                         "tool/assets/ec718pm-agentboot-usb.bin"):
            if required not in seen:
                failures.append({"file": required, "error": "not_in_manifest"})
    except (OSError, ValueError) as exc:
        failures.append({"file": "SHA256SUMS", "error": str(exc)})
    return {"ok": not failures, "files_checked": checked, "failures": failures}


def main():
    python_ok = sys.version_info >= (3, 10)
    linux_ok = sys.platform.startswith("linux")
    serial_check = {"ok": False, "required": "3.5", "version": None}
    try:
        serial = importlib.import_module("serial")
        serial_check["version"] = getattr(serial, "VERSION", None)
        serial_check["ok"] = serial_check["version"] == "3.5" and hasattr(serial, "Serial")
    except ImportError as exc:
        serial_check["error"] = str(exc)
    files = integrity() if python_ok else {
        "ok": False, "files_checked": 0, "failures": [{"error": "Python 3.10+ required"}]}
    offline_ready = python_ok and files["ok"]
    hardware_dependencies_ready = offline_ready and linux_ok and serial_check["ok"]
    result = {
        "package_root": str(ROOT),
        "python": {"version": platform.python_version(), "ok": python_ok},
        "linux": linux_ok,
        "pyserial": serial_check,
        "integrity": files,
        "ready_offline": offline_ready,
        "ready_hardware_dependencies": hardware_dependencies_ready,
        "hardware_access_tested": False,
        "serial_ports_opened": False,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if hardware_dependencies_ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
