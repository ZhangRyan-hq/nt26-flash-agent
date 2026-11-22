"""Strict, offline reader for the observed NT26F6D0 F6D_A binpkg profile.

This module never opens hardware or extracts package-provided filenames.
SHA256 checks detect payload damage; they are not firmware authentication.
Unknown container variants and other EC718PM memory layouts fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct


PRODUCT = "EC718PM_PRD"
FLASH_BASE = 0x800000
FLASH_SIZE = 0x400000
MAX_PACKAGE_SIZE = FLASH_SIZE + 0x10000
SECTOR_SIZE = 0x1000

# Linear load addresses and allocated capacities, independently confirmed in
# the shipped demo and the user's F6D_A OpenKit/CloudScreen/build outputs.
LAYOUT = {
    "BL": (0x803000, 0x16000),
    "AP": (0x882000, 0x1BC000),
    "CP": (0x81E000, 0x64000),
    "PKGFLXAPP": (0xA56000, 0xCB000),
}
TAG_ORDER = tuple(LAYOUT)


class PackageError(ValueError):
    """Unsupported or internally inconsistent firmware package."""


@dataclass(frozen=True)
class PackageEntry:
    tag: str
    name: str
    address: int
    flash_size: int
    data: bytes
    payload_sha256: str


@dataclass(frozen=True)
class Package:
    product: str
    sha256: str
    entries: tuple[PackageEntry, ...]


def _text(field: bytes, label: str) -> str:
    """Accept only the NUL-terminated, zero-padded ASCII fields observed."""
    first, separator, padding = field.partition(b"\0")
    if not separator or any(padding):
        raise PackageError(f"Invalid {label} padding")
    try:
        result = first.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PackageError(f"Non-ASCII {label}") from exc
    if not result:
        raise PackageError(f"Empty {label}")
    return result


def _validate_entries(entries: tuple[PackageEntry, ...]) -> None:
    tags = tuple(entry.tag for entry in entries)
    if tags not in (TAG_ORDER[:3], TAG_ORDER):
        raise PackageError("Expected BL, AP, CP and optional PKGFLXAPP in package order")
    names = set()
    ranges = []
    for entry in entries:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", entry.name) or entry.name in (".", ".."):
            raise PackageError("Unsafe or unsupported image name")
        if entry.name in names:
            raise PackageError("Duplicate image name")
        names.add(entry.name)
        if not isinstance(entry.data, bytes):
            raise PackageError("Image payload must be immutable bytes")
        if not 0 < len(entry.data) <= entry.flash_size:
            raise PackageError("Image length exceeds capacity or is zero")
        if entry.tag in ("BL", "AP", "CP") and len(entry.data) != entry.flash_size:
            raise PackageError("Incomplete fixed-size F6D_A base image")
        offset = entry.address - FLASH_BASE
        end = offset + entry.flash_size
        if offset < 0 or end > FLASH_SIZE or offset % SECTOR_SIZE or entry.flash_size % SECTOR_SIZE:
            raise PackageError("Image range is outside or unaligned to internal flash")
        if any(offset < stop and start < end for start, stop in ranges):
            raise PackageError("Image capacity ranges overlap")
        ranges.append((offset, end))
        if (entry.address, entry.flash_size) != LAYOUT[entry.tag]:
            raise PackageError(f"Unsupported F6D_A layout for {entry.tag}")
        if hashlib.sha256(entry.data).hexdigest() != entry.payload_sha256:
            raise PackageError(f"SHA256 mismatch for {entry.name}")


def parse_package(path: str | Path) -> Package:
    """Read and verify one supported package without touching the device.

    The 52-byte header is followed by three 140-byte parameter records. Each
    image has a 364-byte header immediately followed by its stored payload.
    The recorded position is the image header offset, not a flash offset.
    """
    path = Path(path)
    if not 52 <= path.stat().st_size <= MAX_PACKAGE_SIZE:
        raise PackageError("Package size outside supported bounds")
    with path.open("rb") as stream:
        data = stream.read(MAX_PACKAGE_SIZE + 1)
    if not 52 <= len(data) <= MAX_PACKAGE_SIZE:
        raise PackageError("Package size outside supported bounds")
    if data[:12] != b"111\0\0\0\0\0bpkg":
        raise PackageError("Unsupported binpkg version or magic (expected v111)")
    if data[20:28] != b"SHA256\0\0" or any(data[32:52]):
        raise PackageError("Unsupported hash algorithm or header extension")
    count = struct.unpack_from("<I", data, 16)[0]
    parameter_count, parameter_size = struct.unpack_from("<HH", data, 28)
    if count not in (3, 4) or (parameter_count, parameter_size) != (3, 420):
        raise PackageError("Unsupported image count or parameter table")
    offset = 52 + parameter_size
    if offset > len(data):
        raise PackageError("Truncated parameter table")
    expected_parameters = ((1, "pkgmode"), (4, "banoldtool"), (2, "productname"))
    product = ""
    for index, (expected_kind, expected_name) in enumerate(expected_parameters):
        start = 52 + index * 140
        kind = struct.unpack_from("<I", data, start)[0]
        name = _text(data[start + 4:start + 68], "parameter name")
        value = data[start + 68:start + 132]
        if (kind, name) != (expected_kind, expected_name) or any(data[start + 132:start + 140]):
            raise PackageError("Unsupported parameter record")
        if name == "productname":
            product = _text(value, "product name")
            if product != PRODUCT:
                raise PackageError(f"Unsupported product: {product}")
        elif value != b"\x01" + bytes(63):
            raise PackageError(f"Unsupported {name} value")
    entries = []
    for _ in range(count):
        if offset + 364 > len(data):
            raise PackageError("Truncated image header")
        name = _text(data[offset:offset + 64], "image name")
        address, capacity, position, length = struct.unpack_from("<4I", data, offset + 64)
        expected_hash = _text(data[offset + 80:offset + 336], "image digest").lower()
        tag = _text(data[offset + 336:offset + 352], "image tag")
        if tag not in LAYOUT or any(data[offset + 352:offset + 364]):
            raise PackageError("Unknown image tag or unsupported image extension")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise PackageError("Invalid image SHA256 encoding")
        if position != offset:
            raise PackageError("Invalid image header position")
        end = offset + 364 + length
        if length == 0 or length > capacity or end > len(data):
            raise PackageError("Truncated or oversized image payload")
        payload = data[offset + 364:end]
        entries.append(PackageEntry(tag, name, address, capacity, payload, expected_hash))
        offset = end
    if offset != len(data):
        raise PackageError("Unexpected trailing package bytes")
    result = Package(product, hashlib.sha256(data).hexdigest(), tuple(entries))
    _validate_entries(result.entries)
    return result


def make_plan(package: Package, mode: str = "full") -> dict:
    """Return a JSON-serializable memory plan, never perform a write.

    App mode requires the operator to establish that the installed BL/AP/CP
    images match this package's base. This offline function cannot establish
    that condition. Full mode includes all four images and never describes a
    whole-chip erase. The agent also generates BL/AP boot headers during full
    flashing; their exact 272-byte ranges are excluded from preserved bytes.
    """
    if mode not in ("full", "app"):
        raise PackageError("Mode must be 'full' or 'app'")
    if package.product != PRODUCT:
        raise PackageError("Unsupported product")
    if not re.fullmatch(r"[0-9a-f]{64}", package.sha256):
        raise PackageError("Invalid package SHA256")
    _validate_entries(package.entries)
    if tuple(entry.tag for entry in package.entries) != TAG_ORDER:
        raise PackageError("A complete four-image F6D_A application package is required")
    selected = [entry for entry in package.entries if mode == "full" or entry.tag == "PKGFLXAPP"]
    regions = []
    for entry in selected:
        offset = entry.address - FLASH_BASE
        regions.append({
            "tag": entry.tag, "name": entry.name, "address": entry.address,
            "offset": offset, "flash_size": entry.flash_size,
            "payload_size": len(entry.data), "payload_sha256": entry.payload_sha256,
            "erase_offset": offset, "erase_size": entry.flash_size,
            "write_offset": offset, "write_size": len(entry.data),
            "storage": "ap_flash",
        })
    # Observed with this EC718PM agent: BL and AP transfers update their boot
    # header slots even though the image body addresses start elsewhere.
    generated_headers = ([
        {"tag": "BL", "offset": 0, "size": 272, "address": FLASH_BASE,
         "storage": "ap_flash", "generated_by": "agent"},
        {"tag": "AP", "offset": 0x1000, "size": 272,
         "address": FLASH_BASE + 0x1000, "storage": "ap_flash",
         "generated_by": "agent"},
    ] if mode == "full" else [])
    mutable_ranges = [
        {"offset": region["offset"], "size": region["flash_size"]}
        for region in regions
    ] + generated_headers
    untouched = []
    cursor = 0
    for region in sorted(mutable_ranges, key=lambda item: item["offset"]):
        if cursor < region["offset"]:
            untouched.append({"offset": cursor, "size": region["offset"] - cursor})
        cursor = max(cursor, region["offset"] + region["size"])
    if cursor < FLASH_SIZE:
        untouched.append({"offset": cursor, "size": FLASH_SIZE - cursor})
    boot_protected = ([
        {"name": "bl_header_slot_padding", "offset": 0x110, "size": 0xEF0},
        {"name": "ap_header_slot_padding_and_reserved_area", "offset": 0x1110,
         "size": 0x1EF0},
    ] if mode == "full" else [
        {"name": "pre_bootloader", "offset": 0, "size": 0x3000},
    ])
    return {
        "product": package.product, "profile": "NT26F6D0/F6D_A-observed",
        "package_sha256": package.sha256, "mode": mode,
        "flash_base": FLASH_BASE, "flash_size": FLASH_SIZE,
        "regions": regions, "generated_headers": generated_headers,
        "preserved_regions": untouched,
        "protected_regions": boot_protected + [
            {"name": "drr", "offset": 0x19000, "size": 0x5000},
            {"name": "cal_rr", "offset": 0x3F2000, "size": 0xC000},
        ],
        "base_payload_sha256": {entry.tag: entry.payload_sha256 for entry in package.entries[:3]},
        "requires_matching_base": mode == "app",
        "matching_base_requirement": (
            "Verify the installed BL/AP/CP match this package before app-only flashing."
            if mode == "app" else None
        ),
        "whole_flash_erase": False,
        "device_compatibility_verified": False,
        "payload_hashes_are_authentication": False,
    }
