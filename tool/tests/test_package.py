"""Malformed-container and protected-range checks; no hardware access."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from nt26flash.package import LAYOUT, PackageError, make_plan, parse_package


def fixture(count=4):
    data = bytearray(52)
    data[:12] = b"111\0\0\0\0\0bpkg"
    struct.pack_into("<I", data, 16, count)
    data[20:28] = b"SHA256\0\0"
    struct.pack_into("<HH", data, 28, 3, 420)
    for kind, name, value in ((1, "pkgmode", b"\1"), (4, "banoldtool", b"\1"), (2, "productname", b"EC718PM_PRD")):
        record = bytearray(140)
        struct.pack_into("<I", record, 0, kind)
        record[4:4 + len(name)] = name.encode()
        record[68:68 + len(value)] = value
        data.extend(record)
    offsets = []
    for index, (tag, (address, capacity)) in enumerate(list(LAYOUT.items())[:count]):
        offsets.append(len(data))
        payload = bytes([index + 1]) * (capacity if tag != "PKGFLXAPP" else 37012)
        header = bytearray(364)
        name = f"test_{tag}".encode()
        header[:len(name)] = name
        struct.pack_into("<4I", header, 64, address, capacity, len(data), len(payload))
        header[80:144] = hashlib.sha256(payload).hexdigest().upper().encode()
        header[336:336 + len(tag)] = tag.encode()
        data.extend(header)
        data.extend(payload)
    return data, offsets


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.good, cls.offsets = fixture()

    def read(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.binpkg"
            path.write_bytes(data)
            return parse_package(path)

    def rejected(self, change):
        data = bytearray(self.good)
        change(data)
        with self.assertRaises(PackageError):
            self.read(data)

    def test_valid_full_plan_and_boot_offset(self):
        package = self.read(self.good)
        plan = make_plan(package)
        self.assertEqual(plan["regions"][0]["offset"], 0x3000)
        self.assertEqual(plan["regions"][2]["storage"], "ap_flash")
        self.assertFalse(plan["whole_flash_erase"])
        self.assertEqual(package.sha256, hashlib.sha256(self.good).hexdigest())
        json.dumps(plan)
        for protected in plan["protected_regions"]:
            modified = [{"offset": region["offset"], "size": region["flash_size"]}
                        for region in plan["regions"]] + plan["generated_headers"]
            for region in modified:
                self.assertFalse(region["offset"] < protected["offset"] + protected["size"] and protected["offset"] < region["offset"] + region["size"])

    def test_full_plan_accounts_for_only_two_generated_header_ranges(self):
        plan = make_plan(self.read(self.good), "full")
        self.assertEqual([(r["tag"], r["offset"], r["size"])
                          for r in plan["generated_headers"]],
                         [("BL", 0, 272), ("AP", 0x1000, 272)])
        def preserved(address):
            return any(r["offset"] <= address < r["offset"] + r["size"]
                       for r in plan["preserved_regions"])
        for address in (0, 0x10F, 0x1000, 0x110F):
            self.assertFalse(preserved(address))
        for address in (0x110, 0xFFF, 0x1110, 0x1FFF, 0x2000, 0x2FFF):
            self.assertTrue(preserved(address))
        self.assertEqual([(r["offset"], r["size"])
                          for r in plan["protected_regions"][:2]],
                         [(0x110, 0xEF0), (0x1110, 0x1EF0)])

    def test_plan_ranges_partition_flash_without_gaps_or_overlap(self):
        package = self.read(self.good)
        for mode in ("full", "app"):
            plan = make_plan(package, mode)
            ranges = [{"offset": r["offset"], "size": r["flash_size"]}
                      for r in plan["regions"]]
            ranges += plan["generated_headers"] + plan["preserved_regions"]
            cursor = 0
            for region in sorted(ranges, key=lambda r: r["offset"]):
                self.assertEqual(region["offset"], cursor)
                cursor += region["size"]
            self.assertEqual(cursor, plan["flash_size"])

    def test_app_plan_erases_capacity_not_payload_length(self):
        plan = make_plan(self.read(self.good), "app")
        self.assertTrue(plan["requires_matching_base"])
        self.assertEqual(len(plan["regions"]), 1)
        region = plan["regions"][0]
        self.assertEqual((region["offset"], region["erase_size"], region["write_size"]), (0x256000, 0xCB000, 37012))
        self.assertEqual(plan["generated_headers"], [])
        self.assertEqual(plan["protected_regions"][0],
                         {"name": "pre_bootloader", "offset": 0, "size": 0x3000})
        self.assertEqual(plan["preserved_regions"][0]["offset"], 0)
        self.assertGreaterEqual(plan["preserved_regions"][0]["size"], 0x3000)

    def test_base_package_is_parseable_but_not_flashable_as_full(self):
        package = self.read(fixture(3)[0])
        for mode in ("full", "app"):
            with self.assertRaises(PackageError):
                make_plan(package, mode)

    def test_wrong_version(self):
        self.rejected(lambda data: data.__setitem__(0, ord("2")))

    def test_unknown_product(self):
        self.rejected(lambda data: data.__setitem__(0x190 + 5, ord("Q")))

    def test_unknown_tag(self):
        self.rejected(lambda data: data.__setitem__(self.offsets[0] + 336, ord("Z")))

    def test_duplicate_tag(self):
        self.rejected(lambda data: data.__setitem__(slice(self.offsets[1] + 336, self.offsets[1] + 352), b"BL" + bytes(14)))

    def test_corrupt_payload(self):
        self.rejected(lambda data: data.__setitem__(self.offsets[-1] + 364, 255))

    def test_bad_header_position(self):
        self.rejected(lambda data: struct.pack_into("<I", data, self.offsets[0] + 72, 0))

    def test_truncated_payload_and_header(self):
        for end in (51, 200, self.offsets[-1] + 100, len(self.good) - 1):
            with self.assertRaises(PackageError):
                self.read(self.good[:end])

    def test_extra_trailing_bytes(self):
        with self.assertRaises(PackageError):
            self.read(self.good + b"unexpected")

    def test_unknown_reserved_extensions(self):
        for offset in (32, 52 + 132, self.offsets[0] + 352):
            self.rejected(lambda data, offset=offset: data.__setitem__(offset, 1))

    def test_unsafe_name(self):
        self.rejected(lambda data: data.__setitem__(slice(self.offsets[0], self.offsets[0] + 64), b"../bad" + bytes(58)))

    def test_reject_wrong_layout_even_if_it_fits_flash(self):
        self.rejected(lambda data: struct.pack_into("<I", data, self.offsets[-1] + 64, 0xA57000))

    def test_overlap_and_out_of_flash(self):
        for address in (0x882000, 0xB80000, 0x700000):
            self.rejected(lambda data, address=address: struct.pack_into("<I", data, self.offsets[-1] + 64, address))

    def test_payload_exceeds_capacity(self):
        self.rejected(lambda data: struct.pack_into("<I", data, self.offsets[-1] + 76, 0xCB001))

    def test_wrong_parameter_size_and_count(self):
        for offset, value in ((28, 2), (30, 419)):
            self.rejected(lambda data, offset=offset, value=value: struct.pack_into("<H", data, offset, value))

    def test_invalid_mode(self):
        with self.assertRaises(PackageError):
            make_plan(self.read(self.good), "erase-all")


if __name__ == "__main__":
    unittest.main()
