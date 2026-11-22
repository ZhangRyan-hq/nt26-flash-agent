"""Offline-only protocol checks. No serial ports or downloaded code are opened."""
import hashlib
import json
import struct
import unittest
import zlib
from collections import deque
from pathlib import Path

from nt26flash.protocol import (
    AGBOOT, DLBOOT, LPC, HANDSHAKES, IMAGE_IDS, GET_VERSION, SEL_IMAGE,
    VERIFY_IMAGE, DATA_HEAD, DOWNLOAD_DATA, DONE, BURN_ONE, BURN_STATUS,
    SYS_RESET, READ_MEM, FLASH_ERASE, ProtocolError, ProtocolTimeout, DeviceError,
    Session, SerialTransport, build_request, build_image_header, crc8_maxim,
)


def response(command, payload=b"", *, index=0, mode=AGBOOT, state=0):
    ids = (0x4C, 0xB3) if mode == LPC else (0xCD, 0x32)
    data = bytes([command, index, *ids, state, len(payload)]) + payload
    return data if mode == DLBOOT else data + struct.pack("<I", zlib.crc32(data))


class ScriptedTransport:
    def __init__(self, responses=(), fragment=1):
        self.responses, self.incoming = deque(responses), bytearray()
        self.writes, self.fragment = [], fragment
        self.bauds = []

    def clear_input(self):
        self.incoming.clear()

    def write(self, data):
        self.writes.append(bytes(data))
        if self.responses:
            self.incoming.extend(self.responses.popleft())

    def read(self, size, timeout):
        count = min(size, len(self.incoming), self.fragment)
        data = bytes(self.incoming[:count])
        del self.incoming[:count]
        return data

    def set_baudrate(self, baud):
        self.bauds.append(baud)


class DeviceEmulator(ScriptedTransport):
    """Small stateful peer, validates host frames independently on every write."""
    VERSION = bytes.fromhex("0000030301000000")

    def __init__(self, transfer_size=4096, fragment=7):
        super().__init__(fragment=fragment)
        self.dlboot = True
        self.pending_sync = None
        self.syncs, self.commands, self.transfers = [], [], []
        self.selected = IMAGE_IDS["HEAD"]
        self.header_next = True
        self.image_id = None
        self.accumulator = bytearray()
        self.transfer_size = transfer_size
        self.expected_data_index = 0
        self.current_header = None

    def write(self, data):
        data = bytes(data)
        self.writes.append(data)
        if data in HANDSHAKES.values():
            self.syncs.append(data)
            if self.pending_sync == data:
                self.incoming.extend(data)
                if data == HANDSHAKES[DLBOOT]:
                    self.incoming.append(0)
                self.pending_sync = None
            else:
                self.pending_sync = data
            return
        if len(data) < 8:
            raise AssertionError("truncated request")
        cmd, idx, order, inv, encoded_size = struct.unpack_from("<BBBBI", data)
        mode = LPC if order == 0x4C else DLBOOT if self.dlboot else AGBOOT
        assert (order, inv) == ((0x4C, 0xB3) if mode == LPC else (0xCD, 0x32))
        size = encoded_size if mode == DLBOOT else encoded_size & 0xFFFFFF
        payload = data[8:8 + size]
        assert len(payload) == size
        plain_header = struct.pack("<BBBBI", cmd, idx, order, inv, size)
        if mode == DLBOOT:
            if cmd == DOWNLOAD_DATA:
                assert len(data) == 8 + size + 4
                assert struct.unpack("<I", data[-4:])[0] == sum(plain_header + payload)
            else:
                assert len(data) == 8 + size
        else:
            assert len(data) == 8 + size + 4
            # Independently compute the length guard by bit-at-a-time division.
            crc = 0
            for c in plain_header[4:7]:
                for bit in range(8):
                    mix = (crc & 1) ^ ((c >> bit) & 1)
                    crc = (crc ^ (mix * 0x118)) >> 1
            assert encoded_size >> 24 == crc
            assert struct.unpack("<I", data[-4:])[0] == zlib.crc32(plain_header + payload)
        self.commands.append((mode, cmd, idx, payload))
        returned, state, switch_after = b"", 0, False
        if mode == LPC:
            if cmd == BURN_ONE:
                self.image_id = struct.unpack_from("<I", payload)[0]
                self.selected, self.header_next = IMAGE_IDS["HEAD"], True
            elif cmd == BURN_STATUS:
                returned = bytes(4)
            elif cmd == READ_MEM:
                count, address = struct.unpack("<II", payload)
                returned = bytes((address + i) & 255 for i in range(count))
            elif cmd == SYS_RESET:
                returned = b"ZzZzZzZz"
            elif cmd == FLASH_ERASE:
                count, address = struct.unpack("<II", payload)
                assert count == 4096 and address % 4096 == 0
                assert 0x800000 <= address < 0xC00000
                returned = getattr(self, "erase_reply", b"")
            else:
                returned = b"config-ok"
        elif cmd == GET_VERSION:
            returned = self.VERSION
        elif cmd == SEL_IMAGE:
            returned = struct.pack("<I", self.selected)
        elif cmd == VERIFY_IMAGE:
            pass
        elif cmd == DATA_HEAD:
            remain, = struct.unpack("<I", payload)
            returned = struct.pack("<I", min(remain, self.transfer_size))
        elif cmd == DOWNLOAD_DATA:
            assert idx == self.expected_data_index
            self.expected_data_index = (idx + 1) & 255
            self.accumulator.extend(payload)
        elif cmd == DONE:
            transferred = bytes(self.accumulator)
            self.transfers.append(transferred)
            self.accumulator.clear()
            self.expected_data_index = 0
            if self.header_next:
                assert len(transferred) == 272
                raw = bytearray(transferred)
                digest = bytes(raw[32:64])
                raw[32:64] = bytes(32)
                assert hashlib.sha256(raw).digest() == digest
                self.current_header = transferred
                self.header_next = False
                self.selected = IMAGE_IDS["BL"] if self.dlboot else self.image_id
            elif self.dlboot:
                assert hashlib.sha256(transferred).digest() == self.current_header[96:128]
                switch_after = True
        else:
            raise AssertionError(f"unhandled command {cmd}")
        response_index = (idx + 1) & 255 if cmd == DOWNLOAD_DATA else idx
        self.incoming.extend(response(cmd, returned, index=response_index, mode=mode, state=state))
        if switch_after:
            self.dlboot = False


def session(transport, **kwargs):
    return Session(transport, delay=0, sync_attempts=2, **kwargs)


class EncodingTests(unittest.TestCase):
    def test_crc8_known_vectors(self):
        self.assertEqual(crc8_maxim(b"123456789"), 0xA1)
        self.assertEqual(crc8_maxim(bytes.fromhex("040000")), 0x9E)
        self.assertEqual(crc8_maxim(bytes.fromhex("100100")), 0x8E)

    def test_rom_plain_and_sum_vectors(self):
        self.assertEqual(build_request(GET_VERSION, mode=DLBOOT).hex(), "2000cd3200000000")
        self.assertEqual(build_request(DOWNLOAD_DATA, b"abc", mode=DLBOOT).hex(),
                         "3200cd3203000000616263" + "5a020000")

    def test_agent_crc_covers_plain_length(self):
        wire = build_request(DATA_HEAD, struct.pack("<I", 0x12345678))
        self.assertEqual(wire[4:8].hex(), "0400009e")
        plain = wire[:7] + b"\0" + wire[8:-4]
        self.assertEqual(struct.unpack("<I", wire[-4:])[0], zlib.crc32(plain))
        self.assertNotEqual(struct.unpack("<I", wire[-4:])[0], zlib.crc32(wire[:-4]))

    def test_fixed_command_vectors(self):
        self.assertEqual(build_request(GET_VERSION).hex(), "2000cd3200000000b35bc3ea")
        self.assertEqual(build_request(BURN_ONE, struct.pack("<I", IMAGE_IDS["FLEX"]),
                                       mode=LPC).hex(), "42004cb30400009e49584c469f766891")
        # Captured from vendor LPCCmd.CmdBytes(), not this encoder.
        self.assertEqual(build_request(FLASH_ERASE, struct.pack("<II", 0x1000, 0xA56000),
                                       mode=LPC).hex(), "10004cb308000025001000000060a5005dde7c81")

    def test_vendor_cython_image_header_fixtures(self):
        # Produced by the vendor Image.pyd pure serializers in an isolated Wine
        # process. Original script and stdout are in evidence/vendor_vectors.py
        # and evidence/vendor-vectors.txt. This test does not run vendor code.
        vectors = json.loads((Path(__file__).parent / "fixtures/vendor-header-vectors.json").read_text())
        addresses = {"AG": 0, "BL": 0x3000, "AP": 0x82000, "CP": 0x1E000, "FLEX": 0x256000}
        for kind, expected in vectors.items():
            with self.subTest(image_type=kind):
                actual = build_image_header(b"vector-test-data", image_type=kind,
                                            address=addresses[kind],
                                            baudrate=921600 if kind == "AG" else 0,
                                            pullup_qspi=kind == "AG")
                self.assertEqual(actual.hex(), expected)

    def test_header_hash_and_controls(self):
        result = build_image_header(b"abc", image_type="AP", address=0x82000)
        self.assertEqual(len(result), 272)
        self.assertEqual(struct.unpack_from("<IIII", result, 64),
                         (IMAGE_IDS["AP"], 0x82000, 0x04010000, 3))
        self.assertEqual(result[96:128], hashlib.sha256(b"abc").digest())
        original_hash = result[32:64]
        self.assertEqual(original_hash, hashlib.sha256(result[:32] + bytes(32) + result[64:]).digest())
        agent = build_image_header(b"a", image_type="AG", baudrate=921600, pullup_qspi=True)
        self.assertEqual(struct.unpack_from("<H", agent, 22)[0], 0xA400)
        self.assertEqual(agent[24:28], b"\x01\0\0\0")

    def test_invalid_inputs_have_no_io(self):
        for kwargs in ({"image_type": "bogus"}, {"image_type": "AP", "address": -1},
                       {"image_type": "AP", "address": 0xFFFFFFFF},
                       {"image_type": "AG", "baudrate": 100000000}):
            with self.assertRaises(ValueError):
                build_image_header(b"ab", **kwargs)
        with self.assertRaises(ValueError):
            build_request(DOWNLOAD_DATA, bytes(65537))


class ExchangeTests(unittest.TestCase):
    def test_partial_frame_is_assembled(self):
        t = ScriptedTransport([response(GET_VERSION, b"version")], fragment=1)
        self.assertEqual(session(t).get_version(dlboot=False), b"version")

    def test_timeout_reports_partial_count(self):
        t = ScriptedTransport([bytes([GET_VERSION, 0, 0xCD])])
        with self.assertRaisesRegex(ProtocolTimeout, "3/6"):
            session(t).command(GET_VERSION)

    def test_bad_crc_rejected(self):
        bad = bytearray(response(GET_VERSION, b"version")); bad[-1] ^= 0x40
        with self.assertRaisesRegex(ProtocolError, "CRC32"):
            session(ScriptedTransport([bad])).command(GET_VERSION)

    def test_ids_command_index_and_state_rejected(self):
        for wire in (response(0x21), response(GET_VERSION, index=2),
                     response(GET_VERSION, mode=LPC)):
            with self.assertRaises(ProtocolError):
                session(ScriptedTransport([wire])).command(GET_VERSION)
        t = ScriptedTransport([response(GET_VERSION, state=7)])
        with self.assertRaises(DeviceError):
            session(t, command_attempts=3).command(GET_VERSION)
        self.assertEqual(len(t.writes), 1)

    def test_download_response_index_wraps(self):
        t = ScriptedTransport([response(DOWNLOAD_DATA, index=0)])
        session(t).command(DOWNLOAD_DATA, b"x", index=255)

    def test_oversize_response_rejected(self):
        with self.assertRaisesRegex(ProtocolError, "exceeds"):
            session(ScriptedTransport([response(GET_VERSION, bytes(13))])).command(GET_VERSION)

    def test_retries_do_not_mutate_length(self):
        t = ScriptedTransport([b"", response(DATA_HEAD, struct.pack("<I", 10))])
        self.assertEqual(session(t, command_attempts=2).command(DATA_HEAD, struct.pack("<I", 10)),
                         struct.pack("<I", 10))
        self.assertEqual(t.writes[0], t.writes[1])
        self.assertEqual(t.writes[0][4:8], bytes.fromhex("0400009e"))

    def test_negotiated_zero_oversize_short_rejected_before_data(self):
        for reply in (struct.pack("<I", 0), struct.pack("<I", 20), b"xx"):
            t = ScriptedTransport([response(DATA_HEAD, reply)])
            with self.assertRaises(ProtocolError):
                session(t)._transfer(b"0123456789", dlboot=False)
            self.assertEqual(len(t.writes), 1)

    def test_agent_required(self):
        t = ScriptedTransport(); s = session(t)
        with self.assertRaises(ProtocolError):
            s.burn(b"x", image_type="AP", address=0x82000)
        with self.assertRaises(ProtocolError):
            s.read_memory(0x800000, 1)
        self.assertEqual(t.writes, [])


class WorkflowTests(unittest.TestCase):
    def test_load_agent_burn_app_read_reset(self):
        t = DeviceEmulator(transfer_size=4096)
        s = session(t)
        agent = bytes(range(256)) * 32
        self.assertEqual(s.load_agent(agent, expected_rom_versions=(t.VERSION,)), t.VERSION)
        self.assertTrue(s.agent_loaded)
        self.assertEqual(t.transfers[1], agent)
        app = bytes(range(251)) * 280
        progress = []
        s.burn(app, image_type="FLEX", address=0x256000,
               progress=lambda done, total: progress.append((done, total)))
        self.assertEqual(t.transfers[3] + t.transfers[4], app)
        self.assertEqual(len(t.transfers[3]), 65536)
        self.assertEqual(progress[-1], (len(app), len(app)))
        selectors = [p for m, c, i, p in t.commands if m == LPC and c == BURN_ONE]
        self.assertEqual(selectors, [struct.pack("<I", IMAGE_IDS["FLEX"])])
        self.assertEqual(s.read_memory(0x825600, 300), bytes(i & 255 for i in range(300)))
        s.reset()
        self.assertFalse(s.agent_loaded)

    def test_wrong_rom_stops_before_ram_download(self):
        t = DeviceEmulator(); s = session(t)
        with self.assertRaisesRegex(ProtocolError, "unrecognized ROM"):
            s.load_agent(b"agent", expected_rom_versions=(bytes(8),))
        self.assertFalse(s.agent_loaded)
        self.assertEqual([cmd for _, cmd, _, _ in t.commands], [GET_VERSION])

    def test_all_vendor_confirmed_rom_versions_are_accepted(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/vendor-rom-erase-vectors.json").read_text())
        allowed = tuple(bytes.fromhex(p["wire_hex"]) for p in fixture["rom_version_pairs"])
        for version in allowed:
            with self.subTest(raw_version=version.hex()):
                t = DeviceEmulator(); t.VERSION = version
                s = session(t)
                self.assertEqual(s.load_agent(b"agent", expected_rom_versions=allowed), version)

    def test_vendor_confirmed_twelve_byte_rom_version(self):
        # Original CompRomVerIntSingle succeeds on these complete responses
        # and compares only the first8 bytes; see vendor-rom-erase.txt.
        identity = bytes.fromhex('0000030301000000')
        for suffix in (bytes.fromhex('01202420'), bytes(4), b'\xff' * 4):
            with self.subTest(suffix=suffix.hex()):
                t = DeviceEmulator(); t.VERSION = identity + suffix
                self.assertEqual(session(t).load_agent(b'agent', expected_rom_versions=(identity,)),
                                 identity + suffix)

    def test_twelve_byte_wrong_rom_and_unobserved_lengths_stop_before_load(self):
        allowed = (bytes.fromhex('0000030301000000'),)
        for value in (bytes.fromhex('010003030100000001202420'),
                      allowed[0] + b'\x01', allowed[0][:-1]):
            t = DeviceEmulator(); t.VERSION = value
            with self.assertRaisesRegex(ProtocolError, 'unrecognized ROM'):
                session(t).load_agent(b'agent', expected_rom_versions=allowed)
            self.assertEqual([cmd for _, cmd, _, _ in t.commands], [GET_VERSION])

    def test_uart_first_block_alignment_and_cp_ap_storage(self):
        t = DeviceEmulator(); s = session(t, transport_type="uart")
        s.load_agent(b"agent")
        self.assertEqual(t.bauds, [921600])
        image = bytes(70000)
        s.burn(image, image_type="CP", address=0x1E000, storage="ap")
        self.assertEqual(len(t.transfers[3]), 0x2000)
        self.assertEqual(b"".join(t.transfers[3:]), image)
        header = t.transfers[2]
        self.assertEqual(struct.unpack_from("<I", header, 24)[0], 4)
        selectors = [p for m, c, i, p in t.commands if m == LPC and c == BURN_ONE]
        self.assertEqual(selectors, [struct.pack("<I", IMAGE_IDS["CP"])])

    def test_packet_index_wrap_during_transfer(self):
        t = DeviceEmulator(transfer_size=1)
        s = session(t); s.load_agent(bytes(300))
        self.assertTrue(s.agent_loaded)
        self.assertTrue(any(i == 255 for _, c, i, _ in t.commands if c == DOWNLOAD_DATA))

    def test_opaque_runtime_configuration_no_defaults(self):
        t = DeviceEmulator(); s = session(t); s.load_agent(b"agent")
        self.assertEqual(s.runtime_config(0x7F, b"verified bytes", expected_response=b"config-ok"),
                         b"config-ok")
        with self.assertRaises(NotImplementedError):
            s.get_chip_id()

    def test_explicit_sector_erase_bounded_and_xip_biased(self):
        t = DeviceEmulator(); s = session(t); s.load_agent(b"agent")
        progress = []
        s.erase(0x256000, 0x2000, progress=lambda a, b: progress.append((a, b)))
        frames = [p for m, c, i, p in t.commands if m == LPC and c == FLASH_ERASE]
        self.assertEqual(frames, [struct.pack("<II", 4096, 0xA56000),
                                  struct.pack("<II", 4096, 0xA57000)])
        self.assertEqual(progress, [(4096, 8192), (8192, 8192)])

    def test_erase_invalid_range_never_writes(self):
        t = ScriptedTransport(); s = session(t); s.agent_loaded = True
        for address, size in ((0, 0), (1, 4096), (0x256000, 37012),
                              (0x3FF000, 8192), (0xA56000, 4096)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    s.erase(address, size)
        self.assertEqual(t.writes, [])

    def test_erase_opaque_ack_matches_vendor_check(self):
        t = DeviceEmulator(); s = session(t); s.load_agent(b"agent")
        t.erase_reply = bytes.fromhex("ffffffff")
        s.erase(0x256000, 4096)

    def test_erase_nak_and_bad_crc_stop_before_next_sector(self):
        bad_crc = bytearray(response(FLASH_ERASE, mode=LPC)); bad_crc[-1] ^= 1
        for reply in (response(FLASH_ERASE, mode=LPC, state=1), bad_crc):
            t = ScriptedTransport([b"", HANDSHAKES[LPC], reply])
            s = session(t); s.agent_loaded = True
            with self.assertRaises(ProtocolError):
                s.erase(0x256000, 8192)
            self.assertEqual(len(t.writes), 3)


class SerialAdapterTests(unittest.TestCase):
    def test_partial_writes_are_completed(self):
        class Port:
            def __init__(self): self.sent = bytearray()
            def write(self, data):
                self.sent.extend(data[:3]); return min(3, len(data))
        port = Port(); adapter = SerialTransport(port, chunk_size=7, write_delay=0)
        data = bytes(range(35)); adapter.write(data)
        self.assertEqual(bytes(port.sent), data)

    def test_nonprogress_write_is_error(self):
        class Port:
            def write(self, data): return 0
        with self.assertRaises(ProtocolError):
            SerialTransport(Port(), write_delay=0).write(b"x")


if __name__ == "__main__":
    unittest.main()
