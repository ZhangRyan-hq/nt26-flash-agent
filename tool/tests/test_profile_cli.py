import contextlib
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nt26flash import __main__ as cli
from nt26flash.package import Package, PackageEntry, LAYOUT, PRODUCT, FLASH_SIZE, make_plan
from nt26flash.profile import configure_board, ROM_VERSIONS, RUNTIME_PAYLOAD, AGENT_CONTROL, load_agent_file
from nt26flash.protocol import ProtocolError, build_request, build_image_header, LPC
from nt26flash.devices import enumerate_devices


def package():
    entries = tuple(PackageEntry(tag, tag, address, size, bytes([i + 1]) * (size if tag != 'PKGFLXAPP' else 32),
                                hashlib.sha256(bytes([i + 1]) * (size if tag != 'PKGFLXAPP' else 32)).hexdigest())
                    for i, (tag, (address, size)) in enumerate(LAYOUT.items()))
    return Package(PRODUCT, 'f' * 64, entries)


class ProfileTests(unittest.TestCase):
    def test_vendor_runtime_wire(self):
        self.assertEqual(build_request(0xe0, RUNTIME_PAYLOAD, mode=LPC).hex(),
                         'e0004cb30d000010010100000500000021030103195c58dd34')

    def test_runtime_requires_semantic_success(self):
        for value in (b'', bytes(4), bytes(8), b'\x01'):
            session = Mock()
            session.runtime_config.return_value = value
            with self.assertRaises(ProtocolError): configure_board(session)
        session.runtime_config.return_value = b'\x01\0\0\0'
        self.assertEqual(configure_board(session), '01000000')

    def test_vendor_rom_byte_order(self):
        self.assertEqual(ROM_VERSIONS, tuple(bytes.fromhex(v) for v in (
            '0000030301000000','0000030302000000','0000030303000000')))

    def test_actual_vendor_agent_header(self):
        fixture = Path(__file__).parent / 'fixtures' / 'actual-agent-header.bin'
        self.assertEqual(build_image_header(load_agent_file(),image_type='AG',baudrate=921600,
                                            pullup_qspi=True,agent_control=AGENT_CONTROL),fixture.read_bytes())


class WorkflowTests(unittest.TestCase):
    def test_usb_reenumeration_pyserial_race_is_retryable(self):
        with patch('nt26flash.devices.importlib.import_module') as imported:
            imported.return_value.comports.side_effect = TypeError("int() can't convert non-string with explicit base")
            self.assertEqual(enumerate_devices(), ())

    def test_wrong_confirmation_never_connects(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli, 'parse_package', return_value=package()), \
             patch.object(cli, 'connected') as connected, contextlib.redirect_stderr(io.StringIO()):
            status = cli.main(['flash','dummy.binpkg','--confirm-sha256','0'*64,'--backup-dir',tmp+'/backup'])
            self.assertEqual(status,1)
            connected.assert_not_called()
            self.assertFalse(Path(tmp, 'backup').exists())

    def test_app_mismatch_never_erases(self):
        pkg=package()
        session=Mock()
        with self.assertRaises(ValueError):
            cli.flash_images(session,pkg,make_plan(pkg,'app'),Path('/unused'),bytes(FLASH_SIZE))
        session.erase.assert_not_called()
        session.burn.assert_not_called()

    def test_backup_rejects_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli,'read_flash',return_value=bytes(FLASH_SIZE)):
            original=Path(tmp)/'flash-before.bin'
            original.write_bytes(b'original')
            with self.assertRaises(FileExistsError):cli.backup_flash(Mock(),Path(tmp))
            self.assertEqual(original.read_bytes(),b'original')

    def test_backup_is_private_and_hashed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli,'read_flash',return_value=bytes(FLASH_SIZE)):
            result=cli.backup_flash(Mock(),Path(tmp))
            self.assertEqual(len(result),FLASH_SIZE)
            self.assertEqual((Path(tmp)/'flash-before.bin').stat().st_mode & 0o777,0o600)
            self.assertTrue((Path(tmp)/'backup.json').exists())

    def test_generated_boot_headers_and_padding_are_separately_verified(self):
        pkg = package()
        plan = make_plan(pkg)
        before = bytes([0x55]) * FLASH_SIZE
        image = bytearray(before)
        for entry in pkg.entries:
            offset = entry.address - 0x800000
            image[offset:offset + entry.flash_size] = b'\xff' * entry.flash_size
            image[offset:offset + len(entry.data)] = entry.data
        for tag, offset in [('BL',0),('AP',0x1000)]:
            entry = next(e for e in pkg.entries if e.tag == tag)
            image[offset:offset + 272] = build_image_header(entry.data,image_type=tag,address=entry.address-0x800000)
        for mutation in (None, 0x10, 0x120):
            memory = bytearray(image)
            if mutation is not None: memory[mutation] ^= 1
            session = Mock()
            session.read_memory.side_effect = lambda address, size: bytes(memory[address-0x800000:address-0x800000+size])
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
                if mutation is None:
                    cli.verify_flash(session,pkg,plan,Path(tmp),before)
                    self.assertTrue((Path(tmp)/'verified-header-BL.json').exists())
                else:
                    with self.assertRaises(ProtocolError): cli.verify_flash(session,pkg,plan,Path(tmp),before)
            session.erase.assert_not_called()
            session.burn.assert_not_called()

if __name__=='__main__':unittest.main()
