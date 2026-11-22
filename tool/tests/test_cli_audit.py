"""Independent regression checks for target selection and write transaction state.

All ports and flash operations are fakes. Nothing imports or opens pyserial.
"""
import contextlib
import hashlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nt26flash import __main__ as cli
from nt26flash.devices import DeviceError, DevicePort
from nt26flash.package import Package, PackageEntry, PRODUCT, LAYOUT, FLASH_BASE, FLASH_SIZE, make_plan
from nt26flash.protocol import ProtocolError


def port(path, role, physical):
    vid, pid, interface = (0x3505, 3, 3) if role == 'runtime' else (0x17D1, 1, 0)
    return DevicePort(path, path, vid, pid, role, interface, physical)


def package():
    entries = []
    for n, (tag, (address, capacity)) in enumerate(LAYOUT.items()):
        data = bytes([n + 1]) * (capacity if tag != 'PKGFLXAPP' else 37012)
        entries.append(PackageEntry(tag, tag, address, capacity, data, hashlib.sha256(data).hexdigest()))
    return Package(PRODUCT, 'f' * 64, tuple(entries))


class DeviceSelectionAudit(unittest.TestCase):
    def setUp(self):
        self.a = port('/dev/ttyUSB_A', 'runtime', '/usb/1-1')
        self.arom = port('/dev/ttyUSB_AROM', 'rom', '/usb/1-1')
        self.brom = port('/dev/ttyUSB_BROM', 'rom', '/usb/1-2')

    def test_explicit_at_port_cannot_select_unrelated_existing_rom(self):
        before = [self.a, self.brom]
        after = [self.arom, self.brom]
        calls = [0]
        def devices():
            calls[0] += 1
            return before if calls[0] == 1 else after
        args = SimpleNamespace(port=None, at_port=self.a.port, enter_rom=True)
        with patch.object(cli, 'enumerate_devices', side_effect=devices), \
             patch.object(cli, 'enter_rom', return_value={'physical_location': self.a.physical_location}) as enter, \
             contextlib.redirect_stderr(io.StringIO()):
            selected = cli.wait_rom(args)
        self.assertEqual(selected.physical_location, self.a.physical_location)
        enter.assert_called_once_with(self.a)

    def test_conflicting_at_and_rom_selection_fails_without_mode_change(self):
        args = SimpleNamespace(port=self.brom.port, at_port=self.a.port, enter_rom=True)
        with patch.object(cli, 'enumerate_devices', return_value=[self.a, self.brom]), \
             patch.object(cli, 'enter_rom') as enter:
            with self.assertRaises(DeviceError):
                cli.wait_rom(args)
        enter.assert_not_called()

    def test_missing_explicit_at_target_never_falls_back_to_rom(self):
        args = SimpleNamespace(port=None, at_port='/dev/ttyUSB_missing', enter_rom=True)
        with patch.object(cli, 'enumerate_devices', return_value=[self.brom]), \
             patch.object(cli, 'enter_rom') as enter:
            with self.assertRaises(DeviceError):
                cli.wait_rom(args)
        enter.assert_not_called()

    def test_ambiguous_runtime_and_rom_without_selector_fails(self):
        args = SimpleNamespace(port=None, at_port=None, enter_rom=True)
        with patch.object(cli, 'enumerate_devices', return_value=[self.a, self.brom]), \
             patch.object(cli, 'enter_rom') as enter:
            with self.assertRaises(DeviceError):
                cli.wait_rom(args)
        enter.assert_not_called()

    def test_one_existing_rom_remains_usable(self):
        args = SimpleNamespace(port=None, at_port=None, enter_rom=False)
        with patch.object(cli, 'enumerate_devices', return_value=[self.brom]):
            self.assertEqual(cli.wait_rom(args), self.brom)


class TransactionAudit(unittest.TestCase):
    def _run(self, directory, session, backup, flash):
        pkg = package()
        @contextlib.contextmanager
        def connected(_args):
            yield session, {'rom_version_raw': '0000030301000000'}
        with patch.object(cli, 'parse_package', return_value=pkg), \
             patch.object(cli, 'load_agent_file', return_value=b'fake-agent'), \
             patch.object(cli, 'connected', side_effect=connected), \
             patch.object(cli, 'backup_flash', side_effect=backup), \
             patch.object(cli, 'flash_images', side_effect=flash), \
             contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return cli.main(['flash', 'mock.binpkg', '--confirm-sha256', pkg.sha256,
                             '--backup-dir', str(directory)])

    def test_backup_failure_restores_running_firmware_without_writes(self):
        session = Mock()
        with tempfile.TemporaryDirectory() as tmp:
            status = self._run(Path(tmp) / 'backup', session,
                               OSError('simulated backup disk failure'), Mock())
        self.assertEqual(status, 1)
        session.reset.assert_called_once()
        session.erase.assert_not_called()
        session.burn.assert_not_called()

    def test_post_erase_failure_does_not_reset_partial_firmware(self):
        session = Mock()
        def fail_after_erase(s, *args):
            s.erase(0x256000, 4096)
            raise ProtocolError('simulated lost write acknowledgement')
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'backup'
            status = self._run(directory, session, lambda *args: bytes(FLASH_SIZE), fail_after_erase)
            self.assertFalse((directory / 'success.json').exists())
        self.assertEqual(status, 1)
        session.reset.assert_not_called()

    def test_backup_precedes_every_write_phase(self):
        order = []
        session = Mock()
        session.reset.side_effect = lambda: order.append('reset')
        def backup(*args):
            order.append('backup')
            return bytes(FLASH_SIZE)
        def flash(*args):
            order.append('flash')
        with tempfile.TemporaryDirectory() as tmp:
            status = self._run(Path(tmp) / 'backup', session, backup, flash)
        self.assertEqual(status, 0)
        self.assertEqual(order, ['backup', 'flash', 'reset'])


class FinalFlashStateAudit(unittest.TestCase):
    def test_later_image_corrupting_earlier_image_cannot_report_success(self):
        pkg = package()
        initial = bytes([0xA5]) * FLASH_SIZE
        class MemoryBoard:
            def __init__(self): self.memory = bytearray(initial)
            def erase(self, address, size):
                self.memory[address:address + size] = b'\xff' * size
            def burn(self, data, *, image_type, address, storage, progress):
                self.memory[address:address + len(data)] = data
                if image_type == 'BL':
                    # Model a late side effect: the earlier AP had already
                    # passed its immediate readback. Final validation must
                    # still detect its now-incorrect contents.
                    self.memory[LAYOUT['AP'][0] - FLASH_BASE] ^= 1
                progress(len(data), len(data))
            def read_memory(self, address, size):
                start = address - FLASH_BASE
                return bytes(self.memory[start:start + size])
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ProtocolError):
                cli.flash_images(MemoryBoard(), pkg, make_plan(pkg, 'full'), Path(tmp), initial)


if __name__ == '__main__':
    unittest.main()
