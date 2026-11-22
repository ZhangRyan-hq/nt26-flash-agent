"""No real USB or serial access: sysfs fixtures and mocked pyserial only."""

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from nt26flash import devices


def runtime(port="/dev/ttyUSB1", location="/sys/devices/usb1/1-2", interface=3):
    return devices.DevicePort(port, port, 0x3505, 3, "runtime", interface, location)


def identity(device):
    return {"vid": device.vid, "pid": device.pid,
            "interface_number": device.interface_number,
            "physical_location": device.physical_location}


class DeviceTests(unittest.TestCase):
    def test_sysfs_parent_and_interface(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            usb = root / "devices/usb1/1-2"
            interface = usb / "1-2:1.3"
            tty = interface / "ttyUSB1/tty/ttyUSB1"
            tty.mkdir(parents=True)
            (usb / "idVendor").write_text("3505\n")
            (usb / "idProduct").write_text("0003\n")
            (interface / "bInterfaceNumber").write_text("03\n")
            sysfs = root / "class/tty"
            (sysfs / "ttyUSB1").mkdir(parents=True)
            (sysfs / "ttyUSB1/device").symlink_to(tty)
            result = devices._sysfs_identity("/dev/ttyUSB1", sysfs)
            self.assertEqual(result, {"vid": 0x3505, "pid": 3,
                                     "interface_number": 3, "physical_location": str(usb)})

    def test_enumeration_is_read_only_and_includes_other(self):
        module = MagicMock()
        module.comports.return_value = [
            SimpleNamespace(device="/dev/ttyUSB1", vid=0x3505, pid=3),
            SimpleNamespace(device="/dev/ttyUSB8", vid=0x0403, pid=0x6010)]
        with patch.object(devices.importlib, "import_module", return_value=module) as imports, \
             patch.object(devices, "_sysfs_identity", side_effect=[identity(runtime()), {}]):
            result = devices.enumerate_devices()
        imports.assert_called_once_with("serial.tools.list_ports")
        self.assertEqual([item.role for item in result], ["runtime", "other"])
        module.Serial.assert_not_called()

    def test_only_at_interface_is_selected(self):
        ports = [runtime("/dev/ttyUSB0", interface=2), runtime(), runtime("/dev/ttyUSB2", interface=4)]
        self.assertEqual(devices.select_device(ports), runtime())
        with self.assertRaises(devices.DeviceError):
            devices.select_device(ports, port="/dev/ttyUSB0")

    def test_ambiguity_requires_selector(self):
        a, b = runtime(), runtime("/dev/ttyUSB4", "/sys/devices/usb1/1-4")
        with self.assertRaises(devices.DeviceError):
            devices.select_device([a, b])
        self.assertEqual(devices.select_device([a, b], port=b.port), b)

    def test_unknown_devices_and_unverified_sysfs_rejected(self):
        candidates = [devices.DevicePort("/dev/ttyUSB8", "/dev/ttyUSB8", 0x0403, 0x6010, "other", 3, "/sys/a"),
                      runtime(location=None)]
        with self.assertRaises(devices.DeviceError):
            devices.select_device(candidates)
        with self.assertRaises(devices.DeviceError):
            devices.select_device(candidates, role="other")

    def test_rom_selection_is_pinned_to_runtime_physical_location(self):
        a = devices.DevicePort("/dev/ttyUSB0", "/dev/ttyUSB0", 0x17D1, 1, "rom", 0, "/sys/devices/usb1/1-2")
        b = devices.DevicePort("/dev/ttyUSB4", "/dev/ttyUSB4", 0x17D1, 1, "rom", 0, "/sys/devices/usb1/1-4")
        self.assertEqual(devices.select_device([a, b], role="rom", physical_location=runtime().physical_location), a)

    def serial_mock(self, response):
        connection = MagicMock()
        connection.readline.side_effect = response
        connection.write.side_effect = lambda payload: len(payload)
        module = SimpleNamespace(Serial=MagicMock(return_value=connection), SerialException=OSError)
        return module, connection

    def test_probe_only_expected_commands_and_exclusive_flags(self):
        module, connection = self.serial_mock([b"AT\r\n", b"OK\r\n", b"AT+CGMR\r\n", b"F6D_A_V0101\r\n", b"OK\r\n"])
        with patch.object(devices, "_sysfs_identity", return_value=identity(runtime())), \
             patch.object(devices.importlib, "import_module", return_value=module):
            result = devices.probe_at(runtime())
        self.assertEqual([call.args[0] for call in connection.write.call_args_list], [b"AT\r\n", b"AT+CGMR\r\n"])
        self.assertEqual(result["firmware_version"], "F6D_A_V0101")
        self.assertTrue(module.Serial.call_args.kwargs["exclusive"])
        self.assertIsNone(module.Serial.call_args.kwargs["port"])
        self.assertFalse(connection.dtr)
        self.assertFalse(connection.rts)
        connection.close.assert_called_once()

    def test_enter_rom_is_explicit_and_does_not_claim_success(self):
        module, connection = self.serial_mock([b"OK\r\n"])
        with patch.object(devices, "_sysfs_identity", return_value=identity(runtime())), \
             patch.object(devices.importlib, "import_module", return_value=module):
            result = devices.enter_rom(runtime())
        self.assertEqual([call.args[0] for call in connection.write.call_args_list], [b"AT\r\n", b"AT+ECRST=delay,599\r\n"])
        self.assertEqual(result["physical_location"], runtime().physical_location)
        self.assertFalse(result["rom_verified"])

    def test_identity_changed_before_open(self):
        with patch.object(devices, "_sysfs_identity", return_value={}), \
             patch.object(devices.importlib, "import_module") as imports:
            with self.assertRaises(devices.DeviceError):
                devices.probe_at(runtime())
        imports.assert_not_called()

    def test_diag_and_rom_cannot_receive_at(self):
        for device in (runtime(interface=2), devices.DevicePort("/dev/ttyUSB0", "/dev/ttyUSB0", 0x17D1, 1, "rom", 0, "/sys/a")):
            with self.assertRaises(devices.DeviceError):
                devices.probe_at(device)

    def test_busy_port_fails_and_closes(self):
        module, connection = self.serial_mock([])
        connection.open.side_effect = OSError("busy")
        with patch.object(devices, "_sysfs_identity", return_value=identity(runtime())), \
             patch.object(devices.importlib, "import_module", return_value=module):
            with self.assertRaisesRegex(devices.DeviceError, "exclusively"):
                devices.probe_at(runtime())
        connection.write.assert_not_called()
        connection.close.assert_called_once()

    def test_unsolicited_numeric_identifier_is_redacted(self):
        module, connection = self.serial_mock([b"OK\n", b"IMEI: 123456789012345\n", b"OK\n"])
        with patch.object(devices, "_sysfs_identity", return_value=identity(runtime())), \
             patch.object(devices.importlib, "import_module", return_value=module):
            result = devices.probe_at(runtime())
        self.assertNotIn("123456789012345", str(result))

    def test_error_response_stops_before_version_query(self):
        module, connection = self.serial_mock([b"ERROR\n"])
        with patch.object(devices, "_sysfs_identity", return_value=identity(runtime())), \
             patch.object(devices.importlib, "import_module", return_value=module):
            with self.assertRaises(devices.DeviceError):
                devices.probe_at(runtime())
        self.assertEqual(connection.write.call_count, 1)


if __name__ == "__main__":
    unittest.main()
