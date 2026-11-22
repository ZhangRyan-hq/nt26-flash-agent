"""NT26 USB enumeration and explicitly requested AT actions on Linux.

Enumeration never opens a port. Pyserial is imported only by the functions
that need it. Only the runtime AT interface (03) may receive AT commands.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import importlib
import os
from pathlib import Path
import re
import time


RUNTIME_USB_ID = (0x3505, 0x0003)
ROM_USB_ID = (0x17D1, 0x0001)


class DeviceError(RuntimeError):
    """Absent, ambiguous, changed, unsupported, or busy USB serial device."""


@dataclass(frozen=True)
class DevicePort:
    port: str
    realpath: str
    vid: int | None
    pid: int | None
    role: str
    interface_number: int | None
    physical_location: str | None

    def to_dict(self) -> dict:
        return asdict(self)


def _role(vid, pid):
    if (vid, pid) == RUNTIME_USB_ID:
        return "runtime"
    if (vid, pid) == ROM_USB_ID:
        return "rom"
    return "other"


def _sysfs_identity(realpath: str, sysfs_root: Path = Path("/sys/class/tty")) -> dict:
    """Find USB interface and device ancestors, preserving the physical path.

    The parent USB device path (e.g. .../usb1/1-2) survives a runtime-to-ROM
    re-enumeration, whereas ttyUSB numbering and VID/PID can change.
    """
    try:
        node = (sysfs_root / Path(realpath).name / "device").resolve(strict=True)
    except (OSError, RuntimeError):
        return {}
    interface_number = None
    for parent in (node, *node.parents):
        try:
            interface_path = parent / "bInterfaceNumber"
            if interface_number is None and interface_path.is_file():
                interface_number = int(interface_path.read_text().strip(), 16)
            if (parent / "idVendor").is_file() and (parent / "idProduct").is_file():
                return {
                    "vid": int((parent / "idVendor").read_text().strip(), 16),
                    "pid": int((parent / "idProduct").read_text().strip(), 16),
                    "interface_number": interface_number,
                    "physical_location": str(parent),
                }
        except (OSError, ValueError):
            return {}
    return {}


def enumerate_devices() -> tuple[DevicePort, ...]:
    """List serial devices without opening them; unrelated devices are 'other'."""
    list_ports = importlib.import_module("serial.tools.list_ports")
    devices = []
    seen = set()
    try:
        ports = list_ports.comports()
    except (OSError, TypeError, ValueError):
        # pyserial 3.5 may int(None,16) when USB vanishes between sysfs reads.
        # Treat this enumeration pass as empty; the caller's bounded wait retries.
        return ()
    for info in ports:
        realpath = os.path.realpath(info.device)
        if realpath in seen:
            continue
        seen.add(realpath)
        identity = _sysfs_identity(realpath)
        vid = identity.get("vid", info.vid)
        pid = identity.get("pid", info.pid)
        devices.append(DevicePort(
            port=info.device, realpath=realpath, vid=vid, pid=pid,
            role=_role(vid, pid), interface_number=identity.get("interface_number"),
            physical_location=identity.get("physical_location"),
        ))
    return tuple(sorted(devices, key=lambda device: device.realpath))


def select_device(devices, role: str = "runtime", port: str | None = None,
                  physical_location: str | None = None) -> DevicePort:
    """Require one supported candidate, optionally pinned by port/USB parent.

    Runtime selection means the AT interface, never diagnostic interfaces 02
    or 04. ROM selection can be pinned to the runtime's physical_location.
    """
    if role not in ("runtime", "rom"):
        raise DeviceError("Only runtime or rom devices may be selected")
    wanted_port = os.path.realpath(port) if port is not None else None
    candidates = []
    for device in devices:
        if device.role != role or _role(device.vid, device.pid) != role:
            continue
        if not device.physical_location or device.interface_number is None:
            continue
        if role == "runtime" and device.interface_number != 3:
            continue
        if wanted_port is not None and device.realpath != wanted_port:
            continue
        if physical_location is not None and device.physical_location != physical_location:
            continue
        if device.realpath not in {candidate.realpath for candidate in candidates}:
            candidates.append(device)
    if not candidates:
        raise DeviceError("No matching supported USB serial interface with verified sysfs identity")
    if len(candidates) != 1:
        raise DeviceError("Multiple matching devices; specify the port or physical_location")
    return candidates[0]


def _check_runtime_identity(device: DevicePort) -> None:
    if (device.vid, device.pid) != RUNTIME_USB_ID or device.role != "runtime" or device.interface_number != 3:
        raise DeviceError("AT actions require NT26 runtime USB interface 03")
    if not device.physical_location or os.path.realpath(device.port) != device.realpath:
        raise DeviceError("Port mapping is missing or has changed; enumerate again")
    identity = _sysfs_identity(device.realpath)
    expected = {"vid": device.vid, "pid": device.pid,
                "interface_number": 3, "physical_location": device.physical_location}
    if identity != expected:
        raise DeviceError("Device USB identity changed; enumerate again")


@contextmanager
def _at_connection(device: DevicePort):
    _check_runtime_identity(device)
    serial = importlib.import_module("serial")
    connection = None
    try:
        # Construct closed, set modem lines before open, and request pyserial's
        # exclusive flock. Never reset a device through DTR/RTS intentionally.
        connection = serial.Serial(port=None, baudrate=115200, timeout=0.2,
                                   write_timeout=2, exclusive=True,
                                   rtscts=False, dsrdtr=False)
        connection.dtr = False
        connection.rts = False
        connection.port = device.realpath
        connection.open()
        yield connection
    except DeviceError:
        raise
    except (OSError, serial.SerialException) as exc:
        raise DeviceError("Cannot access the AT port exclusively (busy, disconnected, or permission denied)") from exc
    finally:
        if connection is not None:
            connection.close()


def _exchange(connection, command: str, timeout: float = 2.0) -> list[str]:
    connection.reset_input_buffer()
    request = command.encode("ascii") + b"\r\n"
    if connection.write(request) != len(request):
        raise DeviceError("Incomplete AT command write")
    connection.flush()
    deadline = time.monotonic() + timeout
    lines = []
    received = 0
    while time.monotonic() < deadline:
        raw = connection.readline()
        received += len(raw)
        if received > 16384:
            raise DeviceError("Excessive unsolicited AT output")
        line = raw.decode("ascii", "replace").strip()
        if not line or line.upper() == command.upper():
            continue
        if line == "OK":
            return lines
        if line == "ERROR" or line.startswith(("+CME ERROR", "+CMS ERROR")):
            raise DeviceError(f"Device rejected {command}")
        # Do not propagate a numeric IMEI that may arrive as unsolicited text.
        lines.append(re.sub(r"(?<!\d)\d{15}(?!\d)", "[redacted]", line))
    raise DeviceError(f"Timed out waiting for {command} response")


def probe_at(device: DevicePort) -> dict:
    """Explicitly send only AT and AT+CGMR; never query identifiers or reset."""
    with _at_connection(device) as connection:
        _exchange(connection, "AT")
        version_lines = _exchange(connection, "AT+CGMR")
    return {"port": device.realpath, "physical_location": device.physical_location,
            "at_ok": True, "firmware_version": "\n".join(version_lines)}


def enter_rom(device: DevicePort) -> dict:
    """Explicit mutating action: request download mode and return USB location.

    The USB device may disappear before an OK response. A completed write
    therefore proves only that the command was sent, not that ROM appeared.
    The caller must re-enumerate 17d1:0001 at the returned physical location.
    """
    with _at_connection(device) as connection:
        _exchange(connection, "AT")
        command = b"AT+ECRST=delay,599\r\n"
        connection.reset_input_buffer()
        if connection.write(command) != len(command):
            raise DeviceError("Incomplete enter-ROM command write")
        connection.flush()
    return {"port": device.realpath, "physical_location": device.physical_location,
            "command_sent": True, "rom_verified": False,
            "expected_rom_vid": ROM_USB_ID[0], "expected_rom_pid": ROM_USB_ID[1]}
