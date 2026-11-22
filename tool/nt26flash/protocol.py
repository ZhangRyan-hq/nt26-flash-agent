"""Auditable EigenComm DLBOOT/AgentBoot transport, without device discovery.

Wire behavior is based on MIT-licensed openLuat/ectool2py and yuzhan-tech/ectool;
see evidence/upstream/UPSTREAM_FINDINGS.md and UPSTREAM_LICENSES.txt. This module
does not choose a chip profile, agent binary, flash address, or firmware package.
All hardware access is explicit through SerialTransport.open(). No imports open
ports. Runtime-board controls and CHIPID commands are intentionally not guessed.
"""
from __future__ import annotations

import hashlib
import struct
import time
import zlib
from typing import Callable, Protocol


DLBOOT = "dlboot"
AGBOOT = "agboot"
LPC = "lpc"
HANDSHAKES = {DLBOOT: bytes.fromhex("00d3022b"),
              AGBOOT: bytes.fromhex("aad3022b"), LPC: bytes.fromhex("cdd3022b")}
IMAGE_IDS = {"HEAD": 0x54494D48, "AG": 0x4F424D49, "BL": 0x4F424D49,
             "AP": 0x444B4249, "CP": 0x43504249, "FLEX": 0x464C5849}
GET_VERSION, SEL_IMAGE, VERIFY_IMAGE = 0x20, 0x21, 0x22
DATA_HEAD, DOWNLOAD_DATA, DONE = 0x31, 0x32, 0x3A
BURN_ONE, BURN_STATUS, SYS_RESET, READ_MEM = 0x42, 0x44, 0xAA, 0x21
FLASH_ERASE = 0x10
MAX_BLOCK = 0x10000


class ProtocolError(RuntimeError):
    """A response or locally supplied transfer violates the wire protocol."""


class ProtocolTimeout(ProtocolError):
    """A complete response did not arrive before the configured deadline."""


class DeviceError(ProtocolError):
    """The device explicitly rejected a command; never automatically retried."""

    def __init__(self, command: int, state: int, payload: bytes):
        self.command, self.state, self.payload = command, state, payload
        super().__init__(f"command 0x{command:02x}: device state={state}, "
                         f"payload={payload.hex()}")


class Transport(Protocol):
    """read() returns up to size bytes, empty only on timeout/end-of-stream.

    The timeout is a maximum duration in seconds for this individual read.
    write() must send all bytes or raise. clear_input() discards stale responses.
    """
    def read(self, size: int, timeout: float) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def clear_input(self) -> None: ...
    def set_baudrate(self, baudrate: int) -> None: ...


class SerialTransport:
    """Explicit pyserial adapter. Construct with open(); importing is harmless."""

    def __init__(self, port, *, chunk_size: int = 64, write_delay: float = 0.001):
        if chunk_size < 1 or write_delay < 0:
            raise ValueError("invalid write chunk/delay")
        self._port, self.chunk_size, self.write_delay = port, chunk_size, write_delay

    @classmethod
    def open(cls, path: str, *, baudrate: int = 921600,
             timeout: float = 0.8, dtr: bool = True, chunk_size: int = 64):
        if baudrate <= 0 or timeout <= 0:
            raise ValueError("baudrate and timeout must be positive")
        import serial  # Optional dependency, imported only for explicit hardware use.
        port = serial.Serial(port=None, baudrate=baudrate, timeout=timeout,
                             write_timeout=timeout, exclusive=True)
        port.dtr = dtr
        port.rts = False
        port.port = path
        try:
            port.open()
        except Exception:
            port.close()
            raise
        return cls(port, chunk_size=chunk_size)

    def read(self, size: int, timeout: float) -> bytes:
        self._port.timeout = max(0.0, timeout)
        return bytes(self._port.read(size))

    def write(self, data: bytes) -> None:
        for start in range(0, len(data), self.chunk_size):
            chunk = data[start:start + self.chunk_size]
            offset = 0
            while offset < len(chunk):
                count = self._port.write(chunk[offset:])
                if count is None or count <= 0 or count > len(chunk) - offset:
                    raise ProtocolError("serial write made no progress or returned invalid count")
                offset += count
            if self.write_delay and start + self.chunk_size < len(data):
                time.sleep(self.write_delay)

    def clear_input(self) -> None:
        self._port.reset_input_buffer()

    def set_baudrate(self, baudrate: int) -> None:
        self._port.baudrate = baudrate

    def close(self) -> None:
        self._port.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _u32(value: int, name: str) -> int:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be a uint32")
    return value


def crc8_maxim(data: bytes) -> int:
    """CRC-8/MAXIM-DOW: poly0x31, reflected0x8c, init0, xorout0."""
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8C if crc & 1 else 0)
    return crc


def build_request(command: int, payload: bytes = b"", *, index: int = 0,
                  mode: str = AGBOOT) -> bytes:
    """Pure encoder; CRC32 protects the *unencoded* little-endian length."""
    if mode not in HANDSHAKES or not 0 <= command <= 255 or not 0 <= index <= 255:
        raise ValueError("invalid protocol mode, command, or index")
    payload = bytes(payload)
    if len(payload) > MAX_BLOCK:
        raise ValueError("command payload exceeds 65536 bytes")
    ids = (0x4C, 0xB3) if mode == LPC else (0xCD, 0x32)
    header = struct.pack("<BBBBI", command, index, *ids, len(payload))
    plain = header + payload
    if mode == DLBOOT:
        return (plain + struct.pack("<I", sum(plain) & 0xFFFFFFFF)
                if command == DOWNLOAD_DATA else plain)
    encoded_length = len(payload) | (crc8_maxim(header[4:7]) << 24)
    return (header[:4] + struct.pack("<I", encoded_length) + payload
            + struct.pack("<I", zlib.crc32(plain)))


def build_image_header(image: bytes, *, image_type: str, address: int = 0,
                       baudrate: int = 0, pullup_qspi: bool = False,
                       dribble: bool = False, current_address_valid: bool = False,
                       load_address: int = 0x04010000,
                       agent_control: bytes = b"\0\0\0\0") -> bytes:
    """Build the 272-byte header. Explicit agent_control must be vendor-verified."""
    if image_type not in IMAGE_IDS:
        raise ValueError(f"unknown image type {image_type!r}")
    if not image:
        raise ValueError("empty image")
    _u32(address, "address")
    _u32(load_address, "load_address")
    _u32(len(image), "image size")
    if address + len(image) > 0x100000000:
        raise ValueError("image address range overflows")
    if not isinstance(baudrate, int) or baudrate < 0:
        raise ValueError("invalid baudrate")
    baud_control = baudrate // 100 + 0x8000 if baudrate else 0
    if baud_control > 0xFFFF or len(agent_control) != 4:
        raise ValueError("invalid baudrate control or agent control length")
    header = bytearray(272)
    struct.pack_into("<IIII", header, 0, 0x10000001, IMAGE_IDS["HEAD"], 0x20180507, 0)
    struct.pack_into("<IBBH", header, 16, 1, 0xEE, 0, baud_control)
    controls = int(bool(pullup_qspi)) | (int(bool(dribble)) << 1)
    controls |= int(bool(current_address_valid)) << 2
    struct.pack_into("<I", header, 24, controls)
    struct.pack_into("<IIII", header, 64, IMAGE_IDS[image_type], address,
                     load_address, len(image))
    header[80:84] = agent_control
    header[96:128] = hashlib.sha256(image).digest()
    header[32:64] = hashlib.sha256(header).digest()
    return bytes(header)


class Session:
    """One explicitly supplied port, no discovery and no implicit resets.

    Default command_attempts=1 stops after uncertain exchanges. A caller can
    opt into the vendor's retry convention (up to10), which rebuilds the same
    immutable request. Device NAKs never retry. Dropping a Session does no I/O.
    """
    def __init__(self, transport: Transport, *, timeout: float = 0.8,
                 command_attempts: int = 1, sync_attempts: int = 50,
                 transport_type: str = "usb", delay: float = 0.002,
                 sleeper: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        if timeout <= 0 or not 1 <= command_attempts <= 10 or sync_attempts < 1:
            raise ValueError("invalid timeout or retry count")
        if transport_type not in ("usb", "uart") or delay < 0:
            raise ValueError("invalid transport type or delay")
        self.transport, self.timeout = transport, timeout
        self.command_attempts, self.sync_attempts = command_attempts, sync_attempts
        self.transport_type, self.delay = transport_type, delay
        self._sleep, self._clock = sleeper, clock
        self.agent_loaded = False

    def _read_exact(self, size: int, label: str, *, deadline: float | None = None) -> bytes:
        deadline = self._clock() + self.timeout if deadline is None else deadline
        data = bytearray()
        while len(data) < size:
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise ProtocolTimeout(f"{label}: timeout after {len(data)}/{size} bytes")
            chunk = self.transport.read(size - len(data), remaining)
            if not chunk:
                raise ProtocolTimeout(f"{label}: timeout after {len(data)}/{size} bytes")
            if len(chunk) > size - len(data):
                raise ProtocolError("transport returned more bytes than requested")
            data.extend(chunk)
        return bytes(data)

    def handshake(self, mode: str = DLBOOT, *, count: int = 2) -> bytes:
        if mode not in HANDSHAKES or count < 1:
            raise ValueError("invalid handshake mode or count")
        expected = HANDSHAKES[mode]
        last_error: ProtocolError | None = None
        for _ in range(self.sync_attempts):
            self.transport.clear_input()
            for _ in range(count):
                self.transport.write(expected)
                if self.delay:
                    self._sleep(self.delay)
            try:
                received = self._read_exact(4, f"{mode} handshake")
                if received != expected:
                    raise ProtocolError(f"{mode} handshake mismatch: {received.hex()}")
                if mode == DLBOOT:
                    # Both upstream implementations allow no optional status byte.
                    extra = self.transport.read(1, min(self.timeout, 0.05))
                    if extra and extra != b"\0":
                        raise ProtocolError(f"DLBOOT handshake status {extra.hex()}")
                self.transport.clear_input()
                return received
            except ProtocolError as exc:
                last_error = exc
        raise ProtocolError(f"{mode} synchronization failed: {last_error}") from last_error

    def command(self, command: int, payload: bytes = b"", *, index: int = 0,
                mode: str = AGBOOT, max_response: int | None = None) -> bytes:
        request = build_request(command, payload, index=index, mode=mode)
        max_response = (255 if mode == LPC else 12) if max_response is None else max_response
        if not 0 <= max_response <= 255:
            raise ValueError("invalid response length bound")
        last_error: ProtocolError | None = None
        for attempt in range(self.command_attempts):
            self.transport.clear_input()
            self.transport.write(request)
            if self.delay:
                self._sleep(self.delay)
            try:
                deadline = self._clock() + self.timeout
                header = self._read_exact(6, "response header", deadline=deadline)
                rcmd, ridx, order, inv, state, size = header
                if size > max_response:
                    raise ProtocolError(f"response payload size {size} exceeds {max_response}")
                response = self._read_exact(size, "response payload", deadline=deadline)
                if mode != DLBOOT:
                    crc = self._read_exact(4, "response CRC32", deadline=deadline)
                    if struct.unpack("<I", crc)[0] != zlib.crc32(header + response):
                        raise ProtocolError("response CRC32 mismatch")
                expected_ids = (0x4C, 0xB3) if mode == LPC else (0xCD, 0x32)
                if rcmd != command or (order, inv) != expected_ids:
                    raise ProtocolError("response command/order IDs mismatch")
                expected_index = (index + 1) & 255 if command == DOWNLOAD_DATA else index
                if ridx != expected_index:
                    raise ProtocolError(f"response index {ridx}, expected {expected_index}")
                if state:
                    raise DeviceError(command, state, response)
                return response
            except DeviceError:
                raise
            except ProtocolError as exc:
                last_error = exc
                if attempt + 1 == self.command_attempts:
                    raise
        raise ProtocolError(str(last_error))  # Defensive; validation ensures attempts >=1.

    def get_version(self, *, dlboot: bool = True) -> bytes:
        result = self.command(GET_VERSION, mode=DLBOOT if dlboot else AGBOOT)
        if not result:
            raise ProtocolError("GET_VERSION returned no version bytes")
        return result

    def get_chip_id(self) -> bytes:
        raise NotImplementedError("CHIPID wire command requires vendor validation")

    def _base_info(self, image_type: str, *, dlboot: bool,
                   version: bytes | None = None) -> bytes:
        mode = DLBOOT if dlboot else AGBOOT
        version = self.get_version(dlboot=dlboot) if version is None else version
        selected = self.command(SEL_IMAGE, mode=mode)
        if selected != struct.pack("<I", IMAGE_IDS[image_type]):
            raise ProtocolError(f"SEL_IMAGE returned {selected.hex()}, expected {image_type}")
        self.command(VERIFY_IMAGE, mode=mode)
        return version

    def _transfer(self, data: bytes, *, dlboot: bool) -> None:
        if not data:
            raise ValueError("empty transfer")
        _u32(len(data), "transfer length")
        mode, offset, index = (DLBOOT if dlboot else AGBOOT), 0, 0
        while offset < len(data):
            remaining = len(data) - offset
            reply = self.command(DATA_HEAD, struct.pack("<I", remaining), mode=mode)
            if len(reply) != 4:
                raise ProtocolError("DATA_HEAD response must contain one uint32")
            size = struct.unpack("<I", reply)[0]
            if not 1 <= size <= min(remaining, MAX_BLOCK):
                raise ProtocolError(f"DATA_HEAD invalid negotiated size {size} for {remaining}")
            self.command(DOWNLOAD_DATA, data[offset:offset + size], index=index, mode=mode)
            offset += size
            index = (index + 1) & 255
        self.command(DONE, mode=mode)

    def load_agent(self, agent: bytes, *, baudrate: int = 921600,
                   pullup_qspi: bool = True, load_address: int = 0x04010000,
                   expected_rom_versions: tuple[bytes, ...] | None = None,
                   agent_control: bytes = b"\0\0\0\0") -> bytes:
        """Load caller-selected bytes to RAM, return raw ROM version.

        expected_rom_versions contains the confirmed 8-byte little-endian chip
        versions. Vendor CompRomVerIntSingle compares Version[:8]; the observed
        ROM also appends four date bytes. Only the observed 8/12-byte response
        shapes are accepted and the complete raw response is returned.
        """
        if self.agent_loaded:
            raise ProtocolError("AgentBoot already active in this session")
        if expected_rom_versions is not None and any(len(v) != 8 for v in expected_rom_versions):
            raise ValueError("expected ROM versions must contain exactly eight bytes")
        header = build_image_header(agent, image_type="AG", baudrate=baudrate,
                                    pullup_qspi=pullup_qspi, load_address=load_address,
                                    agent_control=agent_control)
        if baudrate <= 0:
            raise ValueError("AgentBoot baudrate must be positive")
        self.handshake(DLBOOT)
        version = self.get_version(dlboot=True)
        if expected_rom_versions is not None:
            if len(version) not in (8, 12) or version[:8] not in expected_rom_versions:
                raise ProtocolError(f"unrecognized ROM version {version.hex()}; no agent loaded")
        self._base_info("HEAD", dlboot=True, version=version)
        self._transfer(header, dlboot=True)
        self.handshake(DLBOOT)
        self._base_info("BL", dlboot=True)
        self._transfer(agent, dlboot=True)
        if self.transport_type == "uart":
            self.transport.set_baudrate(baudrate)
        self.agent_loaded = True
        return version

    def _require_agent(self) -> None:
        if not self.agent_loaded:
            raise ProtocolError("this operation requires a successfully loaded AgentBoot")

    def runtime_config(self, command: int, payload: bytes, *,
                       expected_response: bytes | None = None,
                       mode: str = LPC) -> bytes:
        """Send an explicitly vendor-verified runtime-control command.

        There is deliberately no default command number or payload encoding.
        The caller must establish the applicable chip/board controls first.
        """
        self._require_agent()
        if mode not in (LPC, AGBOOT):
            raise ValueError("runtime controls require LPC or AgentBoot mode")
        self.handshake(mode)
        response = self.command(command, payload, mode=mode)
        if expected_response is not None and response != expected_response:
            raise ProtocolError("runtime-control response differs from expected payload")
        return response

    def burn(self, image: bytes, *, image_type: str, address: int,
             storage: str = "ap", dribble: bool = False,
             progress: Callable[[int, int], None] | None = None) -> None:
        """Flash one explicit raw target; package/chip address validation is external.

        Use image_type='FLEX' for a vendor-verified PKGFLXAPP mapping. For EC718PM
        CP images use storage='ap'. No erasure of other areas is performed here.
        """
        self._require_agent()
        if image_type not in ("BL", "AP", "CP", "FLEX") or storage not in ("ap", "cp"):
            raise ValueError("invalid image class or storage")
        if storage == "cp" and image_type != "CP":
            raise ValueError("dedicated CP storage is only valid for CP images")
        is_uart = self.transport_type == "uart"
        use_dribble = bool(is_uart and address and dribble)
        valid_address = bool(is_uart and address and (not dribble or address & 0xFFFF))
        header = build_image_header(image, image_type=image_type, address=address,
                                    dribble=use_dribble, current_address_valid=valid_address)
        self.handshake(LPC)
        selector = struct.pack("<I", IMAGE_IDS[image_type])
        if storage == "cp":
            selector += struct.pack("<H", 0xE101)
        self.command(BURN_ONE, selector, mode=LPC)
        self.handshake(AGBOOT)
        self.handshake(AGBOOT)
        self._base_info("HEAD", dlboot=False)
        self._transfer(header, dlboot=False)
        offset = 0
        while offset < len(image):
            self.handshake(AGBOOT)
            self._base_info(image_type, dlboot=False)
            size = min(MAX_BLOCK, len(image) - offset)
            if is_uart and offset == 0 and address & 0xFFFF:
                size = min(size, MAX_BLOCK - (address & 0xFFFF))
            self._transfer(image[offset:offset + size], dlboot=False)
            offset += size
            if progress:
                progress(offset, len(image))
        status = self.command(BURN_STATUS, mode=LPC)
        if status != b"\0\0\0\0":
            raise ProtocolError(f"burn status not successful: {status.hex()}")

    def read_memory(self, address: int, size: int) -> bytes:
        """Read explicit absolute/XIP addresses through an already loaded agent."""
        self._require_agent()
        _u32(address, "address")
        _u32(size, "size")
        if address + size > 0x100000000:
            raise ValueError("read address range overflows")
        if not size:
            return b""
        self.handshake(LPC)
        data = bytearray()
        while len(data) < size:
            count = min(240, size - len(data))
            reply = self.command(READ_MEM, struct.pack("<II", count, address + len(data)),
                                 mode=LPC, max_response=count)
            if len(reply) != count:
                raise ProtocolError(f"read returned {len(reply)} bytes, expected {count}")
            data.extend(reply)
        return bytes(data)

    def erase(self, address: int, size: int, *, sector_size: int = 0x1000,
              flash_size: int = 0x400000,
              progress: Callable[[int, int], None] | None = None) -> None:
        """Erase only the explicit raw AP-flash range, in aligned sectors.

        Default geometry is the vendor EC718PM internal 4MiB flash. Address is
        a raw offset, as for burn(); the LPC erase frame uses offset+0x800000.
        No range rounding, implicit whole-chip erasure, or final reset occurs.
        Vendor LPCFlashEraseStep has no command-specific response-body check.
        The full response is still consumed and command/index/order/state/CRC
        validated. An ACK is protocol success, not a readback verification.
        """
        self._require_agent()
        _u32(address, "address")
        _u32(size, "size")
        if sector_size != 0x1000:
            raise ValueError("only verified 4096-byte erase sectors are supported")
        if flash_size <= 0 or flash_size > 0x400000 or flash_size % sector_size:
            raise ValueError("flash size must describe at most 4MiB of internal AP flash")
        if not size or address % sector_size or size % sector_size:
            raise ValueError("erase address and nonzero size must be sector aligned")
        if address + size > flash_size:
            raise ValueError("erase range exceeds explicitly selected AP flash")
        self.handshake(LPC)
        for offset in range(0, size, sector_size):
            payload = struct.pack("<II", sector_size, 0x800000 + address + offset)
            self.command(FLASH_ERASE, payload, mode=LPC)
            if progress:
                progress(offset + sector_size, size)

    def reset(self) -> None:
        """Explicit reset only; no reset-on-exception or destructor I/O."""
        self._require_agent()
        self.handshake(LPC)
        reply = self.command(SYS_RESET, mode=LPC)
        if reply != b"ZzZzZzZz":
            raise ProtocolError(f"reset acknowledgement invalid: {reply.hex()}")
        self.agent_loaded = False
