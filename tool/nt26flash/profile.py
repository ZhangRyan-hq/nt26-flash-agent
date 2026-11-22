"""Pinned vendor assets and NT26F6D0 board controls.

Evidence: vendor baseini, vendor_vectors.py and the captured vendor-vectors.txt.
This profile deliberately does not support other EC718PM boards/layouts.
"""
from pathlib import Path
import hashlib
import struct

from .protocol import ProtocolError

AGENT_SHA256 = "0db9e8f3462140c7c368723aa144b976ac033ae45fc6d37db5d959b1c9238019"
AGENT_RELATIVE = "assets/ec718pm-agentboot-usb.bin"
RUNTIME_PAYLOAD = bytes.fromhex("01010000050000002103010319")
AGENT_CONTROL = bytes.fromhex("f6040019")  # Vendor GenAgImgHdBuf: AP 4 MiB, no separate CP flash.
# Download.DLDManage.CompRomVerIntSingle decodes Info.Version little-endian.
ROM_VERSIONS = tuple(int(v, 16).to_bytes(8, 'little') for v in (
    '0000000103030000', '0000000203030000', '0000000303030000'))

def load_agent_file(path=None):
    path = Path(path) if path else Path(__file__).resolve().parents[1] / AGENT_RELATIVE
    data = path.read_bytes()
    if len(data) != 50788 or hashlib.sha256(data).hexdigest() != AGENT_SHA256:
        raise ValueError("AgentBoot differs from the audited vendor EC718PM USB image")
    return data

def configure_board(session):
    response = session.runtime_config(0xE0, RUNTIME_PAYLOAD)
    # LPCExtendCmdProc saves raw Rsp.Data with no nested response envelope.
    if len(response) != 4 or not (struct.unpack("<I", response)[0] & 1):
        raise ProtocolError(f"runtime board configuration failed: {response.hex()}")
    return response.hex()
