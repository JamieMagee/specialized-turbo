"""
CRC-16 framing for Specialized Turbo TCX2/TCX3/TCX4 protocols.

TCX2+ packets are 20 bytes: 18 bytes of payload + 2 bytes CRC-16/CCITT-FALSE
(polynomial 0x1021, init 0xFFFF, no final XOR), stored little-endian.
"""

from __future__ import annotations

import binascii

# TCX2+ packet sizes
FRAMED_PACKET_SIZE = 20  # Total packet size with CRC
FRAMED_PAYLOAD_SIZE = 18  # Payload size without CRC
CRC_SIZE = 2

# CRC-16/CCITT-FALSE init value (polynomial 0x1021)
_CRC_INIT = 0xFFFF

# NAK byte — never encrypted, may appear as a bare single-byte packet
NAK_BYTE = 0x0A

# TCX2+ NAK marker.  Packets starting with ``f8 ff`` are rejection responses
# from the bike, not a wrapper around valid data.  Format after CRC strip:
#
#     f8 ff [echoed_param_id_be: 2B] [reason_code: 1B] [zeros: 13B]
#
# The native app calls this ``isNakPacket`` (see ProtocolSessionTCX2 in
# libturbo-core.so).  Earlier versions of this library treated ``f8 ff`` as a
# "system response envelope" and parsed the reason byte as data — that was
# wrong and produced bogus telemetry (e.g. SoC=5%, capacity=4Wh).
NAK_PREFIX = b"\xf8\xff"
REALTIME_PREFIX = b"\xf8\xf4"

# Backwards-compatible alias.  Older code referred to NAK_PREFIX as a
# "clear-prefix" envelope.  Keep the name so existing imports don't break.
CLEAR_PREFIX = NAK_PREFIX


def compute_crc16_ccitt(data: bytes | bytearray) -> int:
    """Compute CRC-16/CCITT-FALSE over *data*. Returns a 16-bit integer."""
    return binascii.crc_hqx(data, _CRC_INIT)


def pack_tcx(payload: bytes | bytearray) -> bytes:
    """
    Frame a payload for TCX2/TCX3/TCX4 transmission.

    Pads *payload* with zeros to 18 bytes, computes CRC-16/CCITT-FALSE,
    and appends it as 2 bytes little-endian.  Returns exactly 20 bytes.

    Raises ValueError if *payload* exceeds 18 bytes.
    """
    if len(payload) > FRAMED_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload too long ({len(payload)} bytes), max {FRAMED_PAYLOAD_SIZE}"
        )
    padded = bytes(payload.ljust(FRAMED_PAYLOAD_SIZE, b"\x00"))
    crc = compute_crc16_ccitt(padded)
    return padded + crc.to_bytes(CRC_SIZE, "little")


def unpack_tcx(data: bytes | bytearray) -> bytes:
    """
    Validate and strip CRC from a 20-byte TCX2/TCX3/TCX4 packet.

    Returns the 18-byte payload if the CRC is valid.

    Raises ValueError if the packet is not 20 bytes or the CRC doesn't match.
    """
    if len(data) != FRAMED_PACKET_SIZE:
        raise ValueError(f"Expected {FRAMED_PACKET_SIZE} bytes, got {len(data)}")
    payload = data[:FRAMED_PAYLOAD_SIZE]
    received_crc = int.from_bytes(data[FRAMED_PAYLOAD_SIZE:], "little")
    expected_crc = compute_crc16_ccitt(payload)
    if received_crc != expected_crc:
        raise ValueError(
            f"CRC mismatch: received 0x{received_crc:04X}, "
            f"expected 0x{expected_crc:04X}"
        )
    return bytes(payload)


def is_framed_packet(data: bytes | bytearray) -> bool:
    """
    Check if *data* is a 20-byte CRC-framed TCX packet with valid CRC.

    This replaces the old heuristic of checking for a ``0xF8 0xFF`` header.
    """
    if len(data) != FRAMED_PACKET_SIZE:
        return False
    payload = data[:FRAMED_PAYLOAD_SIZE]
    received_crc = int.from_bytes(data[FRAMED_PAYLOAD_SIZE:], "little")
    return received_crc == compute_crc16_ccitt(payload)


def strip_clear_prefix(data: bytes | bytearray) -> bytes:
    """Strip the ``f8 ff`` prefix if present.

    .. deprecated:: 0.5.0
       The ``f8 ff`` prefix marks a NAK (rejection) packet, not a wrapper
       around valid data.  Use :func:`is_nak_packet` instead.  This helper
       is retained for backwards compatibility but should not be used in
       new code on the parse path.

    Returns the data unchanged if the prefix is not present.
    """
    if len(data) >= 4 and data[:2] == NAK_PREFIX:
        return bytes(data[2:])
    return bytes(data)


def is_nak_packet(data: bytes | bytearray) -> bool:
    """Return True if *data* is a TCX2+ NAK rejection packet.

    NAK packets start with ``f8 ff`` and carry the echoed parameter ID plus
    a one-byte reason code.  See :data:`NAK_PREFIX`.
    """
    return len(data) >= 5 and data[0] == 0xF8 and data[1] == 0xFF


def is_realtime_packet(data: bytes | bytearray) -> bool:
    """Return True for a bundled TCX real-time ride-data packet."""
    return len(data) >= 3 and data[:2] == REALTIME_PREFIX


def parse_nak_packet(data: bytes | bytearray) -> tuple[int, int]:
    """Decode a TCX2+ NAK packet into ``(echoed_param_id, reason_code)``.

    *data* may include or omit the trailing CRC — only the first 5 bytes
    are read.  Caller is responsible for checking :func:`is_nak_packet`
    first; this function raises ``ValueError`` otherwise.
    """
    if not is_nak_packet(data):
        raise ValueError("Not a NAK packet (does not start with f8 ff)")
    param_id = int.from_bytes(data[2:4], "big")
    reason_code = data[4]
    return param_id, reason_code
