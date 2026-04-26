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

# System response prefix — some bikes wrap request-read responses in
# an ``f8 ff`` envelope: ``[f8ff][param_id_be][data…][zero-pad][CRC]``.
# The prefix must be stripped before extracting the parameter ID.
CLEAR_PREFIX = b"\xf8\xff"


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
    """Strip the ``f8 ff`` system-response envelope if present.

    Some bikes (e.g. Vado 3.0 / TCX3) wrap every request-read response in
    a 2-byte ``\\xf8\\xff`` prefix before the parameter ID.  This function
    strips that prefix so the remaining bytes start with the param ID.

    Returns the data unchanged if the prefix is not present.
    """
    if len(data) >= 4 and data[:2] == CLEAR_PREFIX:
        return bytes(data[2:])
    return bytes(data)
