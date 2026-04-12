"""
Unit tests for framing.py — CRC-16/CCITT-FALSE framing for TCX2+ protocol.

Test vectors are from actual Vado 3.0 (2022) BLE captures.
"""

import pytest

from specialized_turbo.framing import (
    FRAMED_PACKET_SIZE,
    FRAMED_PAYLOAD_SIZE,
    compute_crc16_ccitt,
    is_framed_packet,
    pack_tcx,
    unpack_tcx,
)


class TestCRC16:
    def test_known_packet_battery_charge(self):
        """CRC from Vado 3.0 battery_charge_percent response."""
        # Full 20-byte packet: f8ff000c0500000000000000000000000000 e6ca
        # CRC is over the first 18 bytes
        payload = bytes.fromhex("f8ff000c0500000000000000000000000000")
        assert len(payload) == 18
        assert compute_crc16_ccitt(payload) == 0xCAE6

    def test_known_packet_battery_capacity(self):
        """CRC from Vado 3.0 pairing trigger read."""
        payload = bytes.fromhex("f8ff000004000000000000000000000000000000")[:18]
        assert compute_crc16_ccitt(payload) == 0x0D70

    def test_empty_data(self):
        crc = compute_crc16_ccitt(b"")
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_init_value_is_ccitt_false(self):
        """Verify we use CRC-16/CCITT-FALSE (init=0xFFFF), not XMODEM."""
        import binascii

        data = b"\x01\x02\x03"
        assert compute_crc16_ccitt(data) == binascii.crc_hqx(data, 0xFFFF)


class TestPackTCX:
    def test_short_payload_padded(self):
        result = pack_tcx(b"\x00\x0c\x05")
        assert len(result) == FRAMED_PACKET_SIZE
        # First bytes are our payload, rest padded with zeros
        assert result[:3] == b"\x00\x0c\x05"
        assert result[3:18] == b"\x00" * 15

    def test_full_payload(self):
        payload = bytes(range(18))
        result = pack_tcx(payload)
        assert len(result) == FRAMED_PACKET_SIZE
        assert result[:18] == payload

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="too long"):
            pack_tcx(b"\x00" * 19)

    def test_round_trip(self):
        payload = (
            b"\x00\x1a\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        packed = pack_tcx(payload)
        unpacked = unpack_tcx(packed)
        assert unpacked == payload

    def test_known_packet_round_trip(self):
        """The actual Vado 3.0 packet should round-trip."""
        full_packet = bytes.fromhex("f8ff000c0500000000000000000000000000e6ca")
        payload = unpack_tcx(full_packet)
        repacked = pack_tcx(payload)
        assert repacked == full_packet


class TestUnpackTCX:
    def test_valid_packet(self):
        packet = bytes.fromhex("f8ff000c0500000000000000000000000000e6ca")
        payload = unpack_tcx(packet)
        assert len(payload) == FRAMED_PAYLOAD_SIZE
        assert payload[:4] == b"\xf8\xff\x00\x0c"

    def test_wrong_size_raises(self):
        with pytest.raises(ValueError, match="Expected 20"):
            unpack_tcx(b"\x00" * 19)

    def test_bad_crc_raises(self):
        packet = bytes.fromhex("f8ff000c0500000000000000000000000000dead")
        with pytest.raises(ValueError, match="CRC mismatch"):
            unpack_tcx(packet)


class TestIsFramedPacket:
    def test_valid_framed(self):
        packet = bytes.fromhex("f8ff000c0500000000000000000000000000e6ca")
        assert is_framed_packet(packet) is True

    def test_wrong_size(self):
        assert is_framed_packet(b"\x00" * 19) is False
        assert is_framed_packet(b"\x00" * 21) is False

    def test_bad_crc(self):
        packet = bytes.fromhex("f8ff000c0500000000000000000000000000dead")
        assert is_framed_packet(packet) is False

    def test_tcu1_padded_not_framed(self):
        """TCU1 FF-padded 20-byte message should NOT match as framed."""
        data = bytes.fromhex("000c34" + "ff" * 17)
        assert is_framed_packet(data) is False
