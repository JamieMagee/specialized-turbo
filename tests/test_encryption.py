"""
Unit tests for encryption.py — AES-128-CTR encryption for TCX2+ protocol.
"""

import pytest

from specialized_turbo.encryption import (
    decrypt_packet,
    encrypt_packet,
    is_encryptable,
)
from specialized_turbo.framing import FRAMED_PACKET_SIZE, pack_tcx


class TestIsEncryptable:
    def test_empty_data(self):
        assert is_encryptable(b"") is False

    def test_nak_byte(self):
        assert is_encryptable(b"\x0a") is False

    def test_f8ff_prefix(self):
        assert is_encryptable(b"\xf8\xff\x00\x0c") is False

    def test_normal_packet(self):
        assert is_encryptable(b"\x00\x1a\x34") is True

    def test_full_packet(self):
        packet = pack_tcx(b"\x00\x1a\x34")
        assert is_encryptable(packet) is True

    def test_control_frame_get_new_vi_stays_clear(self):
        """0x0A00 (GET_NEW_VI) is a control frame -> never encrypted."""
        assert is_encryptable(b"\x0a\x00\x00") is False
        assert is_encryptable(pack_tcx(b"\x0a\x00")) is False

    def test_control_frame_protocol_version_stays_clear(self):
        """0x0A01 (HMI_PROTOCOL_VERSION) is a control frame -> never encrypted."""
        assert is_encryptable(b"\x0a\x01\x12\x03") is False
        assert is_encryptable(pack_tcx(b"\x0a\x01")) is False

    def test_any_0a_high_byte_stays_clear(self):
        """Every 0x0Axx frame is clear (matches native ``*begin != 0x0A``)."""
        assert is_encryptable(b"\x0a\xff" + b"\x00" * 18) is False


class TestEncryptDecryptRoundTrip:
    """AES-CTR is symmetric: encrypt(decrypt(x)) == x and decrypt(encrypt(x)) == x."""

    def test_round_trip(self):
        key = b"\x01" * 16
        iv = b"\x02" * 16
        plaintext = pack_tcx(b"\x00\x1a\x34\x00\x00\x00\x00\x00")

        encrypted = encrypt_packet(key, iv, plaintext)
        # Header preserved, body changed
        assert encrypted[:2] == plaintext[:2]
        assert encrypted[2:] != plaintext[2:]

        decrypted = decrypt_packet(key, iv, encrypted)
        assert decrypted == plaintext

    def test_different_keys_produce_different_output(self):
        key1 = b"\x01" * 16
        key2 = b"\x03" * 16
        iv = b"\x02" * 16
        plaintext = pack_tcx(b"\x00\x1a\x34")

        enc1 = encrypt_packet(key1, iv, plaintext)
        enc2 = encrypt_packet(key2, iv, plaintext)
        assert enc1 != enc2

    def test_non_encryptable_passes_through(self):
        key = b"\x01" * 16
        iv = b"\x02" * 16
        # F8 FF prefix — should pass through unchanged
        packet = pack_tcx(b"\xf8\xff\x00\x0c\x05")
        encrypted = encrypt_packet(key, iv, packet)
        assert encrypted == packet

    def test_wrong_size_raises(self):
        key = b"\x01" * 16
        iv = b"\x02" * 16
        with pytest.raises(ValueError, match="Expected 20"):
            encrypt_packet(key, iv, b"\x00" * 19)


class TestEncryptPacketHeaderPreservation:
    def test_header_bytes_unchanged(self):
        """First 2 bytes (parameter ID) must be in the clear."""
        key = bytes(range(16))
        iv = bytes(range(16, 32))
        plaintext = pack_tcx(b"\xab\xcd\x01\x02\x03")

        encrypted = encrypt_packet(key, iv, plaintext)
        assert encrypted[0] == 0xAB
        assert encrypted[1] == 0xCD
        assert len(encrypted) == FRAMED_PACKET_SIZE
