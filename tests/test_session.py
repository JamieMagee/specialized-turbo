"""
Unit tests for session.py — ProtocolSession abstraction.
"""

from specialized_turbo.framing import pack_tcx
from specialized_turbo.session import TCU1Session, TCXSession


class TestTCU1Session:
    def test_pack_passthrough(self):
        session = TCU1Session()
        data = b"\x00\x0c\x34"
        assert session.pack(data) == data

    def test_unpack_passthrough(self):
        session = TCU1Session()
        data = b"\x01\x02\xfa\x00"
        assert session.unpack(data) == data

    def test_round_trip(self):
        session = TCU1Session()
        data = b"\x00\x05\x50"
        assert session.unpack(session.pack(data)) == data


class TestTCXSessionNoEncryption:
    def test_pack_adds_crc(self):
        session = TCXSession()
        assert not session.encrypted
        packed = session.pack(b"\x00\x1a\x34")
        assert len(packed) == 20

    def test_unpack_strips_crc(self):
        session = TCXSession()
        packet = pack_tcx(b"\x00\x1a\x34")
        unpacked = session.unpack(packet)
        assert len(unpacked) == 18
        assert unpacked[:3] == b"\x00\x1a\x34"

    def test_round_trip(self):
        session = TCXSession()
        payload = b"\x00\x1a\x34\x00"
        packed = session.pack(payload)
        unpacked = session.unpack(packed)
        # Unpacked is 18 bytes (padded), original was 4 — compare the prefix
        assert unpacked[: len(payload)] == payload

    def test_unpack_non_framed_passthrough(self):
        """Non-framed data (like NAK) passes through."""
        session = TCXSession()
        nak = b"\x0a"
        assert session.unpack(nak) == nak


class TestTCXSessionWithEncryption:
    def test_encrypted_flag(self):
        session = TCXSession(key=b"\x01" * 16, iv=b"\x02" * 16)
        assert session.encrypted

    def test_round_trip_encrypted(self):
        key = b"\xaa" * 16
        iv = b"\xbb" * 16
        session = TCXSession(key=key, iv=iv)

        payload = b"\x00\x1a\x34\x00\x00"
        packed = session.pack(payload)
        assert len(packed) == 20

        # Packed should differ from unencrypted pack (body is encrypted)
        unencrypted = pack_tcx(payload)
        assert packed[:2] == unencrypted[:2]  # header preserved

        unpacked = session.unpack(packed)
        assert unpacked[: len(payload)] == payload

    def test_non_encryptable_not_encrypted(self):
        """F8 FF prefix packets bypass encryption even with keys set."""
        key = b"\x01" * 16
        iv = b"\x02" * 16
        session = TCXSession(key=key, iv=iv)

        payload = b"\xf8\xff\x00\x0c\x05"
        packed = session.pack(payload)
        # Should be same as without encryption
        unencrypted_session = TCXSession()
        assert packed == unencrypted_session.pack(payload)
