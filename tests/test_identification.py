"""
Unit tests for the official TCX2+ identification state machine.

Uses deterministic synthetic vectors that mirror the official app's wire
behaviour: 0x0A control frames stay clear, ``GET_NEW_VI`` installs a 16-byte
IV, ``HMI_PROTOCOL_VERSION`` selects the revision, and every other read is
AES-CTR encrypted (clear 2-byte header, encrypted body).  A fake bike packs
its responses through a real :class:`TCXSession`, so the crypto path is
exercised end to end.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import pytest
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from specialized_turbo.bike_info import BikeInfo
from specialized_turbo.encryption import is_encryptable
from specialized_turbo.framing import pack_tcx
from specialized_turbo.identification import (
    IDENTIFICATION_PARAMETER_SEQUENCE,
    IV_LENGTH,
    DecryptionError,
    IdentificationNakError,
    IdentificationPhase,
    IdentificationResult,
    IncompleteBikeInfoError,
    MalformedIVError,
    MalformedProtocolResponseError,
    MissingEncryptionKeyError,
    TCXIdentification,
    UnsupportedGenerationError,
    UnsupportedRevisionError,
    WireMessage,
    identify,
    parse_wire_message,
)
from specialized_turbo.keystore.models import BikeEncryptionKey
from specialized_turbo.parameters import BikeParameter, encode_parameter_id
from specialized_turbo.protocol import (
    BLEProfile,
    BLEServiceID,
    get_service_characteristics,
)
from specialized_turbo.session import TCXSession
from specialized_turbo.transport import (
    NotificationCallback,
    TCXNotificationTransport,
    TCXTransportDisconnectedError,
)
from specialized_turbo.wire_profiles import ProtocolRevision, TCXGeneration, wire_id_for

# Deterministic synthetic key + IV (never real key material).
KEY_RAW = b"\x11" * 16
WRONG_KEY_RAW = b"\x99" * 16
IV = b"\x22" * 16

# TCX2 revision 0x12 -> SYSTEM_MOTOR_TYPE resolves to wire 0x08D2.
GENERATION = TCXGeneration.TCX2
REVISION = 0x12
USB_REVISION = 0x03

WIRE_GET_NEW_VI = 0x0A00
WIRE_PROTOCOL_VERSION = 0x0A01


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass
class _FakeCharacteristic:
    uuid: str


class _FakeClient:
    def __init__(self) -> None:
        self.callbacks: dict[str, NotificationCallback] = {}
        self.writes: list[tuple[str, bytes]] = []
        self.on_write: Callable[[str, bytes], None] | None = None

    async def start_notify(
        self, characteristic: str, callback: NotificationCallback
    ) -> None:
        self.callbacks[characteristic] = callback

    async def stop_notify(self, characteristic: str) -> None:
        self.callbacks.pop(characteristic, None)

    async def write_gatt_char(
        self, characteristic: str, data: bytes, response: bool | None = None
    ) -> None:
        packet = bytes(data)
        self.writes.append((characteristic, packet))
        if self.on_write is not None:
            self.on_write(characteristic, packet)

    def notify(self, service_id: BLEServiceID, data: bytes) -> None:
        uuid = get_service_characteristics(BLEProfile.TCX, service_id).notify
        callback = self.callbacks[uuid]
        characteristic = cast(BleakGATTCharacteristic, _FakeCharacteristic(uuid))
        callback(characteristic, bytearray(data))


class _FakeBike:
    """Answers wire requests, packing responses like a real encrypted bike."""

    def __init__(self, client: _FakeClient, *, key: bytes = KEY_RAW, iv: bytes = IV):
        self._client = client
        self._session = TCXSession(key=key, iv=iv)
        self._payloads: dict[int, bytes] = {}
        self._raw: dict[int, bytes] = {}
        self._naks: dict[int, int] = {}
        self.requests: list[int] = []
        self.request_frames: dict[int, bytes] = {}
        client.on_write = self._on_write

    def set_body(self, wire_id: int, body: bytes) -> None:
        self._payloads[wire_id] = encode_parameter_id(wire_id) + bytes(body)

    def set_raw_frame(self, wire_id: int, frame: bytes) -> None:
        self._raw[wire_id] = frame

    def set_nak(self, wire_id: int, reason: int) -> None:
        self._naks[wire_id] = reason

    def _on_write(self, _characteristic: str, packet: bytes) -> None:
        wire_id = int.from_bytes(packet[:2], "big")
        self.requests.append(wire_id)
        self.request_frames[wire_id] = packet
        if wire_id in self._raw:
            frame = self._raw[wire_id]
        elif wire_id in self._naks:
            nak = (
                b"\xf8\xff"
                + encode_parameter_id(wire_id)
                + bytes([self._naks[wire_id]])
            )
            frame = self._session.pack(nak)
        elif wire_id in self._payloads:
            frame = self._session.pack(self._payloads[wire_id])
        else:
            return  # no response -> request stays pending
        self._client.notify(BLEServiceID.REQUEST, frame)


def _complete_bike_info(
    generation: TCXGeneration | None = GENERATION, *, complete: bool = True
) -> BikeInfo:
    return BikeInfo(
        name="SPECIALIZED",
        bike_name="LEVO2 SPECIALIZED",
        is_bike=True,
        complete=complete,
        hmi_serial="1234",
        hmi_hardware_version="B.3.3",
        ble_profile=BLEProfile.TCX,
        tcx_generation=generation,
    )


def _wire(param: BikeParameter, revision: int | None = None) -> int:
    return wire_id_for(param, GENERATION, revision)


def _healthy_bike(client: _FakeClient) -> _FakeBike:
    """A bike that answers every step of a successful handshake."""
    bike = _FakeBike(client)
    bike.set_body(WIRE_GET_NEW_VI, IV)
    bike.set_body(WIRE_PROTOCOL_VERSION, bytes([REVISION, USB_REVISION]))
    bike.set_body(_wire(BikeParameter.SYSTEM_STATE), bytes([4]))
    bike.set_body(_wire(BikeParameter.BATTERY1_FIRMWARE), bytes([1, 2, 3]))
    bike.set_body(_wire(BikeParameter.SYSTEM_HMI_HW_VERSION), b"B.3.3")
    bike.set_body(_wire(BikeParameter.SYSTEM_MOTOR_TYPE, REVISION), bytes([7]))
    bike.set_body(_wire(BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER), b"SN12345")
    return bike


def _transport(client: _FakeClient) -> TCXNotificationTransport:
    return TCXNotificationTransport(cast(BleakClient, client), request_timeout=1.0)


# ---------------------------------------------------------------------------
# Control frame stays clear (requirement 1 / 6)
# ---------------------------------------------------------------------------


class TestControlFramesClear:
    def test_get_new_vi_request_is_not_encrypted(self):
        session = TCXSession(key=KEY_RAW, iv=IV)
        clear = TCXSession()
        payload = encode_parameter_id(WIRE_GET_NEW_VI) + b"\x00"
        assert session.pack(payload) == clear.pack(payload)

    def test_protocol_version_request_is_not_encrypted(self):
        session = TCXSession(key=KEY_RAW, iv=IV)
        clear = TCXSession()
        payload = encode_parameter_id(WIRE_PROTOCOL_VERSION)
        assert session.pack(payload) == clear.pack(payload)

    def test_iv_response_body_is_clear(self):
        bike_session = TCXSession(key=KEY_RAW, iv=IV)
        frame = bike_session.pack(encode_parameter_id(WIRE_GET_NEW_VI) + IV)
        assert not is_encryptable(frame)
        # IV bytes are readable in the clear.
        assert frame[2 : 2 + IV_LENGTH] == IV


# ---------------------------------------------------------------------------
# Full successful handshake (requirement 3 / 6: all seven steps)
# ---------------------------------------------------------------------------


class TestFullHandshake:
    async def test_seven_steps_in_order(self):
        client = _FakeClient()
        bike = _healthy_bike(client)
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        result = await ident.run()

        assert bike.requests == [
            WIRE_GET_NEW_VI,
            WIRE_PROTOCOL_VERSION,
            _wire(BikeParameter.SYSTEM_STATE),
            _wire(BikeParameter.BATTERY1_FIRMWARE),
            _wire(BikeParameter.SYSTEM_HMI_HW_VERSION),
            _wire(BikeParameter.SYSTEM_MOTOR_TYPE, REVISION),
            _wire(BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER),
        ]
        assert len(bike.requests) == len(IDENTIFICATION_PARAMETER_SEQUENCE) == 7
        assert ident.phase is IdentificationPhase.COMPLETE
        assert isinstance(result, IdentificationResult)

    async def test_parsed_result_fields(self):
        client = _FakeClient()
        _healthy_bike(client)
        transport = _transport(client)
        result = await identify(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        assert result.generation is TCXGeneration.TCX2
        assert result.protocol_revision == ProtocolRevision(GENERATION, REVISION)
        assert result.ble_revision == REVISION
        assert result.usb_revision == USB_REVISION
        assert result.system_state == 4
        assert result.battery_firmware == (1, 2, 3)
        assert result.hmi_hardware_version == "B.3.3"
        assert result.motor_type == 7
        assert result.ebike_serial == "SN12345"
        assert result.encrypted is True

    async def test_encrypted_session_installed_on_transport(self):
        client = _FakeClient()
        _healthy_bike(client)
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        await ident.run()

        assert ident.session is not None
        assert ident.session.encrypted
        assert transport.session is ident.session


# ---------------------------------------------------------------------------
# IV installation + revision selection (requirement 6)
# ---------------------------------------------------------------------------


class TestIVInstallation:
    async def test_iv_from_get_new_vi_drives_the_session_key(self):
        """The AES session uses the keystore key + the installed IV.

        Proven behaviourally: the negotiated session encrypts identically to a
        fresh session built from the provided key and the IV carried in the
        GET_NEW_VI body -- never anything derived from param 14.
        """
        client = _FakeClient()
        _healthy_bike(client)
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        await ident.run()

        expected = TCXSession(key=KEY_RAW, iv=IV)
        probe = encode_parameter_id(_wire(BikeParameter.SYSTEM_STATE)) + b"\x04"
        assert ident.session is not None
        assert ident.session.pack(probe) == expected.pack(probe)

    async def test_get_new_vi_request_carries_required_zero_byte(self):
        client = _FakeClient()
        bike = _healthy_bike(client)
        transport = _transport(client)

        await identify(transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW))

        request = bike.request_frames[WIRE_GET_NEW_VI]
        from specialized_turbo.framing import unpack_tcx

        assert unpack_tcx(request)[:3] == encode_parameter_id(WIRE_GET_NEW_VI) + b"\x00"


class TestRevisionSelection:
    @pytest.mark.parametrize(
        "revision, expected_motor_wire",
        [(0x12, 0x08D2), (0x1D, 0x08D1)],
    )
    async def test_revision_selects_motor_type_wire(
        self, revision: int, expected_motor_wire: int
    ):
        client = _FakeClient()
        bike = _FakeBike(client)
        bike.set_body(WIRE_GET_NEW_VI, IV)
        bike.set_body(WIRE_PROTOCOL_VERSION, bytes([revision, USB_REVISION]))
        bike.set_body(_wire(BikeParameter.SYSTEM_STATE), bytes([4]))
        bike.set_body(_wire(BikeParameter.BATTERY1_FIRMWARE), bytes([1, 2, 3]))
        bike.set_body(_wire(BikeParameter.SYSTEM_HMI_HW_VERSION), b"B.3.3")
        bike.set_body(_wire(BikeParameter.SYSTEM_MOTOR_TYPE, revision), bytes([9]))
        bike.set_body(_wire(BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER), b"SN1")
        transport = _transport(client)

        result = await identify(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        assert result.protocol_revision.revision == revision
        assert expected_motor_wire in bike.requests
        assert result.motor_type == 9


# ---------------------------------------------------------------------------
# AES header clear / body encrypted (requirement 6)
# ---------------------------------------------------------------------------


class TestAesLayout:
    async def test_system_state_request_header_clear_body_encrypted(self):
        client = _FakeClient()
        bike = _healthy_bike(client)
        transport = _transport(client)

        await identify(transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW))

        wire = _wire(BikeParameter.SYSTEM_STATE)
        sent = bike.request_frames[wire]
        clear = pack_tcx(encode_parameter_id(wire))
        assert sent[:2] == encode_parameter_id(wire)  # header clear
        assert sent[2:] != clear[2:]  # body encrypted
        assert len(sent) == 20


# ---------------------------------------------------------------------------
# SOC wire 0500 profile-aware parse (requirement 5 / 6)
# ---------------------------------------------------------------------------


class TestProfileAwareParsing:
    def test_soc_wire_0500_reverse_maps(self):
        payload = (encode_parameter_id(0x0500) + bytes([49])).ljust(18, b"\x00")
        msg = parse_wire_message(payload, TCXGeneration.TCX2)
        assert msg.wire_id == 0x0500
        assert msg.parameter is BikeParameter.BATTERY1_STATE_OF_CHARGE
        assert msg.value == 49
        assert msg.nak_reason is None

    def test_system_state_wire_reverse_maps(self):
        payload = encode_parameter_id(0x0801) + bytes([2])
        msg = parse_wire_message(payload, TCXGeneration.TCX2)
        assert msg.parameter is BikeParameter.SYSTEM_STATE
        assert msg.value == 2

    def test_unknown_wire_id_has_no_parameter(self):
        payload = encode_parameter_id(0xFFFF) + bytes([1])
        msg = parse_wire_message(payload, TCXGeneration.TCX2)
        assert msg.parameter is None
        assert msg.value is None

    def test_nak_payload_reverse_maps_echoed_wire(self):
        payload = b"\xf8\xff" + encode_parameter_id(0x0500) + bytes([0x05])
        msg = parse_wire_message(payload, TCXGeneration.TCX2)
        assert msg.is_nak
        assert msg.nak_reason == 0x05
        assert msg.wire_id == 0x0500
        assert msg.parameter is BikeParameter.BATTERY1_STATE_OF_CHARGE

    def test_short_payload_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_wire_message(b"\x05", TCXGeneration.TCX2)

    def test_wire_message_fields(self):
        msg = WireMessage(0x0500, BikeParameter.BATTERY1_STATE_OF_CHARGE, b"\x31", 49)
        assert msg.wire_id == 0x0500
        assert msg.parameter is BikeParameter.BATTERY1_STATE_OF_CHARGE
        assert msg.data == b"\x31"
        assert msg.value == 49
        assert msg.is_nak is False


# ---------------------------------------------------------------------------
# Wrong / missing key errors (requirement 6)
# ---------------------------------------------------------------------------


class TestKeyErrors:
    async def test_missing_key_raises_before_ble(self):
        client = _FakeClient()
        _healthy_bike(client)
        transport = _transport(client)
        ident = TCXIdentification(transport, _complete_bike_info(), None)

        with pytest.raises(MissingEncryptionKeyError):
            await ident.run()
        assert ident.phase is IdentificationPhase.FAILED
        assert client.writes == []  # never touched the bike

    async def test_wrong_key_fails_first_encrypted_read(self):
        client = _FakeClient()
        _healthy_bike(client)  # bike encrypts with the correct key
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=WRONG_KEY_RAW)
        )

        with pytest.raises(DecryptionError):
            await ident.run()
        # IV + revision are clear, so they succeed; failure is at SYSTEM_STATE.
        assert ident.phase is IdentificationPhase.FAILED
        assert ident.failed_phase is IdentificationPhase.READ_SYSTEM_STATE


# ---------------------------------------------------------------------------
# Precondition errors (requirement 2)
# ---------------------------------------------------------------------------


class TestPreconditionErrors:
    async def test_incomplete_bike_info(self):
        client = _FakeClient()
        transport = _transport(client)
        ident = TCXIdentification(
            transport,
            _complete_bike_info(complete=False),
            BikeEncryptionKey(raw=KEY_RAW),
        )
        with pytest.raises(IncompleteBikeInfoError):
            await ident.run()
        assert ident.phase is IdentificationPhase.FAILED

    async def test_unsupported_generation(self):
        client = _FakeClient()
        transport = _transport(client)
        ident = TCXIdentification(
            transport,
            _complete_bike_info(generation=None),
            BikeEncryptionKey(raw=KEY_RAW),
        )
        with pytest.raises(UnsupportedGenerationError):
            await ident.run()


# ---------------------------------------------------------------------------
# NAK + malformed responses (requirement 6)
# ---------------------------------------------------------------------------


class TestNakAndMalformed:
    async def test_nak_on_encrypted_read(self):
        client = _FakeClient()
        bike = _FakeBike(client)
        bike.set_body(WIRE_GET_NEW_VI, IV)
        bike.set_body(WIRE_PROTOCOL_VERSION, bytes([REVISION, USB_REVISION]))
        bike.set_nak(_wire(BikeParameter.SYSTEM_STATE), 0x05)
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        with pytest.raises(IdentificationNakError) as excinfo:
            await ident.run()
        assert excinfo.value.wire_id == _wire(BikeParameter.SYSTEM_STATE)
        assert excinfo.value.reason == 0x05
        assert excinfo.value.phase is IdentificationPhase.READ_SYSTEM_STATE

    async def test_malformed_iv_response(self):
        client = _FakeClient()
        bike = _FakeBike(client)
        # Valid header, corrupted CRC -> cannot unframe -> malformed IV.
        frame = bytearray(pack_tcx(encode_parameter_id(WIRE_GET_NEW_VI) + IV))
        frame[5] ^= 0xFF
        bike.set_raw_frame(WIRE_GET_NEW_VI, bytes(frame))
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        with pytest.raises(MalformedIVError):
            await ident.run()
        assert ident.phase is IdentificationPhase.FAILED
        assert ident.failed_phase is IdentificationPhase.INSTALL_IV

    async def test_malformed_protocol_response(self):
        client = _FakeClient()
        bike = _FakeBike(client)
        bike.set_body(WIRE_GET_NEW_VI, IV)
        frame = bytearray(
            pack_tcx(encode_parameter_id(WIRE_PROTOCOL_VERSION) + bytes([REVISION, 3]))
        )
        frame[6] ^= 0xFF
        bike.set_raw_frame(WIRE_PROTOCOL_VERSION, bytes(frame))
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        with pytest.raises(MalformedProtocolResponseError):
            await ident.run()

    async def test_unsupported_revision(self):
        client = _FakeClient()
        bike = _FakeBike(client)
        bike.set_body(WIRE_GET_NEW_VI, IV)
        bike.set_body(WIRE_PROTOCOL_VERSION, bytes([0x99, USB_REVISION]))
        transport = _transport(client)
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        with pytest.raises(UnsupportedRevisionError):
            await ident.run()
        assert ident.phase is IdentificationPhase.FAILED


# ---------------------------------------------------------------------------
# Disconnect mid-handshake (requirement 6)
# ---------------------------------------------------------------------------


class TestDisconnect:
    async def test_disconnect_fails_immediately(self):
        client = _FakeClient()
        _FakeBike(client)  # answers nothing -> first request stays pending
        transport = TCXNotificationTransport(
            cast(BleakClient, client), request_timeout=60
        )
        ident = TCXIdentification(
            transport, _complete_bike_info(), BikeEncryptionKey(raw=KEY_RAW)
        )

        task = asyncio.create_task(ident.run())
        while WIRE_GET_NEW_VI not in client.writes and not task.done():
            # write frames record the wire id in the (char, packet) tuples
            await asyncio.sleep(0)
            if any(
                int.from_bytes(p[:2], "big") == WIRE_GET_NEW_VI
                for _, p in client.writes
            ):
                break

        transport.mark_disconnected()

        with pytest.raises(TCXTransportDisconnectedError):
            await task
        assert ident.phase is IdentificationPhase.FAILED
