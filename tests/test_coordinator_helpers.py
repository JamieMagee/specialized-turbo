"""
Unit tests for the profile-aware TCX parsing/polling primitives in
``coordinator_helpers``.

Covers replacing the legacy "wire id == BikeParameter enum value" assumption
with ``ProtocolRevision``-aware wire-id resolution (:mod:`specialized_turbo
.wire_profiles`) and reverse-mapping (:func:`specialized_turbo.identification
.parse_wire_message`), plus the revision-aware TCX polling helper and the
now-simplified (no false key derivation) ``identify_tcx`` legacy shim.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import pytest
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from specialized_turbo.coordinator_helpers import (
    TCX_POLL_PARAMS,
    identify_tcx,
    parse_tcx_notification,
    parse_tcx_wire_payload,
    poll_tcu1,
    poll_tcx,
)
from specialized_turbo.models import TelemetrySnapshot
from specialized_turbo.parameters import BikeParameter, encode_parameter_id
from specialized_turbo.protocol import (
    BatteryChannel,
    BLEProfile,
    BLEServiceID,
    ParsedMessage,
    Sender,
    build_request,
    get_service_characteristics,
)
from specialized_turbo.session import TCXSession
from specialized_turbo.transport import (
    NotificationCallback,
    TCXNotificationTransport,
    TCXTransportDisconnectedError,
)
from specialized_turbo.wire_profiles import ProtocolRevision, TCXGeneration, wire_id_for

KEY_RAW = b"\x11" * 16
IV = b"\x22" * 16

# BATTERY1_STATE_OF_CHARGE (BikeParameter 26) is wire id 0x0500 for every
# TCX generation -- *not* 0x001a, which is what the legacy enum-ID
# assumption would (wrongly) use.
SOC_WIRE_ID = 0x0500

GENERATION = TCXGeneration.TCX2
REVISION = 0x12  # known TCX2 revision; SYSTEM_MOTOR_TYPE etc. vary by revision


def _revision(
    generation: TCXGeneration = GENERATION, revision: int = REVISION
) -> ProtocolRevision:
    return ProtocolRevision(generation=generation, revision=revision)


# ---------------------------------------------------------------------------
# parse_tcx_wire_payload / parse_tcx_notification (requirement 1)
# ---------------------------------------------------------------------------


class TestParseTcxWirePayload:
    def test_soc_notification_maps_to_battery_field(self) -> None:
        """0x0500 (the real wire id) resolves to the battery SoC field."""
        payload = encode_parameter_id(SOC_WIRE_ID) + bytes([49])

        msg = parse_tcx_wire_payload(payload, _revision())

        assert msg.field_name == "battery_charge_percent"
        assert msg.converted_value == 49
        assert msg.raw_value == 49
        assert msg.nak_reason is None

    def test_legacy_enum_id_would_have_missed_this_field(self) -> None:
        """Sanity check: the wire id really isn't the BikeParameter enum value."""
        assert int(BikeParameter.BATTERY1_STATE_OF_CHARGE) == 26
        assert SOC_WIRE_ID != int(BikeParameter.BATTERY1_STATE_OF_CHARGE)

    @pytest.mark.parametrize(
        ("generation", "revision"),
        [
            (TCXGeneration.TCX2, 0x12),
            (TCXGeneration.TCX2, 0x1D),  # 29
            (TCXGeneration.TCX3, 0x06),
            (TCXGeneration.TCX4, 0x01),
        ],
    )
    def test_resolves_across_generations_and_revisions(
        self, generation: TCXGeneration, revision: int
    ) -> None:
        """SoC has one generation-wide wire id; range/consumption vary by revision."""
        rev = ProtocolRevision(generation=generation, revision=revision)

        soc_payload = encode_parameter_id(SOC_WIRE_ID) + bytes([61])
        soc_msg = parse_tcx_wire_payload(soc_payload, rev)
        assert soc_msg.field_name == "battery_charge_percent"
        assert soc_msg.converted_value == 61

        range_wire = wire_id_for(BikeParameter.SYSTEM_RANGE_LONG, generation, revision)
        range_payload = encode_parameter_id(range_wire) + bytes([100, 0])
        range_msg = parse_tcx_wire_payload(range_payload, rev)
        assert range_msg.field_name == "range_long"
        assert range_msg.converted_value == pytest.approx(10.0)

    def test_nak_is_flagged_not_parsed_as_data(self) -> None:
        payload = b"\xf8\xff" + encode_parameter_id(SOC_WIRE_ID) + bytes([0x05])

        msg = parse_tcx_wire_payload(payload, _revision())

        assert msg.nak_reason == 0x05
        assert msg.field_name is None
        assert msg.converted_value is None
        assert msg.raw_value == SOC_WIRE_ID

    def test_unknown_wire_id_surfaces_raw_bytes_without_a_name(self) -> None:
        unknown_wire_id = 0xFEED
        payload = encode_parameter_id(unknown_wire_id) + bytes([1, 2])

        msg = parse_tcx_wire_payload(payload, _revision())

        assert msg.field_name is None
        assert msg.nak_reason is None
        # Little-endian [1, 2] -> 0x0201
        assert msg.raw_value == 0x0201
        assert msg.converted_value == 0x0201

    def test_zero_length_data_yields_field_name_with_no_value(self) -> None:
        payload = encode_parameter_id(SOC_WIRE_ID)

        msg = parse_tcx_wire_payload(payload, _revision())

        assert msg.field_name == "battery_charge_percent"
        assert msg.converted_value is None

    def test_encrypted_session_data_round_trips(self) -> None:
        """parse_tcx_notification unpacks (CRC-strip + decrypt) then parses."""
        session = TCXSession(key=KEY_RAW, iv=IV)
        payload = encode_parameter_id(SOC_WIRE_ID) + bytes([77])
        packet = session.pack(payload)

        # The 2-byte wire id header stays clear; the body is encrypted.
        assert packet[:2] == encode_parameter_id(SOC_WIRE_ID)
        assert packet[2:4] != bytes([77]) + b"\x00"

        msg = parse_tcx_notification(session, packet, _revision())

        assert msg.field_name == "battery_charge_percent"
        assert msg.converted_value == 77

    def test_encrypted_nak_stays_clear_and_is_flagged(self) -> None:
        session = TCXSession(key=KEY_RAW, iv=IV)
        nak = b"\xf8\xff" + encode_parameter_id(SOC_WIRE_ID) + bytes([0x07])
        packet = session.pack(nak)

        msg = parse_tcx_notification(session, packet, _revision())

        assert msg.nak_reason == 0x07
        assert msg.field_name is None

    def test_payload_shorter_than_two_bytes_raises(self) -> None:
        """A malformed/short response (e.g. a stray bare-byte NAK) can't be
        parsed as a wire-id header; callers (poll_tcx) must contain this."""
        with pytest.raises(ValueError, match="too short"):
            parse_tcx_wire_payload(b"\x05", _revision())


# ---------------------------------------------------------------------------
# poll_tcx (requirement 2)
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
    """Answers wire-id requests with unencrypted, CRC-framed responses."""

    def __init__(self, client: _FakeClient) -> None:
        self._client = client
        self._session = TCXSession()
        self._payloads: dict[int, bytes] = {}
        self._naks: dict[int, int] = {}
        self.requests: list[int] = []
        client.on_write = self._on_write

    def set_value(self, wire_id: int, body: bytes) -> None:
        self._payloads[wire_id] = encode_parameter_id(wire_id) + bytes(body)

    def set_nak(self, wire_id: int, reason: int) -> None:
        self._naks[wire_id] = reason

    def _on_write(self, _characteristic: str, packet: bytes) -> None:
        wire_id = int.from_bytes(packet[:2], "big")
        self.requests.append(wire_id)
        if wire_id in self._naks:
            frame = self._session.pack(
                b"\xf8\xff"
                + encode_parameter_id(wire_id)
                + bytes([self._naks[wire_id]])
            )
        elif wire_id in self._payloads:
            frame = self._session.pack(self._payloads[wire_id])
        else:
            return  # no response configured -> request stays pending
        self._client.notify(BLEServiceID.REQUEST, frame)


def _transport(client: _FakeClient) -> TCXNotificationTransport:
    return TCXNotificationTransport(cast(BleakClient, client), request_timeout=1.0)


def _wire_id(param: BikeParameter, rev: ProtocolRevision) -> int:
    return wire_id_for(param, rev.generation, rev.revision)


class TestPollTcx:
    async def test_polls_wire_mapped_ids_and_updates_snapshot(self) -> None:
        client = _FakeClient()
        bike = _FakeBike(client)
        rev = _revision()
        for param in TCX_POLL_PARAMS:
            bike.set_value(_wire_id(param, rev), bytes([5]))
        transport = _transport(client)
        snapshot = TelemetrySnapshot()

        updated = await poll_tcx(transport, snapshot, rev)

        assert updated is True
        # Every request used the real wire id, not the BikeParameter enum id.
        assert bike.requests == [_wire_id(p, rev) for p in TCX_POLL_PARAMS]
        assert SOC_WIRE_ID in bike.requests
        assert int(BikeParameter.BATTERY1_STATE_OF_CHARGE) not in bike.requests
        assert snapshot.battery.charge_pct == 5
        assert snapshot.message_count > 0

    async def test_nak_is_skipped_without_touching_snapshot(self) -> None:
        client = _FakeClient()
        bike = _FakeBike(client)
        rev = _revision()
        soc_wire = _wire_id(BikeParameter.BATTERY1_STATE_OF_CHARGE, rev)
        bike.set_nak(soc_wire, 0x05)
        for param in TCX_POLL_PARAMS:
            wire = _wire_id(param, rev)
            if wire != soc_wire:
                bike.set_value(wire, bytes([9]))
        transport = _transport(client)
        snapshot = TelemetrySnapshot()

        updated = await poll_tcx(transport, snapshot, rev)

        assert updated is True  # other fields still updated
        assert snapshot.battery.charge_pct is None
        assert snapshot.motor.motor_power_w == 9

    async def test_unmapped_parameter_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import specialized_turbo.coordinator_helpers as ch

        # BATTERY1_FAULT_LOG_ENTRIES has no wire id in any generation/revision.
        monkeypatch.setattr(
            ch, "TCX_POLL_PARAMS", (BikeParameter.BATTERY1_FAULT_LOG_ENTRIES,)
        )
        client = _FakeClient()
        transport = _transport(client)
        snapshot = TelemetrySnapshot()

        updated = await ch.poll_tcx(transport, snapshot, _revision())

        assert updated is False
        assert client.writes == []  # never even attempted a request

    async def test_malformed_payload_is_contained_to_current_parameter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A parse failure (e.g. an unexpectedly short/malformed response)
        for one parameter must not abort polling the rest."""
        import specialized_turbo.coordinator_helpers as ch

        client = _FakeClient()
        bike = _FakeBike(client)
        rev = _revision()
        for param in TCX_POLL_PARAMS:
            bike.set_value(_wire_id(param, rev), bytes([5]))
        transport = _transport(client)
        snapshot = TelemetrySnapshot()

        soc_wire = _wire_id(BikeParameter.BATTERY1_STATE_OF_CHARGE, rev)
        real_parse = ch.parse_tcx_wire_payload

        def flaky_parse(payload: bytes, revision: ProtocolRevision):
            if int.from_bytes(payload[:2], "big") == soc_wire:
                raise ValueError("Payload too short (1 bytes), need at least 2")
            return real_parse(payload, revision)

        monkeypatch.setattr(ch, "parse_tcx_wire_payload", flaky_parse)

        updated = await ch.poll_tcx(transport, snapshot, rev)

        assert updated is True
        assert snapshot.battery.charge_pct is None  # SOC parse failed, skipped
        assert snapshot.motor.motor_power_w == 5  # other params still updated

    async def test_snapshot_update_failure_is_contained_to_current_parameter(
        self,
    ) -> None:
        """update_from_message raising for one message must not abort the rest."""
        client = _FakeClient()
        bike = _FakeBike(client)
        rev = _revision()
        for param in TCX_POLL_PARAMS:
            bike.set_value(_wire_id(param, rev), bytes([5]))
        transport = _transport(client)

        class _FlakySnapshot(TelemetrySnapshot):
            def update_from_message(self, msg: ParsedMessage) -> None:
                if msg.field_name == "battery_charge_percent":
                    raise RuntimeError("boom")
                super().update_from_message(msg)

        snapshot = _FlakySnapshot()

        updated = await poll_tcx(transport, snapshot, rev)

        assert updated is True
        assert snapshot.battery.charge_pct is None
        assert snapshot.motor.motor_power_w == 5

    async def test_disconnect_propagates(self) -> None:
        client = _FakeClient()
        transport = _transport(client)
        snapshot = TelemetrySnapshot()
        transport.mark_disconnected()

        with pytest.raises(TCXTransportDisconnectedError):
            await poll_tcx(transport, snapshot, _revision())


# ---------------------------------------------------------------------------
# poll_tcu1 (requirement: TCU1 unchanged)
# ---------------------------------------------------------------------------


class _FakeTcu1Client:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.responses: dict[bytes, bytes] = {}

    async def write_gatt_char(self, _characteristic: str, data: bytes) -> None:
        self.writes.append(bytes(data))

    async def read_gatt_char(self, _characteristic: str) -> bytes:
        return self.responses[self.writes[-1]]


class TestPollTcu1:
    async def test_polls_sender_channel_pairs_unchanged(self) -> None:
        client = _FakeTcu1Client()
        request = build_request(Sender.BATTERY, BatteryChannel.CHARGE_PERCENT)
        client.responses[request] = bytes(
            [Sender.BATTERY, BatteryChannel.CHARGE_PERCENT, 42]
        )
        snapshot = TelemetrySnapshot()

        updated = await poll_tcu1(
            cast(BleakClient, client), "write-char", "read-char", snapshot
        )

        assert updated is True
        assert snapshot.battery.charge_pct == 42


# ---------------------------------------------------------------------------
# identify_tcx legacy shim (requirement 6: no more false key derivation)
# ---------------------------------------------------------------------------


class _IdentClient:
    def __init__(self) -> None:
        self.callbacks: dict[str, NotificationCallback] = {}
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
        if self.on_write is not None:
            self.on_write(characteristic, packet)

    def notify(self, service_id: BLEServiceID, data: bytes) -> None:
        uuid = get_service_characteristics(BLEProfile.TCX, service_id).notify
        callback = self.callbacks[uuid]
        characteristic = cast(BleakGATTCharacteristic, _FakeCharacteristic(uuid))
        callback(characteristic, bytearray(data))


class TestIdentifyTcxLegacyShim:
    async def test_always_returns_unencrypted_session_even_with_long_firmware_body(
        self,
    ) -> None:
        """Even a >=20 byte BATTERY1_FIRMWARE response is never treated as a key."""
        client = _IdentClient()
        session = TCXSession()

        def respond(_characteristic: str, packet: bytes) -> None:
            wire_id = int.from_bytes(packet[:2], "big")
            if wire_id == int(BikeParameter.BATTERY1_FIRMWARE):
                # Looks superficially "key-like" (>=20 bytes after the
                # 2-byte header) but must never be used as key material.
                body = b"A" * 32
            else:
                body = bytes([1, 2, 3])
            frame = session.pack(encode_parameter_id(wire_id) + body)
            client.notify(BLEServiceID.REQUEST, frame)

        client.on_write = respond
        transport = TCXNotificationTransport(
            cast(BleakClient, client), request_timeout=1.0
        )

        result = await identify_tcx(transport)

        assert isinstance(result, TCXSession)
        assert result.encrypted is False

    async def test_naks_are_logged_but_do_not_abort_the_sequence(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = _IdentClient()
        session = TCXSession()

        def respond(_characteristic: str, packet: bytes) -> None:
            wire_id = int.from_bytes(packet[:2], "big")
            if wire_id == int(BikeParameter.SYSTEM_STATE):
                frame = session.pack(
                    b"\xf8\xff" + encode_parameter_id(wire_id) + bytes([0x02])
                )
            else:
                frame = session.pack(encode_parameter_id(wire_id) + bytes([1]))
            client.notify(BLEServiceID.REQUEST, frame)

        client.on_write = respond
        transport = TCXNotificationTransport(
            cast(BleakClient, client), request_timeout=1.0
        )

        with caplog.at_level("WARNING"):
            result = await identify_tcx(transport)

        assert result.encrypted is False
        assert any("rejected by bike" in r.message for r in caplog.records)

    async def test_disconnect_propagates(self) -> None:
        client = _IdentClient()
        transport = TCXNotificationTransport(
            cast(BleakClient, client), request_timeout=60
        )
        task = asyncio.create_task(identify_tcx(transport))
        await asyncio.sleep(0)

        transport.mark_disconnected()

        with pytest.raises(TCXTransportDisconnectedError):
            await task


def test_poll_params_cover_home_assistant_entities() -> None:
    """Poll values that are not present in the bike's real-time stream."""
    assert {
        BikeParameter.BATTERY1_CURRENT_LEVEL,
        BikeParameter.BATTERY1_HEALTH,
        BikeParameter.BATTERY1_REMAINING_CAPACITY,
        BikeParameter.BATTERY1_TEMPERATURE,
        BikeParameter.BATTERY1_TOTAL_CHARGE_CYCLES,
        BikeParameter.BATTERY1_VOLTAGE_LEVEL,
        BikeParameter.MOTOR_ACTIVE_TRAVEL_MODE,
        BikeParameter.MOTOR_ODOMETER,
        BikeParameter.SYSTEM_KCAL,
    } <= set(TCX_POLL_PARAMS)
