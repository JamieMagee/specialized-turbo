"""Tests for TCX write/notification transactions."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import pytest
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from specialized_turbo.framing import pack_tcx, unpack_tcx
from specialized_turbo.parameters import BikeParameter
from specialized_turbo.protocol import (
    BLEProfile,
    BLEServiceID,
    build_tcx_request,
    get_service_characteristics,
    parse_tcx_message,
)
from specialized_turbo.session import TCXSession
from specialized_turbo.transport import (
    BLETraceEvent,
    NotificationCallback,
    TCXNotificationTransport,
    TCXProtocolNotNegotiatedError,
    TCXRequestTimeoutError,
    TCXTransportDisconnectedError,
    TraceCallback,
)
from specialized_turbo.wire_profiles import ProtocolRevision, TCXGeneration


@dataclass
class _FakeCharacteristic:
    uuid: str


class _FakeClient:
    def __init__(self) -> None:
        self.callbacks: dict[str, NotificationCallback] = {}
        self.subscriptions: list[str] = []
        self.unsubscriptions: list[str] = []
        self.writes: list[tuple[str, bytes, bool | None]] = []
        self.on_write: Callable[[str, bytes], None] | None = None

    async def start_notify(
        self,
        characteristic: str,
        callback: NotificationCallback,
    ) -> None:
        self.callbacks[characteristic] = callback
        self.subscriptions.append(characteristic)

    async def stop_notify(self, characteristic: str) -> None:
        self.callbacks.pop(characteristic)
        self.unsubscriptions.append(characteristic)

    async def write_gatt_char(
        self,
        characteristic: str,
        data: bytes,
        response: bool | None = None,
    ) -> None:
        packet = bytes(data)
        self.writes.append((characteristic, packet, response))
        if self.on_write is not None:
            self.on_write(characteristic, packet)

    def notify(self, service_id: BLEServiceID, data: bytes) -> None:
        uuid = get_service_characteristics(BLEProfile.TCX, service_id).notify
        callback = self.callbacks[uuid]
        characteristic = cast(
            BleakGATTCharacteristic,
            _FakeCharacteristic(uuid),
        )
        callback(characteristic, bytearray(data))


def _transport(
    client: _FakeClient,
    *,
    session: TCXSession | None = None,
    request_timeout: float = 7.0,
    trace_callback: TraceCallback | None = None,
) -> TCXNotificationTransport:
    return TCXNotificationTransport(
        cast(BleakClient, client),
        session=session,
        request_timeout=request_timeout,
        trace_callback=trace_callback,
    )


def test_identification_frame_matches_official_app() -> None:
    frame = TCXSession().pack(build_tcx_request(300))
    assert frame.hex() == "012c00000000000000000000000000000000004d"


@pytest.mark.asyncio
async def test_subscription_order_matches_official_app() -> None:
    client = _FakeClient()
    transport = _transport(client)

    await transport.subscribe_for_identification()
    await transport.subscribe_for_realtime()

    expected = [
        get_service_characteristics(BLEProfile.TCX, service_id).notify
        for service_id in (
            BLEServiceID.REQUEST,
            BLEServiceID.DATA,
            BLEServiceID.COMMAND,
        )
    ]
    assert client.subscriptions == expected


@pytest.mark.asyncio
async def test_request_writes_framed_packet_and_awaits_notification() -> None:
    client = _FakeClient()
    transport = _transport(client)

    def respond(characteristic: str, packet: bytes) -> None:
        service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.REQUEST)
        assert characteristic == service.write
        assert unpack_tcx(packet)[:2] == bytes.fromhex("001a")
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("001a31")),
        )

    client.on_write = respond
    response = await transport.request_parameter(26)
    message = parse_tcx_message(response)

    assert message.field_name == "battery_charge_percent"
    assert message.converted_value == 49
    assert client.writes[0][2] is False


@pytest.mark.asyncio
async def test_request_ignores_unrelated_notification() -> None:
    client = _FakeClient()
    transport = _transport(client)

    def respond(_characteristic: str, _packet: bytes) -> None:
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("001131")),
        )
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("001a31")),
        )

    client.on_write = respond

    response = await transport.request_parameter(26)

    assert parse_tcx_message(response).converted_value == 49


@pytest.mark.asyncio
async def test_request_returns_matching_nak() -> None:
    client = _FakeClient()
    transport = _transport(client)

    def respond(_characteristic: str, _packet: bytes) -> None:
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("f8ff001a05")),
        )

    client.on_write = respond

    response = await transport.request_parameter(26)
    message = parse_tcx_message(response)

    assert message.raw_value == 26
    assert message.nak_reason == 0x05


@pytest.mark.asyncio
async def test_request_times_out_and_clears_pending_state() -> None:
    client = _FakeClient()
    transport = _transport(client, request_timeout=0.001)

    with pytest.raises(TCXRequestTimeoutError, match="parameter 26"):
        await transport.request_parameter(26)

    def respond(_characteristic: str, _packet: bytes) -> None:
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("001a31")),
        )

    client.on_write = respond
    response = await transport.request_parameter(26)
    assert parse_tcx_message(response).converted_value == 49


@pytest.mark.asyncio
async def test_disconnect_fails_pending_request_immediately() -> None:
    client = _FakeClient()
    transport = _transport(client, request_timeout=60)
    request = asyncio.create_task(transport.request_parameter(26))
    await asyncio.sleep(0)

    transport.mark_disconnected()

    with pytest.raises(TCXTransportDisconnectedError, match="disconnected"):
        await request
    with pytest.raises(TCXTransportDisconnectedError, match="disconnected"):
        await transport.request_parameter(26)


@pytest.mark.asyncio
async def test_realtime_enable_uses_service_three_write() -> None:
    client = _FakeClient()
    transport = _transport(client)
    transport.protocol_revision = ProtocolRevision(TCXGeneration.TCX2, 0x12)

    await transport.set_realtime_enabled(True)

    service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.DATA)
    characteristic, packet, response = client.writes[-1]
    assert characteristic == service.write
    # SYSTEM_REAL_TIME_DATA_ENB resolves to wire 0x080f, not its raw
    # BikeParameter value (346 / 0x015a) -- see wire_profiles.
    assert unpack_tcx(packet)[:3] == bytes.fromhex("080f01")
    assert response is False


@pytest.mark.asyncio
async def test_realtime_enable_requires_negotiated_revision() -> None:
    client = _FakeClient()
    transport = _transport(client)

    with pytest.raises(
        TCXProtocolNotNegotiatedError, match="SYSTEM_REAL_TIME_DATA_ENB"
    ):
        await transport.set_realtime_enabled(True)


@pytest.mark.asyncio
async def test_trace_records_full_write_and_notification_payloads() -> None:
    client = _FakeClient()
    events: list[BLETraceEvent] = []
    transport = _transport(client, trace_callback=events.append)

    def respond(_characteristic: str, _packet: bytes) -> None:
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("001a31")),
        )

    client.on_write = respond
    await transport.request_parameter(26)

    assert [event.direction for event in events] == ["tx", "rx"]
    assert all(len(event.data) == 20 for event in events)
    assert events[0].service_id == BLEServiceID.REQUEST


@pytest.mark.asyncio
async def test_request_bike_parameter_resolves_soc_wire_0500() -> None:
    client = _FakeClient()
    transport = _transport(client)
    transport.protocol_revision = ProtocolRevision(TCXGeneration.TCX2, 0x12)

    def respond(characteristic: str, packet: bytes) -> None:
        service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.REQUEST)
        assert characteristic == service.write
        assert unpack_tcx(packet)[:2] == bytes.fromhex("0500")
        client.notify(BLEServiceID.REQUEST, pack_tcx(bytes.fromhex("050031")))

    client.on_write = respond
    response = await transport.request_bike_parameter(
        BikeParameter.BATTERY1_STATE_OF_CHARGE
    )

    assert parse_tcx_message(response).converted_value == 49


@pytest.mark.asyncio
async def test_request_bike_parameter_extracts_target_from_group() -> None:
    client = _FakeClient()
    transport = _transport(client)
    transport.protocol_revision = ProtocolRevision(TCXGeneration.TCX2, 0x33)
    seen: list[bytes] = []
    transport.add_listener(lambda _sender, data: seen.append(bytes(data)))

    def respond(characteristic: str, packet: bytes) -> None:
        service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.REQUEST)
        assert characteristic == service.write
        # BATTERY1_CURRENT_LEVEL is byte 5 of packed group 0x0500.
        assert unpack_tcx(packet)[:2] == bytes.fromhex("0500")
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("0500310000000064")),
        )

    client.on_write = respond
    response = await transport.request_bike_parameter(
        BikeParameter.BATTERY1_CURRENT_LEVEL
    )

    assert response == bytes.fromhex("05fc64")
    assert [unpack_tcx(packet)[:2] for packet in seen] == [bytes.fromhex("0500")]


@pytest.mark.asyncio
async def test_group_request_returns_group_nak() -> None:
    client = _FakeClient()
    transport = _transport(client)
    transport.protocol_revision = ProtocolRevision(TCXGeneration.TCX2, 0x33)

    def respond(_characteristic: str, packet: bytes) -> None:
        assert unpack_tcx(packet)[:2] == bytes.fromhex("0500")
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("f8ff050002")),
        )

    client.on_write = respond
    response = await transport.request_bike_parameter(
        BikeParameter.BATTERY1_CURRENT_LEVEL
    )

    message = parse_tcx_message(response)
    assert message.raw_value == 0x0500
    assert message.nak_reason == 0x02


@pytest.mark.asyncio
async def test_wire_group_completes_on_group_response() -> None:
    client = _FakeClient()
    transport = _transport(client)

    def respond(_characteristic: str, packet: bytes) -> None:
        assert unpack_tcx(packet)[:2] == bytes.fromhex("0800")
        client.notify(
            BLEServiceID.REQUEST,
            pack_tcx(bytes.fromhex("080000000000000000006400000000000000")),
        )

    client.on_write = respond
    response = await transport.request_wire_group(
        0x0800,
        (0x08FC, 0x08FD, 0x08FE),
    )

    assert response[:2] == bytes.fromhex("0800")


@pytest.mark.asyncio
async def test_request_bike_parameter_requires_negotiated_revision() -> None:
    client = _FakeClient()
    transport = _transport(client)

    with pytest.raises(TCXProtocolNotNegotiatedError, match="BATTERY1_STATE_OF_CHARGE"):
        await transport.request_bike_parameter(BikeParameter.BATTERY1_STATE_OF_CHARGE)


@pytest.mark.asyncio
async def test_unsubscribe_stops_all_owned_notifications() -> None:
    client = _FakeClient()
    transport = _transport(client)
    await transport.subscribe_for_identification()
    await transport.subscribe_for_realtime()

    await transport.unsubscribe_all()

    assert set(client.unsubscriptions) == set(client.subscriptions)
