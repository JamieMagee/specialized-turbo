"""Tests for TCX write/notification transactions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import pytest
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from specialized_turbo.coordinator_helpers import identify_tcx
from specialized_turbo.framing import pack_tcx, unpack_tcx
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
    TCXRequestTimeoutError,
    TraceCallback,
)


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
    frame = TCXSession().pack(build_tcx_request(301))
    assert frame.hex() == "012d00000000000000000000000000000000e25d"


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
async def test_identification_installs_iv_before_encrypted_steps() -> None:
    client = _FakeClient()
    transport = _transport(client)
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    encrypted_session = TCXSession(key=key, iv=iv)
    seen_params: list[int] = []

    def respond(_characteristic: str, packet: bytes) -> None:
        if not seen_params:
            payload = TCXSession().unpack(packet)
            param_id = int.from_bytes(payload[:2], "big")
            assert param_id == 301
            response = TCXSession().pack(payload[:2] + iv)
        else:
            payload = encrypted_session.unpack(packet)
            param_id = int.from_bytes(payload[:2], "big")
            response = encrypted_session.pack(payload[:2] + b"\x01")
        seen_params.append(param_id)
        client.notify(BLEServiceID.REQUEST, response)

    client.on_write = respond

    session = await identify_tcx(
        transport,
        bike_key=key,
        encryption_required=True,
    )

    assert session.encrypted
    assert seen_params == [301, 311, 364, 14, 309, 330, 291]


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
async def test_realtime_enable_uses_service_three_write() -> None:
    client = _FakeClient()
    transport = _transport(client)

    await transport.set_realtime_enabled(True)

    service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.DATA)
    characteristic, packet, response = client.writes[-1]
    assert characteristic == service.write
    assert unpack_tcx(packet)[:3] == bytes.fromhex("015b01")
    assert response is False


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
async def test_unsubscribe_stops_all_owned_notifications() -> None:
    client = _FakeClient()
    transport = _transport(client)
    await transport.subscribe_for_identification()
    await transport.subscribe_for_realtime()

    await transport.unsubscribe_all()

    assert set(client.unsubscriptions) == set(client.subscriptions)
