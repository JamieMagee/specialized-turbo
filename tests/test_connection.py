"""Connection-level tests for TCX identification/session/key integration.

The fake BLE client below plays the role of a real, AES-encrypted TCX2 bike:
it answers the seven-step identification handshake exactly like the fake
bike in ``test_identification.py`` (clear ``GET_NEW_VI``/
``HMI_PROTOCOL_VERSION`` control frames, then AES-CTR encrypted reads for
every other step), then continues encrypting/decrypting every subsequent
request through the same negotiated session -- so post-identification reads
(SOC, real-time enable, ...) exercise the exact crypto path a real bike
would.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

import pytest
from bleak.backends.characteristic import BleakGATTCharacteristic

import specialized_turbo.connection as connection_module
from specialized_turbo.bike_info import BikeInfo
from specialized_turbo.connection import SpecializedConnection
from specialized_turbo.framing import is_nak_packet
from specialized_turbo.identification import (
    IncompleteBikeInfoError,
    MissingEncryptionKeyError,
    UnsupportedGenerationError,
)
from specialized_turbo.keystore.models import BikeEncryptionKey
from specialized_turbo.parameters import BikeParameter, encode_parameter_id
from specialized_turbo.protocol import (
    BLEProfile,
    BLEServiceID,
    get_service_characteristics,
)
from specialized_turbo.session import TCU1Session, TCXSession
from specialized_turbo.telemetry import TelemetryMonitor
from specialized_turbo.transport import (
    NotificationCallback,
    TCXTransportDisconnectedError,
)
from specialized_turbo.wire_profiles import ProtocolRevision, TCXGeneration, wire_id_for

# Deterministic synthetic key + IV -- never real key material.
KEY_RAW = b"\x33" * 16
WRONG_KEY_RAW = b"\x99" * 16
IV = b"\x44" * 16

GENERATION = TCXGeneration.TCX2
REVISION = 0x12
USB_REVISION = 0x03

WIRE_GET_NEW_VI = 0x0A00
WIRE_PROTOCOL_VERSION = 0x0A01


def _wire(param: BikeParameter, revision: int | None = REVISION) -> int:
    return wire_id_for(param, GENERATION, revision)


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


@dataclass
class _FakeCharacteristic:
    uuid: str


@dataclass
class _FakeBike:
    """Answers wire requests like a real AES-CTR encrypted TCX2 bike.

    Every identification step is pre-programmed via ``_healthy_bike()``.
    Any *other* wire id gets a generic ``[wire_id_be, 0x01]`` reply (still
    encrypted through the same session) -- enough for legacy raw-wire-id
    callers (``request_tcx_value``/``TelemetryMonitor``) without needing to
    special-case every parameter.
    """

    key: bytes = KEY_RAW
    iv: bytes = IV
    _session: TCXSession = field(init=False)
    _bodies: dict[int, bytes] = field(default_factory=dict, init=False)
    _naks: dict[int, int] = field(default_factory=dict, init=False)
    requests: list[int] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self._session = TCXSession(key=self.key, iv=self.iv)

    def set_body(self, wire_id: int, body: bytes) -> None:
        self._bodies[wire_id] = encode_parameter_id(wire_id) + bytes(body)

    def set_nak(self, wire_id: int, reason: int) -> None:
        self._naks[wire_id] = reason

    def reply_for(self, wire_id: int) -> bytes:
        self.requests.append(wire_id)
        if wire_id in self._naks:
            nak = (
                b"\xf8\xff"
                + encode_parameter_id(wire_id)
                + bytes([self._naks[wire_id]])
            )
            return self._session.pack(nak)
        body = self._bodies.get(wire_id, encode_parameter_id(wire_id) + b"\x01")
        return self._session.pack(body)


def _healthy_bike() -> _FakeBike:
    bike = _FakeBike()
    bike.set_body(WIRE_GET_NEW_VI, IV)
    bike.set_body(WIRE_PROTOCOL_VERSION, bytes([REVISION, USB_REVISION]))
    bike.set_body(_wire(BikeParameter.SYSTEM_STATE), bytes([4]))
    bike.set_body(_wire(BikeParameter.BATTERY1_FIRMWARE), bytes([1, 2, 3]))
    bike.set_body(_wire(BikeParameter.SYSTEM_HMI_HW_VERSION), b"B.3.3")
    bike.set_body(_wire(BikeParameter.SYSTEM_MOTOR_TYPE), bytes([7]))
    bike.set_body(_wire(BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER), b"SN12345")
    bike.set_body(_wire(BikeParameter.BATTERY1_STATE_OF_CHARGE), bytes([49]))
    return bike


class _FakeBleakClient:
    """A fake ``BleakClient`` fronting a :class:`_FakeBike`."""

    instance: _FakeBleakClient | None = None

    def __init__(
        self,
        _address: object,
        *,
        disconnected_callback: Callable[[Any], None] | None = None,
    ) -> None:
        type(self).instance = self
        self.disconnected_callback = disconnected_callback
        self.is_connected = False
        self.callbacks: dict[str, NotificationCallback] = {}
        self.subscriptions: list[str] = []
        self.writes: list[tuple[str, bytes, bool | None]] = []
        self.reads: list[str] = []
        self.bike = _healthy_bike()
        # If set, disconnect (and stop answering) as soon as this wire id
        # is written -- simulates a mid-handshake link drop.
        self.disconnect_on_wire: int | None = None
        # Characteristic UUIDs for which start_notify() should raise --
        # simulates a post-identification subscribe_for_realtime() failure.
        self.fail_start_notify_for: set[str] = set()

    async def connect(self) -> None:
        self.is_connected = True

    async def disconnect(self) -> None:
        self.is_connected = False

    async def pair(self, *, protection_level: int) -> None:
        assert protection_level == 2

    async def start_notify(
        self,
        characteristic: str,
        callback: NotificationCallback,
    ) -> None:
        if characteristic in self.fail_start_notify_for:
            raise RuntimeError(f"start_notify failed for {characteristic}")
        self.callbacks[characteristic] = callback
        self.subscriptions.append(characteristic)

    async def stop_notify(self, characteristic: str) -> None:
        self.callbacks.pop(characteristic, None)

    async def read_gatt_char(self, characteristic: str) -> bytes:
        self.reads.append(characteristic)
        return b"\x00\x0c\x31"

    async def write_gatt_char(
        self,
        characteristic: str,
        data: bytes,
        response: bool | None = None,
    ) -> None:
        packet = bytes(data)
        self.writes.append((characteristic, packet, response))

        if len(packet) != 20:
            return
        wire_id = int.from_bytes(packet[:2], "big")

        if wire_id == self.disconnect_on_wire:
            self.is_connected = False
            if self.disconnected_callback is not None:
                self.disconnected_callback(self)
            return

        request_service = get_service_characteristics(
            BLEProfile.TCX, BLEServiceID.REQUEST
        )
        if characteristic != request_service.write:
            return

        reply = self.bike.reply_for(wire_id)
        self.notify(BLEServiceID.REQUEST, reply)

    def notify(self, service_id: BLEServiceID, data: bytes) -> None:
        uuid = get_service_characteristics(BLEProfile.TCX, service_id).notify
        callback = self.callbacks[uuid]
        characteristic = cast(BleakGATTCharacteristic, _FakeCharacteristic(uuid))
        callback(characteristic, bytearray(data))


@pytest.fixture
def fake_bleak(monkeypatch: pytest.MonkeyPatch) -> type[_FakeBleakClient]:
    monkeypatch.setattr(connection_module, "BleakClient", _FakeBleakClient)
    return _FakeBleakClient


def _connection(**kwargs: Any) -> SpecializedConnection:
    return SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        bike_info=_complete_bike_info(),
        key=BikeEncryptionKey(raw=KEY_RAW),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Successful AES connect: identification, session/revision installed,
# S2/S3 subscribed only after success, zero GATT reads.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcx_connect_identifies_without_gatt_reads(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()

    await connection.connect()

    client = fake_bleak.instance
    assert client is not None
    assert client.reads == []

    expected_subscriptions = [
        get_service_characteristics(BLEProfile.TCX, service_id).notify
        for service_id in (
            BLEServiceID.REQUEST,
            BLEServiceID.DATA,
            BLEServiceID.COMMAND,
        )
    ]
    assert client.subscriptions == expected_subscriptions

    identification_wire_ids = [
        int.from_bytes(packet[:2], "big") for _, packet, _ in client.writes[:7]
    ]
    assert identification_wire_ids == [
        WIRE_GET_NEW_VI,
        WIRE_PROTOCOL_VERSION,
        _wire(BikeParameter.SYSTEM_STATE),
        _wire(BikeParameter.BATTERY1_FIRMWARE),
        _wire(BikeParameter.SYSTEM_HMI_HW_VERSION),
        _wire(BikeParameter.SYSTEM_MOTOR_TYPE),
        _wire(BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER),
    ]
    assert all(response is False for _, _, response in client.writes[:7])
    assert all(not is_nak_packet(packet) for _, packet, _ in client.writes[:7])

    await connection.disconnect()


@pytest.mark.asyncio
async def test_successful_identification_installs_session_and_revision(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()

    await connection.connect()

    assert isinstance(connection.session, TCXSession)
    assert connection.session.encrypted
    assert connection.protocol_revision == ProtocolRevision(GENERATION, REVISION)
    assert connection.identification_result is not None
    assert (
        connection.identification_result.protocol_revision
        == connection.protocol_revision
    )

    await connection.disconnect()


@pytest.mark.asyncio
async def test_soc_reads_wire_0500_through_negotiated_revision(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None

    msg = await connection.request_tcx_parameter(BikeParameter.BATTERY1_STATE_OF_CHARGE)

    assert msg.wire_id == 0x0500
    assert msg.value == 49
    assert client.bike.requests[-1] == 0x0500
    assert client.reads == []

    await connection.disconnect()


@pytest.mark.asyncio
async def test_realtime_enable_uses_wire_080f(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None

    received: list[bytes] = []

    def notification(
        _sender: BleakGATTCharacteristic,
        data: bytearray,
    ) -> None:
        received.append(bytes(data))

    await connection.subscribe_notifications(notification)

    data_service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.DATA)
    enable_characteristic, enable_packet, enable_response = client.writes[-1]
    assert enable_characteristic == data_service.write
    assert connection.session.unpack(enable_packet)[:3] == bytes.fromhex("080f01")
    assert enable_response is False

    await connection.unsubscribe_notifications()
    disable_characteristic, disable_packet, disable_response = client.writes[-1]
    assert disable_characteristic == data_service.write
    assert connection.session.unpack(disable_packet)[:3] == bytes.fromhex("080f00")
    assert disable_response is False

    await connection.disconnect()


# ---------------------------------------------------------------------------
# Missing / incomplete bike info and key -- clean, typed errors.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_bike_info_raises_cleanly(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF", key=BikeEncryptionKey(raw=KEY_RAW)
    )

    with pytest.raises(IncompleteBikeInfoError):
        await connection.connect()

    assert not connection.is_connected
    assert connection.protocol_revision is None

    # Retryable: connecting again (still without bike_info) fails the same
    # clean way, with no leftover state or AttributeError.
    with pytest.raises(IncompleteBikeInfoError):
        await connection.connect()
    assert not connection.is_connected


@pytest.mark.asyncio
async def test_incomplete_bike_info_raises_cleanly(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        bike_info=_complete_bike_info(complete=False),
        key=BikeEncryptionKey(raw=KEY_RAW),
    )

    with pytest.raises(IncompleteBikeInfoError):
        await connection.connect()

    assert not connection.is_connected


@pytest.mark.asyncio
async def test_missing_generation_raises_cleanly(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        bike_info=_complete_bike_info(generation=None),
        key=BikeEncryptionKey(raw=KEY_RAW),
    )

    with pytest.raises(UnsupportedGenerationError):
        await connection.connect()

    assert not connection.is_connected


@pytest.mark.asyncio
async def test_missing_key_raises_cleanly_and_is_retryable(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF", bike_info=_complete_bike_info()
    )

    with pytest.raises(MissingEncryptionKeyError):
        await connection.connect()
    assert not connection.is_connected

    # Retry with a valid key on the *same* connection object succeeds.
    connection._key = BikeEncryptionKey(raw=KEY_RAW)  # noqa: SLF001
    await connection.connect()
    assert connection.is_connected
    assert connection.protocol_revision == ProtocolRevision(GENERATION, REVISION)

    await connection.disconnect()


# ---------------------------------------------------------------------------
# NAK during identification.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nak_during_identification_fails_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _connection()

    class _NakkingClient(_FakeBleakClient):
        def __init__(
            self,
            address: object,
            *,
            disconnected_callback: Callable[[Any], None] | None = None,
        ) -> None:
            super().__init__(address, disconnected_callback=disconnected_callback)
            self.bike = _healthy_bike()
            self.bike.set_nak(_wire(BikeParameter.SYSTEM_STATE), 0x05)

    monkeypatch.setattr(connection_module, "BleakClient", _NakkingClient)

    with pytest.raises(Exception, match="0x05|reason"):
        await connection.connect()

    assert not connection.is_connected
    assert connection.protocol_revision is None


# ---------------------------------------------------------------------------
# Disconnect mid-identification: clean failure, retryable.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disconnect_during_identification_fails_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _connection()

    # Configure the disconnect trigger *before* connect() creates the client
    # by patching the constructor via a thin subclass.
    class _DisconnectingClient(_FakeBleakClient):
        def __init__(
            self,
            address: object,
            *,
            disconnected_callback: Callable[[Any], None] | None = None,
        ) -> None:
            super().__init__(address, disconnected_callback=disconnected_callback)
            self.disconnect_on_wire = WIRE_GET_NEW_VI

    monkeypatch.setattr(connection_module, "BleakClient", _DisconnectingClient)

    with pytest.raises(TCXTransportDisconnectedError, match="disconnected"):
        await connection.connect()

    assert not connection.is_connected
    assert connection.protocol_revision is None


@pytest.mark.asyncio
async def test_disconnect_during_identification_allows_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _connection()

    class _DisconnectingClient(_FakeBleakClient):
        def __init__(
            self,
            address: object,
            *,
            disconnected_callback: Callable[[Any], None] | None = None,
        ) -> None:
            super().__init__(address, disconnected_callback=disconnected_callback)
            self.disconnect_on_wire = WIRE_GET_NEW_VI

    monkeypatch.setattr(connection_module, "BleakClient", _DisconnectingClient)
    with pytest.raises(TCXTransportDisconnectedError):
        await connection.connect()
    assert not connection.is_connected

    # A healthy client this time -- retry succeeds cleanly.
    monkeypatch.setattr(connection_module, "BleakClient", _FakeBleakClient)
    await connection.connect()
    assert connection.is_connected
    assert connection.protocol_revision == ProtocolRevision(GENERATION, REVISION)

    await connection.disconnect()


@pytest.mark.asyncio
async def test_realtime_subscribe_failure_after_identification_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-identification failure (S3/S2 subscribe) must not leak state.

    Identification itself succeeds (all seven steps complete), but
    ``subscribe_for_realtime()`` -- the DATA/COMMAND ``start_notify()`` calls
    made only *after* a successful handshake -- then fails. ``connect()``
    must run the same cleanup as an identification failure: disconnect and
    drop the old client/transport, clear session/revision/result, and leave
    ``is_connected`` false so a subsequent connect() can retry cleanly.
    """
    connection = _connection()
    data_service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.DATA)
    request_service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.REQUEST)

    class _RealtimeSubscribeFailingClient(_FakeBleakClient):
        def __init__(
            self,
            address: object,
            *,
            disconnected_callback: Callable[[Any], None] | None = None,
        ) -> None:
            super().__init__(address, disconnected_callback=disconnected_callback)
            self.fail_start_notify_for = {data_service.notify}

    monkeypatch.setattr(
        connection_module, "BleakClient", _RealtimeSubscribeFailingClient
    )

    with pytest.raises(RuntimeError, match="start_notify failed"):
        await connection.connect()

    failed_client = _RealtimeSubscribeFailingClient.instance
    assert failed_client is not None
    # Identification (all 7 steps) completed before the DATA subscribe blew
    # up -- no extra/leaked writes, and only the identification-phase
    # (REQUEST) notification stayed subscribed on the old, now-abandoned
    # client.
    assert len(failed_client.writes) == 7
    assert failed_client.subscriptions == [request_service.notify]

    # No leaked old client/transport/profile: is_connected is false and the
    # negotiated state is fully cleared, not half-installed.
    assert not connection.is_connected
    assert connection.protocol_revision is None
    assert connection.identification_result is None
    assert isinstance(connection.session, TCU1Session)

    # A healthy retry (fresh client) succeeds cleanly and doesn't reuse
    # anything from the failed attempt.
    monkeypatch.setattr(connection_module, "BleakClient", _FakeBleakClient)
    await connection.connect()
    healthy_client = _FakeBleakClient.instance
    assert healthy_client is not None
    assert healthy_client is not failed_client
    assert connection.is_connected
    assert connection.protocol_revision == ProtocolRevision(GENERATION, REVISION)
    assert connection.identification_result is not None

    await connection.disconnect()


@pytest.mark.asyncio
async def test_disconnect_during_unsubscribe_does_not_race_transport_cleanup(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None

    def notification(
        _sender: BleakGATTCharacteristic,
        _data: bytearray,
    ) -> None:
        pass

    await connection.subscribe_notifications(notification)
    client.disconnect_on_wire = 0x080F  # real-time disable write

    await connection.unsubscribe_notifications()

    assert not connection.is_connected


# ---------------------------------------------------------------------------
# TCU1 unchanged.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcu1_request_read_is_unchanged(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        generation=BLEProfile.TCU1,
    )
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None

    message = await connection.request_value(0, 12)

    assert message.converted_value == 49
    assert len(client.reads) == 1
    assert client.writes[-1][1] == bytes.fromhex("000c")

    await connection.disconnect()


# ---------------------------------------------------------------------------
# TelemetryMonitor still primes without GATT reads (legacy raw-wire path).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_telemetry_monitor_primes_tcx_snapshot_without_reads(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None
    monitor = TelemetryMonitor(connection)

    await monitor.start()

    assert monitor.snapshot.message_count > 0
    assert client.reads == []

    await monitor.stop()
    await connection.disconnect()


# ---------------------------------------------------------------------------
# No secret material in logs/errors.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_secret_key_material_in_logs_or_errors(
    fake_bleak: type[_FakeBleakClient],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    connection = _connection()

    await connection.connect()
    await connection.request_tcx_parameter(BikeParameter.BATTERY1_STATE_OF_CHARGE)
    await connection.disconnect()

    key_hex = KEY_RAW.hex()
    for record in caplog.records:
        message = record.getMessage()
        assert key_hex not in message
        # BikeEncryptionKey's own __repr__/__str__ redact the key; if it is
        # ever interpolated into a log message it must stay redacted.
        if "BikeEncryptionKey" in message:
            assert "<redacted>" in message

    # Wrong-key failures must not leak either key's bytes in the exception.
    bad_connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        bike_info=_complete_bike_info(),
        key=BikeEncryptionKey(raw=WRONG_KEY_RAW),
    )
    with pytest.raises(Exception) as excinfo:
        await bad_connection.connect()
    assert KEY_RAW.hex() not in str(excinfo.value)
    assert WRONG_KEY_RAW.hex() not in str(excinfo.value)
