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

import base64
import logging
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import specialized_turbo.connection as connection_module
from specialized_turbo.bike_info import BikeInfo, parse_bike_info
from specialized_turbo.connection import (
    SpecializedConnection,
    UnsupportedTCXOperationError,
)
from specialized_turbo.encryption import PRODUCTION_WRAPPING_KEY
from specialized_turbo.framing import is_nak_packet
from specialized_turbo.identification import (
    IncompleteBikeInfoError,
    UnsupportedGenerationError,
)
from specialized_turbo.key_provider import EncryptionKeyRequiredError
from specialized_turbo.keystore.models import BikeEncryptionKey
from specialized_turbo.parameters import BikeParameter, encode_parameter_id
from specialized_turbo.protocol import (
    NORDIC_COMPANY_ID,
    BikeAdvertisement,
    BLEProfile,
    BLEServiceID,
    ProtocolEncryptionMethod,
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
        encryption_method=ProtocolEncryptionMethod.AES_CTR,
    )


def _wrapped_key(raw_key: bytes = KEY_RAW) -> str:
    iv = bytes(range(16))
    cipher = Cipher(algorithms.AES(PRODUCTION_WRAPPING_KEY), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(raw_key.hex().encode("ascii")) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode("ascii")


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
        "AA:BB:CC:DD:EE:FF",
        bike_info=BikeInfo(name="", bike_name="", is_bike=False, complete=False),
        key=BikeEncryptionKey(raw=KEY_RAW),
    )

    with pytest.raises(IncompleteBikeInfoError):
        await connection.connect()

    assert not connection.is_connected
    assert connection.protocol_revision is None

    # Retryable: connecting again fails the same clean way, with no leftover
    # state or AttributeError.
    with pytest.raises(IncompleteBikeInfoError):
        await connection.connect()
    assert not connection.is_connected


async def test_encrypted_bike_info_requires_key_provider() -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        bike_info=_complete_bike_info(),
    )

    with pytest.raises(EncryptionKeyRequiredError):
        await connection._prepare_tcx_context()


async def test_manual_wrapped_key_is_resolved_before_connection() -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        bike_info=_complete_bike_info(),
        wrapped_key=_wrapped_key(),
    )

    await connection._prepare_tcx_context()

    assert connection._key == BikeEncryptionKey(raw=KEY_RAW)


async def test_decoded_advertisement_builds_bike_info_without_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = AsyncMock()
    monkeypatch.setattr(
        connection_module,
        "find_advertisement_by_address",
        scan,
    )
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        advertisement=BikeAdvertisement(
            generation=BLEProfile.TCX,
            encryption=ProtocolEncryptionMethod.AES_CTR,
            hmi_serial="80005338",
            hmi_hardware="B.3.3",
            reserved=0x33,
            bike_type=6,
            system_state=1,
        ),
        wrapped_key=_wrapped_key(),
    )

    await connection._prepare_tcx_context()

    scan.assert_not_awaited()
    assert connection._bike_info is not None
    assert connection._bike_info.tcx_generation is TCXGeneration.TCX2
    assert connection._key == BikeEncryptionKey(raw=KEY_RAW)


async def test_scan_builds_bike_info_for_key_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = bytes.fromhex("dac8c404423333330601")
    info = parse_bike_info("WSBC001057439S", {NORDIC_COMPANY_ID: payload})
    assert info.tcx_generation is TCXGeneration.TCX2

    device = cast(
        BLEDevice,
        SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name="WSBC001057439S"),
    )
    advertisement = AdvertisementData(
        local_name="WSBC001057439S",
        manufacturer_data={NORDIC_COMPANY_ID: payload},
        service_data={},
        service_uuids=[],
        tx_power=None,
        rssi=-50,
        platform_data=(),
    )

    async def discover(
        _address: str,
        timeout: float = 10.0,
    ) -> tuple[BLEDevice, AdvertisementData]:
        del timeout
        return device, advertisement

    monkeypatch.setattr(
        connection_module,
        "find_advertisement_by_address",
        discover,
    )

    connection = SpecializedConnection(
        device.address,
        wrapped_key=_wrapped_key(),
    )
    await connection._prepare_tcx_context()

    assert connection._bike_info == info
    assert connection._key == BikeEncryptionKey(raw=KEY_RAW)


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

    with pytest.raises(EncryptionKeyRequiredError):
        await connection.connect()
    assert not connection.is_connected

    # Retry with a valid key on the *same* connection object succeeds.
    connection._key = BikeEncryptionKey(raw=KEY_RAW)
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


@pytest.mark.asyncio
async def test_tcu1_convenience_writes_unchanged(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    """TCU1 convenience writers keep the bare sender/channel/value format."""
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        generation=BLEProfile.TCU1,
    )
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None

    await connection.set_assist_level(2)
    assert client.writes[-1][1] == bytes([0x01, 0x05, 0x02])

    await connection.set_assist_percentage(1, 60)  # TRAIL -> channel 0x04
    assert client.writes[-1][1] == bytes([0x02, 0x04, 60])

    await connection.set_shuttle(50)  # TCU1 supports shuttle
    assert client.writes[-1][1] == bytes([0x01, 0x15, 50])

    await connection.disconnect()


# ---------------------------------------------------------------------------
# TelemetryMonitor primes profile-aware (no GATT reads); the connection's
# active_revision drives both priming and live notification decoding.
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


@pytest.mark.asyncio
async def test_active_revision_aliases_protocol_revision(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()

    expected = ProtocolRevision(GENERATION, REVISION)
    assert connection.active_revision == expected
    # protocol_revision is retained as an alias of the canonical accessor.
    assert connection.protocol_revision == connection.active_revision

    await connection.disconnect()


@pytest.mark.asyncio
async def test_telemetry_primes_and_decodes_soc_profile_aware(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    """AES connect -> active revision -> mapped priming + notification (SOC 0x0500)."""
    connection = _connection()
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None
    monitor = TelemetryMonitor(connection)

    # The monitor reads the connection's negotiated revision structurally.
    assert monitor._active_revision() == ProtocolRevision(GENERATION, REVISION)

    await monitor.start()

    # Priming addressed SOC by its real wire id 0x0500 -- never the raw enum
    # id (26), which is not a valid TCX2 wire id.
    assert 0x0500 in client.bike.requests
    assert int(BikeParameter.BATTERY1_STATE_OF_CHARGE) not in client.bike.requests
    # The healthy bike's primed SOC body is 49.
    assert monitor.snapshot.battery.charge_pct == 49

    # A live SOC notification (wire 0x0500 = 61) decodes profile-aware.
    packet = connection.session.pack(encode_parameter_id(0x0500) + bytes([61]))
    client.notify(BLEServiceID.DATA, packet)
    assert monitor.snapshot.battery.charge_pct == 61
    assert client.reads == []

    await monitor.stop()
    await connection.disconnect()


@pytest.mark.asyncio
async def test_no_deprecated_raw_calls_during_connect_and_telemetry(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    """Connect + prime + decode must not touch the deprecated raw enum-id path."""
    connection = _connection()
    monitor = TelemetryMonitor(connection)

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        await connection.connect()
        await monitor.start()
        client = fake_bleak.instance
        assert client is not None
        packet = connection.session.pack(encode_parameter_id(0x0500) + bytes([61]))
        client.notify(BLEServiceID.DATA, packet)
        await monitor.stop()

    assert monitor.snapshot.battery.charge_pct == 61
    await connection.disconnect()


# ---------------------------------------------------------------------------
# TCX convenience writers map through the correct BikeParameter wire ids.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcx_convenience_writes_map_to_wire_ids(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None
    data_service = get_service_characteristics(BLEProfile.TCX, BLEServiceID.DATA)

    def last_data_write() -> bytes:
        characteristic, packet, response = client.writes[-1]
        assert characteristic == data_service.write
        assert response is False
        return connection.session.unpack(packet)

    # assist level -> MOTOR_ACTIVE_TRAVEL_MODE (0x07fa)
    await connection.set_assist_level(2)
    assert last_data_write()[:3] == bytes([0x07, 0xFA, 0x02])

    # profile scaling ECO/TRAIL/TURBO -> 0x07f2 / 0x07f1 / 0x07f0
    await connection.set_assist_percentage(0, 55)
    assert last_data_write()[:3] == bytes([0x07, 0xF2, 55])
    await connection.set_assist_percentage(1, 60)
    assert last_data_write()[:3] == bytes([0x07, 0xF1, 60])
    await connection.set_assist_percentage(2, 70)
    assert last_data_write()[:3] == bytes([0x07, 0xF0, 70])

    # acceleration -> MOTOR_ACCELERATION_RESPONSE (0x0711); 50% -> 6000 LE
    await connection.set_acceleration(50)
    unpacked = last_data_write()
    assert unpacked[:2] == bytes([0x07, 0x11])
    assert unpacked[2:4] == (6000).to_bytes(2, "little")

    await connection.disconnect()


@pytest.mark.asyncio
async def test_tcx_set_shuttle_raises_unsupported(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None
    writes_before = len(client.writes)

    with pytest.raises(UnsupportedTCXOperationError, match="shuttle"):
        await connection.set_shuttle(50)

    # No wire write was emitted for the unsupported operation.
    assert len(client.writes) == writes_before

    await connection.disconnect()


@pytest.mark.asyncio
async def test_tcx_set_assist_percentage_rejects_bad_level_index(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = _connection()
    await connection.connect()

    with pytest.raises(ValueError, match="level_index"):
        await connection.set_assist_percentage(3, 50)

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
