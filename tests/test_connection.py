"""Connection-level tests for TCX write/notification transactions."""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import pytest
from bleak.backends.characteristic import BleakGATTCharacteristic
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import specialized_turbo.connection as connection_module
from specialized_turbo.connection import SpecializedConnection
from specialized_turbo.encryption import PRODUCTION_WRAPPING_KEY
from specialized_turbo.framing import is_nak_packet, pack_tcx, unpack_tcx
from specialized_turbo.key_provider import EncryptionKeyRequiredError
from specialized_turbo.protocol import (
    BLEProfile,
    BLEServiceID,
    BikeAdvertisement,
    ProtocolEncryptionMethod,
    get_service_characteristics,
)
from specialized_turbo.telemetry import TelemetryMonitor
from specialized_turbo.transport import NotificationCallback


@dataclass
class _FakeCharacteristic:
    uuid: str


class _FakeBleakClient:
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
        self.read_response = bytes.fromhex("000c31")

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
        self.callbacks[characteristic] = callback
        self.subscriptions.append(characteristic)

    async def stop_notify(self, characteristic: str) -> None:
        self.callbacks.pop(characteristic)

    async def read_gatt_char(self, characteristic: str) -> bytes:
        self.reads.append(characteristic)
        return self.read_response

    async def write_gatt_char(
        self,
        characteristic: str,
        data: bytes,
        response: bool | None = None,
    ) -> None:
        packet = bytes(data)
        self.writes.append((characteristic, packet, response))

        request_service = get_service_characteristics(
            BLEProfile.TCX,
            BLEServiceID.REQUEST,
        )
        if characteristic != request_service.write or len(packet) != 20:
            return

        param_id = int.from_bytes(unpack_tcx(packet)[:2], "big")
        if param_id == 14:
            reply = pack_tcx(bytes.fromhex("f8ff000e05"))
        elif param_id == 26:
            reply = pack_tcx(bytes.fromhex("001a31"))
        else:
            reply = pack_tcx(param_id.to_bytes(2, "big") + b"\x01")
        self.notify(BLEServiceID.REQUEST, reply)

    def notify(self, service_id: BLEServiceID, data: bytes) -> None:
        uuid = get_service_characteristics(BLEProfile.TCX, service_id).notify
        callback = self.callbacks[uuid]
        characteristic = cast(
            BleakGATTCharacteristic,
            _FakeCharacteristic(uuid),
        )
        callback(characteristic, bytearray(data))


@pytest.fixture
def fake_bleak(monkeypatch: pytest.MonkeyPatch) -> type[_FakeBleakClient]:
    async def no_advertisement(
        _address: str,
        timeout: float = 10.0,
    ) -> None:
        del timeout
        return None

    monkeypatch.setattr(connection_module, "BleakClient", _FakeBleakClient)
    monkeypatch.setattr(
        connection_module,
        "find_bike_advertisement_by_address",
        no_advertisement,
    )
    return _FakeBleakClient


@pytest.mark.asyncio
async def test_tcx_connect_identifies_without_gatt_reads(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection("AA:BB:CC:DD:EE:FF")

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

    identification = [unpack_tcx(packet) for _, packet, _ in client.writes[:7]]
    assert [int.from_bytes(packet[:2], "big") for packet in identification] == [
        301,
        311,
        364,
        14,
        309,
        330,
        291,
    ]
    assert all(response is False for _, _, response in client.writes[:7])
    assert all(not is_nak_packet(packet) for packet in identification)

    await connection.disconnect()


async def test_encrypted_advertisement_requires_key_provider() -> None:
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        advertisement=BikeAdvertisement(
            generation=BLEProfile.TCX,
            encryption=ProtocolEncryptionMethod.AES_CTR,
            hmi_serial="123456789",
            hmi_hardware="3.2.1",
        ),
    )

    with pytest.raises(EncryptionKeyRequiredError):
        await connection._prepare_encryption()


async def test_manual_wrapped_key_is_resolved_before_connection() -> None:
    expected = bytes.fromhex("00112233445566778899aabbccddeeff")
    wrapping_iv = bytes(range(16))
    cipher = Cipher(
        algorithms.AES(PRODUCTION_WRAPPING_KEY),
        modes.CTR(wrapping_iv),
    )
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(expected.hex().encode()) + encryptor.finalize()
    wrapped_key = base64.b64encode(wrapping_iv + encrypted).decode()
    connection = SpecializedConnection(
        "AA:BB:CC:DD:EE:FF",
        advertisement=BikeAdvertisement(
            generation=BLEProfile.TCX,
            encryption=ProtocolEncryptionMethod.AES_CTR,
            hmi_serial="123456789",
            hmi_hardware="3.2.1",
        ),
        wrapped_key=wrapped_key,
    )

    assert await connection._prepare_encryption() == expected


@pytest.mark.asyncio
async def test_tcx_read_and_stream_control_use_notifications(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection("AA:BB:CC:DD:EE:FF")
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None

    message = await connection.request_tcx_value(26)
    assert message.converted_value == 49
    assert client.reads == []

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
    assert unpack_tcx(enable_packet)[:3] == bytes.fromhex("015b01")
    assert enable_response is False

    telemetry_packet = pack_tcx(bytes.fromhex("001a31"))
    client.notify(BLEServiceID.REQUEST, telemetry_packet)
    assert received == [telemetry_packet]

    await connection.unsubscribe_notifications()
    disable_characteristic, disable_packet, disable_response = client.writes[-1]
    assert disable_characteristic == data_service.write
    assert unpack_tcx(disable_packet)[:3] == bytes.fromhex("015b00")
    assert disable_response is False

    await connection.disconnect()


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
async def test_telemetry_monitor_primes_tcx_snapshot_without_reads(
    fake_bleak: type[_FakeBleakClient],
) -> None:
    connection = SpecializedConnection("AA:BB:CC:DD:EE:FF")
    await connection.connect()
    client = fake_bleak.instance
    assert client is not None
    monitor = TelemetryMonitor(connection)

    await monitor.start()

    assert monitor.snapshot.battery.charge_pct == 49
    assert monitor.snapshot.message_count > 0
    assert client.reads == []

    message_count = monitor.snapshot.message_count
    client.notify(
        BLEServiceID.DATA,
        pack_tcx(bytes.fromhex("f8f4ff001a31")),
    )
    assert monitor.snapshot.message_count == message_count

    await monitor.stop()
    await connection.disconnect()
