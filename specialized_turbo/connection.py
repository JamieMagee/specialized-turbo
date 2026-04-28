"""
BLE scanning and connection for Specialized Turbo bikes.

Wraps bleak to handle discovery, pairing, notifications, and request-read queries.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .protocol import (
    BLEProfile,
    build_request,
    build_tcx_request,
    get_char_notify,
    get_char_request_read,
    get_char_request_write,
    get_char_write,
    is_specialized_advertisement,
    parse_message,
    parse_tcx_message,
    ParsedMessage,
)
from .session import ProtocolSession, TCU1Session, TCXSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scanning / discovery
# ---------------------------------------------------------------------------


async def scan_for_bikes(
    timeout: float = 10.0,
) -> list[tuple[BLEDevice, AdvertisementData]]:
    """
    Scan for Specialized Turbo bikes over BLE.

    Returns (device, advertisement_data) tuples for bikes that advertise
    as Specialized Turbo bikes (TCU1 or TCX).
    """
    found: list[tuple[BLEDevice, AdvertisementData]] = []

    def _detection_callback(device: BLEDevice, adv: AdvertisementData) -> None:
        if is_specialized_advertisement(adv.manufacturer_data):
            # Avoid duplicates
            if not any(d.address == device.address for d, _ in found):
                logger.info(
                    "Found Specialized bike: %s (%s)", device.name, device.address
                )
                found.append((device, adv))

    scanner = BleakScanner(detection_callback=_detection_callback)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()
    return found


async def find_bike_by_address(
    address: str,
    timeout: float = 10.0,
) -> BLEDevice | None:
    """Scan for a specific bike by MAC address. Returns None if not found."""
    device = await BleakScanner.find_device_by_address(address, timeout=timeout)
    return device


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


class SpecializedConnection:
    """
    Async BLE connection to a Specialized Turbo bike.

    Usage::

        async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin=946166) as conn:
            await conn.subscribe_notifications(my_callback)
            await asyncio.sleep(30)

    Handles connecting, BLE pairing (passkey entry), subscribing to
    telemetry notifications, and request-read queries.
    """

    def __init__(
        self,
        address_or_device: str | BLEDevice,
        *,
        pin: str | None = None,
        generation: BLEProfile = BLEProfile.TCX,
        disconnect_callback: Callable[[BleakClient], None] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        address_or_device :
            BLE MAC address string or a ``BLEDevice`` from scanning.
        pin :
            6-digit pairing PIN displayed on the bike's TCU.  Required for
            pairing on first connection.
        generation :
            Protocol generation (TCU1 or TCX).  Determines which
            GATT UUIDs to use.  Defaults to TCX.
        disconnect_callback :
            Optional callback invoked if the bike disconnects unexpectedly.
        """
        self._address = address_or_device
        self._pin = pin
        self._generation = generation
        self._char_notify = get_char_notify(generation)
        self._char_request_read = get_char_request_read(generation)
        self._char_request_write = get_char_request_write(generation)
        self._char_write = get_char_write(generation)
        self._client: BleakClient | None = None
        self._session: ProtocolSession = TCU1Session()
        self._disconnect_cb = disconnect_callback
        self._notification_started = False

    # -- context manager --------------------------------------------------

    async def __aenter__(self) -> SpecializedConnection:
        await self.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.disconnect()

    # -- connection lifecycle ---------------------------------------------

    async def connect(self) -> None:
        """Establish the BLE connection and trigger pairing if needed."""
        logger.info("Connecting to %s ...", self._address)

        self._client = BleakClient(
            self._address,
            disconnected_callback=self._on_disconnect,
        )
        await self._client.connect()
        logger.info("BLE connected, is_connected=%s", self._client.is_connected)

        # On Windows (WinRT), bleak supports pairing with a passkey.
        # Trigger pairing by attempting a read on the data characteristic.
        # This initiates the MITM + Secure Connections auth flow.
        try:
            logger.debug("Triggering pairing by reading CHAR_NOTIFY ...")
            await self._client.read_gatt_char(self._char_notify)
        except Exception as exc:
            logger.debug(
                "Initial read raised %s (expected during pairing): %s",
                type(exc).__name__,
                exc,
            )

        # Attempt explicit pairing if a PIN was provided
        if self._pin is not None:
            try:
                logger.info("Requesting pairing with PIN %s ...", self._pin)
                await self._client.pair(
                    protection_level=2
                )  # 2 = EncryptionAndAuthentication
                logger.info("Pairing completed")
            except NotImplementedError:
                logger.warning(
                    "bleak backend does not support programmatic pairing. "
                    "Please pair via your OS Bluetooth settings with PIN %s.",
                    self._pin,
                )
            except Exception as exc:
                logger.warning("Pairing raised %s: %s", type(exc).__name__, exc)

        # Create protocol session
        if self._generation == BLEProfile.TCX:
            session = await self._identify_tcx()
            self._session = session
        else:
            self._session = TCU1Session()

        logger.info("Connection established to %s", self._address)

    async def disconnect(self) -> None:
        """Cleanly disconnect from the bike."""
        if self._client and self._client.is_connected:
            if self._notification_started:
                try:
                    await self._client.stop_notify(self._char_notify)
                except Exception:
                    pass
                self._notification_started = False
            await self._client.disconnect()
            logger.info("Disconnected from %s", self._address)
        self._client = None

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    @property
    def session(self) -> ProtocolSession:
        """The active protocol session (TCU1Session or TCXSession)."""
        return self._session

    # -- notifications ----------------------------------------------------

    async def subscribe_notifications(
        self,
        callback: Callable[[BleakGATTCharacteristic, bytearray], None],
    ) -> None:
        """Start receiving telemetry notifications. Callback gets (characteristic, data)."""
        if self._client is None:
            raise RuntimeError("Not connected")
        await self._client.start_notify(self._char_notify, callback)
        self._notification_started = True
        logger.info("Subscribed to telemetry notifications")

    async def unsubscribe_notifications(self) -> None:
        """Stop receiving telemetry notifications."""
        if self._client and self._notification_started:
            await self._client.stop_notify(self._char_notify)
            self._notification_started = False
            logger.info("Unsubscribed from notifications")

    # -- request-read -----------------------------------------------------

    async def request_value(self, sender: int, channel: int) -> ParsedMessage:
        """
        Query a specific value using the TCU1 request-read pattern.

        Writes [sender, channel] to CHAR_REQUEST_WRITE, then reads the
        response from CHAR_REQUEST_READ.
        """
        if self._client is None:
            raise RuntimeError("Not connected")
        request_bytes = build_request(sender, channel)
        logger.debug("Request-write: %s", request_bytes.hex())
        await self._client.write_gatt_char(self._char_request_write, request_bytes)

        await asyncio.sleep(0.1)

        response = await self._client.read_gatt_char(self._char_request_read)
        logger.debug("Request-read response: %s", bytes(response).hex())
        unpacked = self._session.unpack(response)
        msg = parse_message(unpacked)

        if msg.sender != sender or msg.channel != channel:
            logger.warning(
                "Response mismatch: requested (%02x, %02x), got (%02x, %02x)",
                sender,
                channel,
                msg.sender,
                msg.channel,
            )
        return msg

    async def request_tcx_value(self, param_id: int) -> ParsedMessage:
        """
        Query a specific value using the TCX2+ request-read pattern.

        Writes a 2-byte big-endian parameter ID to CHAR_REQUEST_WRITE,
        then reads and parses the response.
        """
        if self._client is None:
            raise RuntimeError("Not connected")
        request_bytes = build_tcx_request(param_id)
        logger.debug("TCX request-write param %d: %s", param_id, request_bytes.hex())
        await self._client.write_gatt_char(self._char_request_write, request_bytes)

        await asyncio.sleep(0.1)

        response = await self._client.read_gatt_char(self._char_request_read)
        logger.debug("TCX request-read response: %s", bytes(response).hex())
        unpacked = self._session.unpack(response)
        return parse_tcx_message(unpacked)

    # -- write commands ----------------------------------------------------

    async def write_command(self, data: bytes | bytearray) -> None:
        """
        Send a write command to the bike.

        *data* is the raw command payload.  For TCU1, pass the bare
        ``[sender, channel, value…]`` bytes.  For TCX, pass the
        ``[param_id_be, value…]`` bytes — they will be CRC-framed
        and encrypted through the session automatically.
        """
        if self._client is None:
            raise RuntimeError("Not connected")
        packed = self._session.pack(data)
        logger.debug("Write command: %s", packed.hex())
        await self._client.write_gatt_char(self._char_write, packed)

    async def set_assist_level(self, level: int) -> None:
        """Set the assist level (0=OFF, 1=ECO, 2=TRAIL, 3=TURBO)."""
        from .protocol import build_write_command

        await self.write_command(
            build_write_command(0x01, 0x05, level.to_bytes(1, "little"))
        )

    async def set_assist_percentage(self, level_index: int, value: int) -> None:
        """Set assist percentage for a level (level_index: 0=ECO, 1=TRAIL, 2=TURBO; value: 0-100)."""
        from .protocol import build_write_command

        await self.write_command(
            build_write_command(0x02, 0x03 + level_index, bytes([value]))
        )

    async def set_acceleration(self, percent: float) -> None:
        """Set acceleration sensitivity (0-100%)."""
        from .protocol import build_write_command

        raw = int(percent * 60 + 3000)
        await self.write_command(
            build_write_command(0x02, 0x07, raw.to_bytes(2, "little"))
        )

    async def set_shuttle(self, value: int) -> None:
        """Set shuttle value (0-100)."""
        from .protocol import build_write_command

        await self.write_command(build_write_command(0x01, 0x15, bytes([value])))

    # -- TCX identification -----------------------------------------------

    async def _identify_tcx(self) -> TCXSession:
        """Run the TCX identification handshake and return an appropriate session.

        Executes the full 7-step identification sequence.  Step 4 may
        return encryption key material.  Returns an encrypted
        ``TCXSession`` if a key is found, or an unencrypted one otherwise.
        """
        from .encryption import derive_key
        from .framing import is_framed_packet, strip_clear_prefix, unpack_tcx
        from .parameters import BikeParameter

        assert self._client is not None

        logger.debug("Starting TCX identification handshake")

        steps = [
            BikeParameter.SYSTEM_GET_NEW_VI,  # 300
            BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION,  # 310
            BikeParameter.SYSTEM_STATE,  # 363
            BikeParameter.BATTERY1_FIRMWARE,  # 14 — encryption key
            BikeParameter.SYSTEM_HMI_HW_VERSION,  # 308
            BikeParameter.SYSTEM_MOTOR_TYPE,  # 329
            BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER,  # 290
        ]

        key_response: bytes | None = None

        for param in steps:
            request = build_tcx_request(int(param))
            await self._client.write_gatt_char(self._char_request_write, request)
            await asyncio.sleep(0.15)
            response = await self._client.read_gatt_char(self._char_request_read)
            logger.debug(
                "Identification step %d: %d bytes: %s",
                int(param),
                len(response),
                bytes(response).hex(),
            )
            if param == BikeParameter.BATTERY1_FIRMWARE:
                key_response = bytes(response)

        if key_response is None or len(key_response) < 4:
            logger.debug("No encryption key in identification response")
            return TCXSession()

        # Strip CRC framing if present, then strip f8ff envelope, then
        # skip 2-byte param ID to get the key material.
        payload = key_response
        if is_framed_packet(payload):
            payload = unpack_tcx(payload)
        payload = strip_clear_prefix(payload)
        key_data = payload[2:].rstrip(b"\x00")

        if len(key_data) == 0:
            logger.debug("Empty key response — bike does not require encryption")
            return TCXSession()

        # A valid base64 encryption key is 64 chars (~48 decoded bytes).
        # Short responses (e.g. a single firmware-version byte) are not keys.
        if len(key_data) < 20:
            logger.debug(
                "Key response too short for encryption (%d bytes) "
                "— bike does not require encryption",
                len(key_data),
            )
            return TCXSession()

        try:
            aes_key = derive_key(key_data.decode("ascii"))
            logger.info("TCX encryption key derived")
            return TCXSession(key=aes_key, iv=b"\x00" * 16)
        except Exception:
            logger.warning(
                "Failed to derive encryption key, using unencrypted session",
                exc_info=True,
            )
            return TCXSession()

    # -- internal ---------------------------------------------------------

    def _on_disconnect(self, client: BleakClient) -> None:
        logger.warning("Disconnected from bike!")
        self._notification_started = False
        if self._disconnect_cb:
            self._disconnect_cb(client)
