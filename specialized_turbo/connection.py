"""
BLE scanning and connection for Specialized Turbo bikes.

Wraps bleak to handle discovery, pairing, notifications, and parameter queries.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Self

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .coordinator_helpers import identify_tcx
from .protocol import (
    BLEProfile,
    ParsedMessage,
    build_request,
    get_char_notify,
    get_char_request_read,
    get_char_request_write,
    get_char_write,
    is_specialized_advertisement,
    parse_message,
    parse_tcx_message,
)
from .session import ProtocolSession, TCU1Session, TCXSession
from .transport import (
    NotificationCallback,
    TCXNotificationTransport,
    TraceCallback,
)

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
        if is_specialized_advertisement(adv.manufacturer_data) and not any(
            d.address == device.address for d, _ in found
        ):
            logger.info("Found Specialized bike: %s (%s)", device.name, device.address)
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
    telemetry notifications, and parameter queries.
    """

    def __init__(
        self,
        address_or_device: str | BLEDevice,
        *,
        pin: str | None = None,
        generation: BLEProfile = BLEProfile.TCX,
        disconnect_callback: Callable[[BleakClient], None] | None = None,
        trace_callback: TraceCallback | None = None,
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
        trace_callback :
            Optional callback receiving every raw TCX write and notification.
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
        self._trace_callback = trace_callback
        self._tcx_transport: TCXNotificationTransport | None = None
        self._telemetry_callback: NotificationCallback | None = None
        self._notification_started = False

    # -- context manager --------------------------------------------------

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
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

        # Attempt explicit pairing if a PIN was provided
        if self._pin is not None:
            # A protected characteristic access prompts WinRT for passkey entry.
            try:
                logger.debug("Triggering pairing by reading CHAR_NOTIFY ...")
                await self._client.read_gatt_char(self._char_notify)
            except Exception as exc:
                logger.debug(
                    "Initial read raised %s (expected during pairing): %s",
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
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
                logger.warning(
                    "Pairing raised %s: %s",
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )

        # Create protocol session
        if self._generation == BLEProfile.TCX:
            self._session = TCXSession()
            self._tcx_transport = TCXNotificationTransport(
                self._client,
                session=self._session,
                trace_callback=self._trace_callback,
            )
            await self._tcx_transport.subscribe_for_identification()
            session = await identify_tcx(self._tcx_transport)
            self._session = session
            self._tcx_transport.session = session
            await self._tcx_transport.subscribe_for_realtime()
        else:
            self._session = TCU1Session()

        logger.info("Connection established to %s", self._address)

    async def disconnect(self) -> None:
        """Cleanly disconnect from the bike."""
        if self._client and self._client.is_connected:
            if self._notification_started:
                try:
                    await self.unsubscribe_notifications()
                except Exception:
                    logger.debug("Failed to disable telemetry stream", exc_info=True)
            if self._tcx_transport is not None:
                try:
                    await self._tcx_transport.unsubscribe_all()
                except Exception:
                    logger.debug("Failed to stop TCX notifications", exc_info=True)
            await self._client.disconnect()
            logger.info("Disconnected from %s", self._address)
        self._client = None
        self._tcx_transport = None

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
        callback: NotificationCallback,
    ) -> None:
        """Start receiving telemetry notifications. Callback gets (characteristic, data)."""
        if self._client is None:
            raise RuntimeError("Not connected")

        if self._generation == BLEProfile.TCX:
            if self._tcx_transport is None:
                raise RuntimeError("TCX transport is not initialized")
            self._tcx_transport.add_listener(callback)
            self._telemetry_callback = callback
            try:
                await self._tcx_transport.set_realtime_enabled(True)
            except Exception:
                self._tcx_transport.remove_listener(callback)
                self._telemetry_callback = None
                raise
        else:
            await self._client.start_notify(self._char_notify, callback)
        self._notification_started = True
        logger.info("Subscribed to telemetry notifications")

    async def unsubscribe_notifications(self) -> None:
        """Stop receiving telemetry notifications."""
        if self._client and self._notification_started:
            if self._generation == BLEProfile.TCX:
                if self._tcx_transport is not None:
                    try:
                        await self._tcx_transport.set_realtime_enabled(False)
                    finally:
                        if self._telemetry_callback is not None:
                            self._tcx_transport.remove_listener(
                                self._telemetry_callback
                            )
                        self._telemetry_callback = None
            else:
                await self._client.stop_notify(self._char_notify)
            self._notification_started = False
            logger.info("Unsubscribed from notifications")

    # -- parameter queries ------------------------------------------------

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
        Query a TCX2+ value through a write/notification transaction.

        Writes a CRC-framed parameter request without response, then waits for
        the matching notification from the bike.

        If the bike rejects the request the returned ``ParsedMessage`` has
        ``nak_reason`` set to the rejection code.  A warning is logged
        with the parameter and reason for diagnostics.
        """
        if self._client is None or self._tcx_transport is None:
            raise RuntimeError("Not connected")
        logger.debug("TCX notification request param %d", param_id)
        response = await self._tcx_transport.request_parameter(param_id)
        logger.debug("TCX notification response: %s", response.hex())
        msg = parse_tcx_message(response)

        if msg.nak_reason is not None:
            from .parameters import get_tcx_field

            field_def = get_tcx_field(param_id)
            field_name = field_def.name if field_def else f"param={param_id}"
            logger.warning(
                "Bike rejected TCX request for %s (param=%d, reason=0x%02x)",
                field_name,
                param_id,
                msg.nak_reason,
            )

        return msg

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
        if self._generation == BLEProfile.TCX:
            if self._tcx_transport is None:
                raise RuntimeError("TCX transport is not initialized")
            packed = self._session.pack(data)
            logger.debug("TCX write command: %s", packed.hex())
            from .protocol import BLEServiceID

            await self._tcx_transport.write_frame(BLEServiceID.DATA, packed)
        else:
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

    # -- internal ---------------------------------------------------------

    def _on_disconnect(self, client: BleakClient) -> None:
        logger.warning("Disconnected from bike!")
        self._notification_started = False
        self._tcx_transport = None
        if self._disconnect_cb:
            self._disconnect_cb(client)
