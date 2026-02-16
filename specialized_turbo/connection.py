"""
BLE scanning and connection for Specialized Turbo bikes.

Wraps bleak to handle discovery, pairing, notifications, and request-read queries.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .protocol import (
    CHAR_NOTIFY,
    CHAR_REQUEST_READ,
    CHAR_REQUEST_WRITE,
    build_request,
    is_specialized_advertisement,
    parse_message,
    ParsedMessage,
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
    the TURBOHMI manufacturer data under Nordic's company ID (0x0059).
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
        pin: int | None = None,
        disconnect_callback: Callable[[BleakClient], None] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        address_or_device :
            BLE MAC address string or a ``BLEDevice`` from scanning.
        pin :
            Numeric passkey displayed on the bike's TCU.  Required for
            pairing on first connection.
        disconnect_callback :
            Optional callback invoked if the bike disconnects unexpectedly.
        """
        self._address = address_or_device
        self._pin = pin
        self._client: BleakClient | None = None
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
            await self._client.read_gatt_char(CHAR_NOTIFY)
        except Exception as exc:
            logger.debug(
                "Initial read raised %s (expected during pairing): %s",
                type(exc).__name__,
                exc,
            )

        # Attempt explicit pairing if a PIN was provided
        if self._pin is not None:
            try:
                logger.info("Requesting pairing with PIN %d ...", self._pin)
                await self._client.pair(
                    protection_level=2
                )  # 2 = EncryptionAndAuthentication
                logger.info("Pairing completed")
            except NotImplementedError:
                logger.warning(
                    "bleak backend does not support programmatic pairing. "
                    "Please pair via your OS Bluetooth settings with PIN %d.",
                    self._pin,
                )
            except Exception as exc:
                logger.warning("Pairing raised %s: %s", type(exc).__name__, exc)

        logger.info("Connection established to %s", self._address)

    async def disconnect(self) -> None:
        """Cleanly disconnect from the bike."""
        if self._client and self._client.is_connected:
            if self._notification_started:
                try:
                    await self._client.stop_notify(CHAR_NOTIFY)
                except Exception:
                    pass
                self._notification_started = False
            await self._client.disconnect()
            logger.info("Disconnected from %s", self._address)
        self._client = None

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    # -- notifications ----------------------------------------------------

    async def subscribe_notifications(
        self,
        callback: Callable[[BleakGATTCharacteristic, bytearray], None],
    ) -> None:
        """Start receiving telemetry notifications. Callback gets (characteristic, data)."""
        if self._client is None:
            raise RuntimeError("Not connected")
        await self._client.start_notify(CHAR_NOTIFY, callback)
        self._notification_started = True
        logger.info("Subscribed to telemetry notifications")

    async def unsubscribe_notifications(self) -> None:
        """Stop receiving telemetry notifications."""
        if self._client and self._notification_started:
            await self._client.stop_notify(CHAR_NOTIFY)
            self._notification_started = False
            logger.info("Unsubscribed from notifications")

    # -- request-read -----------------------------------------------------

    async def request_value(self, sender: int, channel: int) -> ParsedMessage:
        """
        Query a specific value using the request-read pattern.

        Writes [sender, channel] to CHAR_REQUEST_WRITE, then reads the
        response from CHAR_REQUEST_READ. You may need to unsubscribe
        from notifications first, since they can interfere.
        """
        if self._client is None:
            raise RuntimeError("Not connected")
        request_bytes = build_request(sender, channel)
        logger.debug("Request-write: %s", request_bytes.hex())
        await self._client.write_gatt_char(CHAR_REQUEST_WRITE, request_bytes)

        # Small delay to allow the bike to prepare the response
        await asyncio.sleep(0.1)

        response = await self._client.read_gatt_char(CHAR_REQUEST_READ)
        logger.debug("Request-read response: %s", bytes(response).hex())
        msg = parse_message(response)

        # Verify response matches request
        if msg.sender != sender or msg.channel != channel:
            logger.warning(
                "Response mismatch: requested (%02x, %02x), got (%02x, %02x)",
                sender,
                channel,
                msg.sender,
                msg.channel,
            )
        return msg

    # -- internal ---------------------------------------------------------

    def _on_disconnect(self, client: BleakClient) -> None:
        logger.warning("Disconnected from bike!")
        self._notification_started = False
        if self._disconnect_cb:
            self._disconnect_cb(client)
