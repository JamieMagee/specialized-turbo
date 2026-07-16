"""
BLE scanning and connection for Specialized Turbo bikes.

Wraps bleak to handle discovery, pairing, notifications, and parameter queries.
"""

from __future__ import annotations

import asyncio
import logging
import warnings
from collections.abc import Callable
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .bike_info import BikeInfo
from .identification import (
    IdentificationResult,
    TCXIdentification,
    WireMessage,
    parse_wire_message,
)
from .keystore.models import BikeEncryptionKey
from .parameters import BikeParameter
from .protocol import (
    BLEProfile,
    build_request,
    get_char_notify,
    get_char_request_read,
    get_char_request_write,
    get_char_write,
    is_specialized_advertisement,
    parse_message,
    parse_tcx_message,
    ParsedMessage,
)
from .session import ProtocolSession, TCU1Session
from .transport import (
    NotificationCallback,
    TCXNotificationTransport,
    TraceCallback,
)
from .wire_profiles import ProtocolRevision

logger = logging.getLogger(__name__)


class UnsupportedTCXOperationError(RuntimeError):
    """A TCU1 convenience write has no verified TCX2+ ``BikeParameter`` equivalent.

    Raised instead of guessing a wire id for an operation (e.g. shuttle)
    that has no confirmed mapping on the TCX2+ protocol, so a TCX write can
    never silently address the wrong parameter.
    """


#: Sentinel used when no ``BikeInfo`` is supplied to :class:`SpecializedConnection`.
#: ``complete=False`` routes straight into :class:`~specialized_turbo.
#: identification.IncompleteBikeInfoError` instead of an ``AttributeError``.
_UNKNOWN_BIKE_INFO = BikeInfo(name="", bike_name="", is_bike=False, complete=False)


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

    TCX2+ bikes require the pre-connect advertisement parse (*bike_info*, see
    :func:`specialized_turbo.bike_info.parse_bike_info`) and the AES key
    fetched out-of-band from the account keystore (*key*, a
    :class:`~specialized_turbo.keystore.models.BikeEncryptionKey`) so the
    official identification handshake can run and negotiate the protocol
    revision. TCU1 bikes need neither. Usage::

        async with SpecializedConnection(
            "DC:DD:BB:4A:D6:55", pin="946166", bike_info=info, key=key
        ) as conn:
            await conn.subscribe_notifications(my_callback)
            await asyncio.sleep(30)

    Handles connecting, BLE pairing (passkey entry), the TCX identification
    handshake, subscribing to telemetry notifications, and parameter queries.
    """

    def __init__(
        self,
        address_or_device: str | BLEDevice,
        *,
        pin: str | None = None,
        generation: BLEProfile = BLEProfile.TCX,
        bike_info: BikeInfo | None = None,
        key: BikeEncryptionKey | None = None,
        disconnect_callback: Callable[[BleakClient], None] | None = None,
        trace_callback: TraceCallback | None = None,
        identification_timeout: float | None = None,
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
        bike_info :
            The pre-connect advertisement parse (see
            :func:`specialized_turbo.bike_info.parse_bike_info`).  Required
            for a TCX connection: it must be ``complete`` and carry a
            ``tcx_generation`` so the official identification handshake
            (:class:`~specialized_turbo.identification.TCXIdentification`)
            can select the right wire-id map.  Ignored for TCU1.
        key :
            The bike's AES-128 encryption key, fetched out-of-band from the
            account keystore (never available over BLE). Required for a
            TCX connection, since every complete TCX ``BikeInfo`` implies
            AES-CTR encryption. Never logged -- see
            :class:`~specialized_turbo.keystore.models.BikeEncryptionKey`.
        disconnect_callback :
            Optional callback invoked if the bike disconnects unexpectedly.
        trace_callback :
            Optional callback receiving every raw TCX write and notification.
        identification_timeout :
            Optional per-request timeout (seconds) for each identification
            step. Defaults to the transport's own timeout.
        """
        self._address = address_or_device
        self._pin = pin
        self._generation = generation
        self._bike_info = bike_info
        self._key = key
        self._identification_timeout = identification_timeout
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
        self._identification_result: IdentificationResult | None = None
        self._protocol_revision: ProtocolRevision | None = None

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
                logger.warning("Pairing raised %s: %s", type(exc).__name__, exc)

        # Create protocol session
        if self._generation == BLEProfile.TCX:
            transport = TCXNotificationTransport(
                self._client,
                trace_callback=self._trace_callback,
            )
            self._tcx_transport = transport
            bike_info = (
                self._bike_info if self._bike_info is not None else _UNKNOWN_BIKE_INFO
            )
            identification = TCXIdentification(
                transport,
                bike_info,
                self._key,
                timeout=self._identification_timeout,
            )
            try:
                result = await identification.run()
                self._session = transport.session
                transport.protocol_revision = result.protocol_revision
                self._protocol_revision = result.protocol_revision
                self._identification_result = result
                await transport.subscribe_for_realtime()
            except Exception:
                logger.warning(
                    "TCX connect failed during identification/setup "
                    "(failed_phase=%s, phase=%s)",
                    identification.failed_phase,
                    identification.phase,
                )
                await self._reset_after_failed_tcx_connect()
                raise
        else:
            self._session = TCU1Session()

        logger.info("Connection established to %s", self._address)

    async def _reset_after_failed_tcx_connect(self) -> None:
        """Return to a clean, retryable state after a failed TCX identification.

        Never leaves partial state (a stale transport, a half-negotiated
        session) behind: a subsequent :meth:`connect` call starts fresh.
        """
        self._tcx_transport = None
        self._session = TCU1Session()
        self._protocol_revision = None
        self._identification_result = None
        client = self._client
        self._client = None
        if client is not None and client.is_connected:
            try:
                await client.disconnect()
            except Exception:
                logger.debug(
                    "Failed to disconnect after failed TCX identification",
                    exc_info=True,
                )

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
        self._protocol_revision = None
        self._identification_result = None

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    @property
    def session(self) -> ProtocolSession:
        """The active protocol session (TCU1Session or TCXSession)."""
        return self._session

    @property
    def active_revision(self) -> ProtocolRevision | None:
        """The active TCX generation/revision, negotiated during identification.

        This is the canonical accessor consumers should read (e.g.
        :class:`~specialized_turbo.telemetry.TelemetryMonitor`, via the
        :class:`~specialized_turbo.telemetry.RevisionAwareConnection`
        structural protocol) to know which wire-id map is in effect -- see
        :mod:`specialized_turbo.wire_profiles`.

        Read-only: ``None`` for a TCU1 connection, or before a TCX
        identification handshake has completed.
        """
        return self._protocol_revision

    @property
    def protocol_revision(self) -> ProtocolRevision | None:
        """Alias of :attr:`active_revision`.

        Kept for symmetry with
        :attr:`~specialized_turbo.identification.IdentificationResult.protocol_revision`
        and :attr:`~specialized_turbo.transport.TCXNotificationTransport.protocol_revision`.
        New code should prefer :attr:`active_revision`.
        """
        return self._protocol_revision

    @property
    def identification_result(self) -> IdentificationResult | None:
        """The full result of the TCX identification handshake, if any.

        Read-only: ``None`` for a TCU1 connection, or before identification
        has completed.
        """
        return self._identification_result

    # -- notifications ----------------------------------------------------

    async def subscribe_notifications(
        self,
        callback: NotificationCallback,
    ) -> None:
        """Start receiving telemetry notifications. Callback gets (characteristic, data)."""
        if self._client is None:
            raise RuntimeError("Not connected")

        if self._generation == BLEProfile.TCX:
            transport = self._tcx_transport
            if transport is None:
                raise RuntimeError("TCX transport is not initialized")
            transport.add_listener(callback)
            self._telemetry_callback = callback
            try:
                await transport.set_realtime_enabled(True)
            except Exception:
                transport.remove_listener(callback)
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
                transport = self._tcx_transport
                if transport is not None:
                    try:
                        await transport.set_realtime_enabled(False)
                    finally:
                        if self._telemetry_callback is not None:
                            transport.remove_listener(self._telemetry_callback)
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

        .. deprecated::
           *param_id* is treated directly as the wire command id (the
           legacy behaviour from before generation/revision-aware wire
           mapping existed).  It only returns the right value for
           parameters whose wire id happens to equal their
           :class:`~specialized_turbo.parameters.BikeParameter` value.  New
           code should call :meth:`request_tcx_parameter` instead, which
           resolves the wire id through the ``ProtocolRevision`` negotiated
           during identification (see :attr:`protocol_revision`).

        Writes a CRC-framed parameter request without response, then waits for
        the matching notification from the bike.

        If the bike rejects the request the returned ``ParsedMessage`` has
        ``nak_reason`` set to the rejection code.  A warning is logged
        with the parameter and reason for diagnostics.
        """
        warnings.warn(
            "request_tcx_value(param_id) addresses the bike by a raw wire "
            "id and is deprecated; use request_tcx_parameter(BikeParameter) "
            "instead, which resolves the wire id through the negotiated "
            "ProtocolRevision.",
            DeprecationWarning,
            stacklevel=2,
        )
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

    async def request_tcx_parameter(
        self,
        param: BikeParameter,
        *,
        timeout: float | None = None,
    ) -> WireMessage:
        """
        Query a TCX2+ value by its stable app-level ``BikeParameter`` id.

        Resolves *param* to a wire command id through the
        :class:`~specialized_turbo.wire_profiles.ProtocolRevision`
        negotiated during identification (see :attr:`protocol_revision`),
        then correlates the response by that wire id.  This is the
        profile-aware replacement for :meth:`request_tcx_value`: it never
        assumes a ``BikeParameter`` value coincides with its wire id.

        If the bike rejects the request the returned :class:`~specialized_
        turbo.identification.WireMessage` has ``nak_reason`` set, and a
        warning is logged with the parameter and reason for diagnostics.
        """
        if self._client is None or self._tcx_transport is None:
            raise RuntimeError("Not connected")
        revision = self._protocol_revision
        if revision is None:
            raise RuntimeError(
                "TCX identification has not completed; no protocol "
                "revision has been negotiated"
            )
        logger.debug("TCX notification request %s", param.name)
        response = await self._tcx_transport.request_bike_parameter(
            param, timeout=timeout
        )
        msg = parse_wire_message(response, revision.generation, revision.revision)

        if msg.nak_reason is not None:
            logger.warning(
                "Bike rejected TCX request for %s (wire=0x%04x, reason=0x%02x)",
                param.name,
                msg.wire_id,
                msg.nak_reason,
            )

        return msg

    # -- write commands ----------------------------------------------------

    async def write_command(self, data: bytes | bytearray) -> None:
        """
        Send a raw write command to the bike.

        .. deprecated::
           For TCX, *data* is treated as an already wire-ready
           ``[wire_id_be, value…]`` payload -- the caller is responsible
           for resolving the wire id themselves (e.g. via
           :mod:`specialized_turbo.wire_profiles`).  Passing a raw
           :class:`~specialized_turbo.parameters.BikeParameter` value here
           only writes the intended parameter if it happens to coincide
           with its wire id.  New code addressing a TCX2+ parameter should
           call :meth:`write_tcx_parameter` instead, which resolves the
           wire id through the negotiated :attr:`protocol_revision`. TCU1
           callers are unaffected: pass the bare
           ``[sender, channel, value…]`` bytes as before.
        """
        if self._client is None:
            raise RuntimeError("Not connected")
        if self._generation == BLEProfile.TCX:
            if self._tcx_transport is None:
                raise RuntimeError("TCX transport is not initialized")
            warnings.warn(
                "write_command() on a TCX connection treats data as an "
                "already wire-ready [wire_id_be, value...] payload and is "
                "deprecated; use write_tcx_parameter(BikeParameter, value), "
                "which resolves the wire id through the negotiated "
                "ProtocolRevision. (TCU1 callers are unaffected.)",
                DeprecationWarning,
                stacklevel=2,
            )
            packed = self._session.pack(data)
            logger.debug("TCX write command: %s", packed.hex())
            from .protocol import BLEServiceID

            await self._tcx_transport.write_frame(BLEServiceID.DATA, packed)
        else:
            packed = self._session.pack(data)
            logger.debug("Write command: %s", packed.hex())
            await self._client.write_gatt_char(self._char_write, packed)

    async def write_tcx_parameter(
        self,
        param: BikeParameter,
        data: bytes | bytearray,
    ) -> None:
        """
        Write a TCX2+ value by its stable app-level ``BikeParameter`` id.

        Resolves *param* to a wire command id through the negotiated
        :attr:`protocol_revision` before writing -- the profile-aware
        replacement for :meth:`write_command` on the TCX path.
        """
        if self._client is None or self._tcx_transport is None:
            raise RuntimeError("Not connected")
        if self._protocol_revision is None:
            raise RuntimeError(
                "TCX identification has not completed; no protocol "
                "revision has been negotiated"
            )
        await self._tcx_transport.write_bike_parameter(param, data)

    #: TCX2+ profile-scaling parameters for ECO/TRAIL/TURBO, indexed to match
    #: :meth:`set_assist_percentage`'s ``level_index`` (0=ECO, 1=TRAIL, 2=TURBO).
    _TCX_PROFILE_SCALING = (
        BikeParameter.MOTOR_PROFILE_SCALING_ECO_SETTING,
        BikeParameter.MOTOR_PROFILE_SCALING_TRAIL_SETTING,
        BikeParameter.MOTOR_PROFILE_SCALING_TURBO_SETTING,
    )

    async def set_assist_level(self, level: int) -> None:
        """Set the assist level (0=OFF, 1=ECO, 2=TRAIL, 3=TURBO).

        On TCX2+ this maps to ``MOTOR_ACTIVE_TRAVEL_MODE`` through the
        negotiated protocol revision; on TCU1 it keeps the legacy
        sender/channel write unchanged.
        """
        if self._generation == BLEProfile.TCX:
            await self.write_tcx_parameter(
                BikeParameter.MOTOR_ACTIVE_TRAVEL_MODE, bytes([level])
            )
            return

        from .protocol import build_write_command

        await self.write_command(
            build_write_command(0x01, 0x05, level.to_bytes(1, "little"))
        )

    async def set_assist_percentage(self, level_index: int, value: int) -> None:
        """Set assist percentage for a level (level_index: 0=ECO, 1=TRAIL, 2=TURBO; value: 0-100).

        On TCX2+ this maps to the matching ``MOTOR_PROFILE_SCALING_*_SETTING``
        parameter through the negotiated protocol revision; on TCU1 it keeps
        the legacy sender/channel write unchanged.
        """
        if self._generation == BLEProfile.TCX:
            try:
                param = self._TCX_PROFILE_SCALING[level_index]
            except IndexError:
                raise ValueError(
                    f"level_index must be 0 (ECO), 1 (TRAIL), or 2 (TURBO), "
                    f"got {level_index}"
                ) from None
            await self.write_tcx_parameter(param, bytes([value]))
            return

        from .protocol import build_write_command

        await self.write_command(
            build_write_command(0x02, 0x03 + level_index, bytes([value]))
        )

    async def set_acceleration(self, percent: float) -> None:
        """Set acceleration sensitivity (0-100%).

        On TCX2+ this maps to ``MOTOR_ACCELERATION_RESPONSE`` through the
        negotiated protocol revision (same ``percent * 60 + 3000`` wire
        encoding); on TCU1 it keeps the legacy sender/channel write unchanged.
        """
        raw = int(percent * 60 + 3000)
        if self._generation == BLEProfile.TCX:
            await self.write_tcx_parameter(
                BikeParameter.MOTOR_ACCELERATION_RESPONSE, raw.to_bytes(2, "little")
            )
            return

        from .protocol import build_write_command

        await self.write_command(
            build_write_command(0x02, 0x07, raw.to_bytes(2, "little"))
        )

    async def set_shuttle(self, value: int) -> None:
        """Set shuttle value (0-100).

        TCU1 only: there is no verified TCX2+ ``BikeParameter`` equivalent
        for the TCU1 shuttle write, so this raises
        :class:`UnsupportedTCXOperationError` on a TCX connection rather than
        guessing a wire id.
        """
        if self._generation == BLEProfile.TCX:
            raise UnsupportedTCXOperationError(
                "set_shuttle has no verified TCX2+ BikeParameter equivalent; "
                "it is supported on TCU1 only"
            )

        from .protocol import build_write_command

        await self.write_command(build_write_command(0x01, 0x15, bytes([value])))

    # -- internal ---------------------------------------------------------

    def _on_disconnect(self, client: BleakClient) -> None:
        logger.warning("Disconnected from bike!")
        self._notification_started = False
        transport = self._tcx_transport
        self._tcx_transport = None
        if transport is not None:
            transport.mark_disconnected()
        if self._disconnect_cb:
            self._disconnect_cb(client)
