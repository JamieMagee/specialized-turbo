"""
Official TCX2+ identification protocol (post-connect, encrypted).

This is the profile-aware identification **state machine** that a connection
layer drives after a BLE link is established and (for encrypted bikes) the
AES key has been supplied by the caller, obtained from an external,
authorized source.  It ties together the previously-added foundation layers
-- :mod:`bike_info`, :mod:`wire_profiles`, :mod:`keystore`,
:mod:`transport`/:mod:`session`/:mod:`encryption` -- into one tested unit.
It does **not** open a BLE connection, scan, pair, or start telemetry;
those remain the caller's job.

Corrected facts this layer encodes (superseding the earlier, buggy
``coordinator_helpers.identify_tcx`` flow, which is kept only as a legacy
shim):

- The AES key is **never** read over BLE.  It must come from an external,
  authorized source (:class:`specialized_turbo.keystore.models.BikeEncryptionKey`).
  In particular TCX parameter 14 (``BATTERY1_FIRMWARE``) is a 3-byte
  firmware version string, *not* key material.
- ``SYSTEM_GET_NEW_VI`` (wire ``0x0A00``) is a **clear** control frame whose
  request carries a single required zero byte and whose response body is the
  16-byte AES-CTR **IV**.  The IV plus the supplied key are what initialise
  the encrypted session -- no key is exchanged here.
- ``SYSTEM_HMI_PROTOCOL_VERSION`` (wire ``0x0A01``) is a **clear** control
  frame whose response carries the bike's BLE and USB protocol revision
  bytes.  The BLE revision combined with ``BikeInfo.tcx_generation`` yields
  the :class:`~specialized_turbo.wire_profiles.ProtocolRevision` used to
  resolve revision-specific wire ids (e.g. ``SYSTEM_MOTOR_TYPE``).
- Every *other* read (``SYSTEM_STATE``, ``BATTERY1_FIRMWARE``,
  ``SYSTEM_HMI_HW_VERSION``, ``SYSTEM_MOTOR_TYPE``,
  ``SYSTEM_EBIKE_SERIAL_NUMBER``) is an **encrypted** mapped read: its wire
  id (from :mod:`specialized_turbo.wire_profiles`) has a non-``0x0A`` high
  byte, so :func:`specialized_turbo.encryption.is_encryptable` encrypts the
  body while leaving the 2-byte wire-id header in the clear.

No error, result, or log emitted here ever contains key material.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum

from .bike_info import BikeInfo
from .framing import FRAMED_PAYLOAD_SIZE, is_nak_packet, parse_nak_packet
from .keystore.models import BikeEncryptionKey
from .parameters import BikeParameter, decode_parameter_id
from .session import TCXSession
from .transport import TCXNotificationTransport
from .wire_profiles import (
    IdentificationProtocol,
    ProtocolRevision,
    TCXGeneration,
    UnmappedParameterError,
    UnsupportedRevisionError as _WireUnsupportedRevisionError,
    WireDatatype,
    bike_parameter_for_wire_id,
    get_wire_datatype,
    identification_wire_id_for,
    wire_id_for,
)

logger = logging.getLogger(__name__)

#: Length of the AES-CTR IV carried in the clear ``GET_NEW_VI`` response body.
IV_LENGTH = 16

#: Length of the ``BATTERY1_FIRMWARE`` (param 14) firmware-version field.
#: This is a firmware version, **not** a key -- see the module docstring.
FIRMWARE_LENGTH = 3

#: The seven identification steps, in order, expressed as app-level
#: ``BikeParameter`` values (the wire id each maps to depends on the
#: generation/revision negotiated during the handshake).
IDENTIFICATION_PARAMETER_SEQUENCE: tuple[BikeParameter, ...] = (
    BikeParameter.SYSTEM_GET_NEW_VI,
    BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION,
    BikeParameter.SYSTEM_STATE,
    BikeParameter.BATTERY1_FIRMWARE,
    BikeParameter.SYSTEM_HMI_HW_VERSION,
    BikeParameter.SYSTEM_MOTOR_TYPE,
    BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER,
)


# ---------------------------------------------------------------------------
# Errors (none carry key material)
# ---------------------------------------------------------------------------


class IdentificationError(Exception):
    """Base class for TCX identification failures."""


class IncompleteBikeInfoError(IdentificationError):
    """The pre-connect :class:`BikeInfo` is not a complete structured record.

    Identification needs the advertised structured record (HMI serial /
    hardware version, generation).  A detection-only ``BikeInfo``
    (``complete=False``) cannot drive the handshake.
    """


class UnsupportedGenerationError(IdentificationError):
    """The bike is not a TCX2/TCX3/TCX4 bike (no ``tcx_generation``)."""


class UnsupportedRevisionError(IdentificationError):
    """The bike reported a protocol revision unknown for its generation."""


class MissingEncryptionKeyError(IdentificationError):
    """No :class:`BikeEncryptionKey` was supplied for an encrypted bike.

    The key can never be obtained over BLE; it must come from an external,
    authorized source (e.g. a key file supplied out-of-band).
    """


class MalformedIVError(IdentificationError):
    """The clear ``GET_NEW_VI`` response did not carry a valid 16-byte IV."""


class MalformedProtocolResponseError(IdentificationError):
    """The clear ``HMI_PROTOCOL_VERSION`` response was not a valid revision reply."""


class DecryptionError(IdentificationError):
    """An encrypted read could not be decrypted/CRC-validated.

    Almost always a wrong (or stale) encryption key: the clear wire-id
    header still correlates the response, but the AES-CTR body fails its
    CRC-16 check after decryption.  Never carries key material.
    """


class IdentificationNakError(IdentificationError):
    """The bike rejected an identification request with a NAK."""

    def __init__(self, phase: IdentificationPhase, wire_id: int, reason: int) -> None:
        super().__init__(
            f"Bike rejected identification step {phase.value} "
            f"(wire 0x{wire_id:04x}, reason 0x{reason:02x})"
        )
        self.phase = phase
        self.wire_id = wire_id
        self.reason = reason


# ---------------------------------------------------------------------------
# State + result types
# ---------------------------------------------------------------------------


class IdentificationPhase(StrEnum):
    """Typed progress state of the identification state machine."""

    NOT_STARTED = "not_started"
    INSTALL_IV = "install_iv"
    NEGOTIATE_REVISION = "negotiate_revision"
    READ_SYSTEM_STATE = "read_system_state"
    READ_BATTERY_FIRMWARE = "read_battery_firmware"
    READ_HMI_HW_VERSION = "read_hmi_hw_version"
    READ_MOTOR_TYPE = "read_motor_type"
    READ_SERIAL = "read_serial"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class WireMessage:
    """A profile-aware decode of a TCX response payload.

    Reverse-maps the response's wire command id back to a
    :class:`~specialized_turbo.parameters.BikeParameter` for the negotiated
    generation/revision (``None`` if the wire id is unknown there).  Unlike
    the legacy :func:`specialized_turbo.protocol.parse_tcx_message`, which
    treats the 2-byte header as a ``BikeParameter`` value directly, this
    resolves the header as a *wire id* first.
    """

    wire_id: int
    parameter: BikeParameter | None
    data: bytes
    value: int | None
    nak_reason: int | None = None

    @property
    def is_nak(self) -> bool:
        return self.nak_reason is not None


@dataclass(frozen=True, slots=True)
class IdentificationResult:
    """Structured outcome of a successful identification handshake.

    Deliberately carries no key or IV material.  The ready-to-use encrypted
    :class:`~specialized_turbo.session.TCXSession` is installed on the
    transport and exposed via :attr:`TCXIdentification.session`.
    """

    generation: TCXGeneration
    protocol_revision: ProtocolRevision
    ble_revision: int
    usb_revision: int
    system_state: int | None
    battery_firmware: tuple[int, ...] | None
    hmi_hardware_version: str | None
    motor_type: int | None
    ebike_serial: str | None
    encrypted: bool = True


# ---------------------------------------------------------------------------
# Profile-aware message parsing
# ---------------------------------------------------------------------------

_SCALAR_DATATYPES = frozenset(
    {
        WireDatatype.INT,
        WireDatatype.BOOL,
        WireDatatype.FLOAT,
        WireDatatype.SYSTEM_STATE,
        WireDatatype.BIKE_TYPE,
    }
)


def _reverse_parameter(
    wire_id: int,
    generation: TCXGeneration,
    revision: int | None,
) -> BikeParameter | None:
    try:
        return bike_parameter_for_wire_id(wire_id, generation, revision)
    except (UnmappedParameterError, _WireUnsupportedRevisionError):
        return None


def _decode_scalar(parameter: BikeParameter | None, data: bytes) -> int | None:
    """Little-endian scalar value for scalar datatypes, else ``None``."""
    if parameter is None:
        return None
    info = get_wire_datatype(parameter)
    if info is None or info.datatype not in _SCALAR_DATATYPES:
        return None
    length = min(info.length_bytes, len(data))
    if length == 0:
        return None
    return int.from_bytes(data[:length], "little")


def parse_wire_message(
    payload: bytes | bytearray,
    generation: TCXGeneration,
    revision: int | None = None,
) -> WireMessage:
    """Profile-aware parse of an unpacked TCX response *payload*.

    *payload* is the CRC-stripped (and, for encrypted reads, already
    decrypted) response as returned by
    :meth:`TCXNotificationTransport.request_wire_parameter`.  The wire id is
    reverse-mapped to a :class:`~specialized_turbo.parameters.BikeParameter`
    for the given generation/revision.

    Raises:
        ValueError: *payload* is shorter than the 2-byte wire-id header.
    """
    if len(payload) < 2:
        raise ValueError(f"Payload too short ({len(payload)} bytes), need at least 2")

    if is_nak_packet(payload):
        echoed_wire, reason = parse_nak_packet(payload)
        return WireMessage(
            wire_id=echoed_wire,
            parameter=_reverse_parameter(echoed_wire, generation, revision),
            data=b"",
            value=None,
            nak_reason=reason,
        )

    wire_id = decode_parameter_id(payload)
    parameter = _reverse_parameter(wire_id, generation, revision)
    data = bytes(payload[2:])
    return WireMessage(
        wire_id=wire_id,
        parameter=parameter,
        data=data,
        value=_decode_scalar(parameter, data),
    )


def _decode_string(data: bytes) -> str:
    """Decode a NUL-padded ASCII/Latin-1 identification string field."""
    return data.rstrip(b"\x00").decode("latin-1")


# ---------------------------------------------------------------------------
# Identification state machine
# ---------------------------------------------------------------------------


class TCXIdentification:
    """Drives the official TCX2+ identification handshake over a transport.

    The *transport* must already be connected (and, on real bikes, paired).
    *bike_info* is the complete pre-connect advertisement parse (its
    ``tcx_generation`` selects the wire map); *key* is the AES key obtained
    from an external, authorized source.  Call :meth:`run` once.
    """

    def __init__(
        self,
        transport: TCXNotificationTransport,
        bike_info: BikeInfo,
        key: BikeEncryptionKey | None,
        *,
        timeout: float | None = None,
    ) -> None:
        self._transport = transport
        self._bike_info = bike_info
        self._key = key
        self._timeout = timeout
        self._phase = IdentificationPhase.NOT_STARTED
        self._failed_phase: IdentificationPhase | None = None
        self._session: TCXSession | None = None
        self._result: IdentificationResult | None = None

    @property
    def phase(self) -> IdentificationPhase:
        """Current (or terminal) state-machine phase."""
        return self._phase

    @property
    def failed_phase(self) -> IdentificationPhase | None:
        """The phase that was in progress when the handshake failed, if any."""
        return self._failed_phase

    @property
    def session(self) -> TCXSession | None:
        """The negotiated encrypted session, once the IV has been installed."""
        return self._session

    @property
    def result(self) -> IdentificationResult | None:
        """The identification result, once :meth:`run` has completed."""
        return self._result

    async def run(self) -> IdentificationResult:
        """Execute the full handshake and return an :class:`IdentificationResult`.

        On success the negotiated encrypted :class:`~specialized_turbo.session.
        TCXSession` **and** the negotiated
        :class:`~specialized_turbo.wire_profiles.ProtocolRevision` are both
        installed on the transport before returning, so a caller driving the
        transport directly (e.g. a Home Assistant client that uses
        :func:`identify` rather than :class:`~specialized_turbo.connection.
        SpecializedConnection`) can immediately call
        :meth:`~specialized_turbo.transport.TCXNotificationTransport.
        request_bike_parameter` / ``write_bike_parameter`` /
        ``set_realtime_enabled`` without any further wiring.

        Raises a subclass of :class:`IdentificationError` on protocol
        failures, or :class:`~specialized_turbo.transport.
        TCXTransportDisconnectedError` if the link drops mid-handshake.  On
        any failure :attr:`phase` becomes :attr:`IdentificationPhase.FAILED`
        and :attr:`failed_phase` records the step that was in progress.
        """
        try:
            generation, key = self._validate_preconditions()
            await self._transport.subscribe_for_identification()
            await self._install_iv(key)
            revision, ble_revision, usb_revision = await self._negotiate_revision(
                generation
            )
            result = await self._read_parameters(
                generation, revision, ble_revision, usb_revision
            )
        except Exception:
            if self._phase is not IdentificationPhase.FAILED:
                self._failed_phase = self._phase
            self._phase = IdentificationPhase.FAILED
            raise
        self._phase = IdentificationPhase.COMPLETE
        self._result = result
        # Install the negotiated revision on the transport alongside the
        # session so BikeParameter -> wire id resolution works immediately,
        # even without a SpecializedConnection.
        self._transport.protocol_revision = result.protocol_revision
        return result

    # -- preconditions ----------------------------------------------------

    def _validate_preconditions(self) -> tuple[TCXGeneration, BikeEncryptionKey]:
        if not self._bike_info.complete:
            raise IncompleteBikeInfoError(
                "BikeInfo is detection-only (complete=False); a structured "
                "advertisement record is required to identify the bike"
            )
        generation = self._bike_info.tcx_generation
        if generation is None:
            raise UnsupportedGenerationError(
                "BikeInfo has no TCX generation; not a TCX2/TCX3/TCX4 bike"
            )
        if self._key is None:
            raise MissingEncryptionKeyError(
                "No encryption key supplied. This key can never be obtained "
                "over BLE; it must come from an external, authorized source "
                "(e.g. a key file supplied out-of-band)."
            )
        return generation, self._key

    # -- step 1: install IV, build encrypted session ----------------------

    async def _install_iv(self, key: BikeEncryptionKey) -> bytes:
        self._phase = IdentificationPhase.INSTALL_IV
        wire_id = identification_wire_id_for(
            BikeParameter.SYSTEM_GET_NEW_VI, IdentificationProtocol.TCX2
        )
        raw = await self._transport.request_wire_parameter(
            wire_id, body=b"\x00", timeout=self._timeout
        )
        self._raise_for_nak(self._phase, raw)
        if len(raw) != FRAMED_PAYLOAD_SIZE or decode_parameter_id(raw) != wire_id:
            raise MalformedIVError("GET_NEW_VI response was not a valid clear IV frame")
        iv = bytes(raw[2 : 2 + IV_LENGTH])
        if len(iv) != IV_LENGTH:
            raise MalformedIVError(
                f"GET_NEW_VI IV must be {IV_LENGTH} bytes, got {len(iv)}"
            )
        session = TCXSession(key=key.raw, iv=iv)
        self._session = session
        self._transport.session = session
        logger.debug("Installed identification IV, encrypted session active")
        return iv

    # -- step 2: negotiate protocol revision ------------------------------

    async def _negotiate_revision(
        self, generation: TCXGeneration
    ) -> tuple[ProtocolRevision, int, int]:
        self._phase = IdentificationPhase.NEGOTIATE_REVISION
        wire_id = identification_wire_id_for(
            BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION, IdentificationProtocol.TCX2
        )
        raw = await self._transport.request_wire_parameter(
            wire_id, timeout=self._timeout
        )
        self._raise_for_nak(self._phase, raw)
        if (
            len(raw) != FRAMED_PAYLOAD_SIZE
            or decode_parameter_id(raw) != wire_id
            or len(raw) < 4
        ):
            raise MalformedProtocolResponseError(
                "HMI_PROTOCOL_VERSION response was not a valid clear revision frame"
            )
        ble_revision = raw[2]
        usb_revision = raw[3]
        try:
            revision = ProtocolRevision(generation=generation, revision=ble_revision)
        except _WireUnsupportedRevisionError as exc:
            raise UnsupportedRevisionError(
                f"Bike reported unknown {generation.name} protocol revision "
                f"0x{ble_revision:02x}"
            ) from exc
        logger.debug(
            "Negotiated %s revision 0x%02x (usb 0x%02x)",
            generation.name,
            ble_revision,
            usb_revision,
        )
        return revision, ble_revision, usb_revision

    # -- steps 3-7: encrypted mapped reads --------------------------------

    async def _read_parameters(
        self,
        generation: TCXGeneration,
        revision: ProtocolRevision,
        ble_revision: int,
        usb_revision: int,
    ) -> IdentificationResult:
        rev = revision.revision

        state_msg = await self._encrypted_read(
            IdentificationPhase.READ_SYSTEM_STATE,
            BikeParameter.SYSTEM_STATE,
            generation,
            rev,
        )
        firmware_msg = await self._encrypted_read(
            IdentificationPhase.READ_BATTERY_FIRMWARE,
            BikeParameter.BATTERY1_FIRMWARE,
            generation,
            rev,
        )
        hw_msg = await self._encrypted_read(
            IdentificationPhase.READ_HMI_HW_VERSION,
            BikeParameter.SYSTEM_HMI_HW_VERSION,
            generation,
            rev,
        )
        motor_msg = await self._encrypted_read(
            IdentificationPhase.READ_MOTOR_TYPE,
            BikeParameter.SYSTEM_MOTOR_TYPE,
            generation,
            rev,
        )
        serial_msg = await self._encrypted_read(
            IdentificationPhase.READ_SERIAL,
            BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER,
            generation,
            rev,
        )

        # param 14 is a firmware version, never key material: keep only its
        # 3 firmware bytes.
        firmware = tuple(firmware_msg.data[:FIRMWARE_LENGTH])

        return IdentificationResult(
            generation=generation,
            protocol_revision=revision,
            ble_revision=ble_revision,
            usb_revision=usb_revision,
            system_state=state_msg.value,
            battery_firmware=firmware or None,
            hmi_hardware_version=_decode_string(hw_msg.data) or None,
            motor_type=motor_msg.value,
            ebike_serial=_decode_string(serial_msg.data) or None,
        )

    async def _encrypted_read(
        self,
        phase: IdentificationPhase,
        parameter: BikeParameter,
        generation: TCXGeneration,
        revision: int,
    ) -> WireMessage:
        self._phase = phase
        wire_id = wire_id_for(parameter, generation, revision)
        raw = await self._transport.request_wire_parameter(
            wire_id, timeout=self._timeout
        )
        self._raise_for_nak(phase, raw)
        if len(raw) != FRAMED_PAYLOAD_SIZE:
            # The clear wire-id header still correlated the response, but the
            # encrypted body failed its CRC after decryption -> wrong key.
            raise DecryptionError(
                f"Could not decrypt {parameter.name} response "
                f"(step {phase.value}); the encryption key is likely wrong"
            )
        return parse_wire_message(raw, generation, revision)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _raise_for_nak(phase: IdentificationPhase, raw: bytes) -> None:
        if is_nak_packet(raw):
            echoed_wire, reason = parse_nak_packet(raw)
            raise IdentificationNakError(phase, echoed_wire, reason)


async def identify(
    transport: TCXNotificationTransport,
    bike_info: BikeInfo,
    key: BikeEncryptionKey | None,
    *,
    timeout: float | None = None,
) -> IdentificationResult:
    """Convenience wrapper: run :class:`TCXIdentification` once.

    The negotiated encrypted session **and** protocol revision are installed
    on *transport* before returning, so ``transport.request_bike_parameter``/
    ``write_bike_parameter``/``set_realtime_enabled`` work immediately; the
    return value is the structured identification result.  For access to the
    session or intermediate phase, construct :class:`TCXIdentification`
    directly.
    """
    return await TCXIdentification(transport, bike_info, key, timeout=timeout).run()
