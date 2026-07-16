"""
Helpers for BLE coordinator integrations (e.g. Home Assistant).

These functions encapsulate device-specific protocol logic so that
integration coordinators can stay thin.  They work with an externally-
managed ``BleakClient`` (the integration controls connection lifecycle)
while the library handles parsing, polling, and identification.
"""

from __future__ import annotations

import asyncio
import logging

from bleak import BleakClient

from .framing import (
    is_framed_packet,
    is_nak_packet,
    parse_nak_packet,
)
from .identification import WireMessage, parse_wire_message
from .models import TelemetrySnapshot
from .parameters import BikeParameter, get_tcx_field
from .protocol import (
    TCU1_POLL_FIELDS,
    build_request,
    parse_message,
    parse_tcx_message,
    ParsedMessage,
)
from .session import ProtocolSession, TCXSession
from .transport import TCXNotificationTransport, TCXTransportDisconnectedError
from .wire_profiles import ProtocolRevision, UnmappedParameterError, wire_id_for

logger = logging.getLogger(__name__)

#: TCX2+ parameter IDs to query through write/notification transactions.
TCX_POLL_PARAMS: tuple[BikeParameter, ...] = (
    BikeParameter.SYSTEM_STATE,
    BikeParameter.SYSTEM_RANGE_LONG,
    BikeParameter.SYSTEM_RANGE_SHORT,
    BikeParameter.SYSTEM_TEMPERATURE,
    BikeParameter.SYSTEM_CONSUMPTION,
    BikeParameter.SYSTEM_ALT,
    BikeParameter.SYSTEM_ALT_GAIN,
    BikeParameter.SYSTEM_GRADIENT,
    BikeParameter.BATTERY1_STATE_OF_CHARGE,
    BikeParameter.MOTOR_BIKE_SPEED,
    BikeParameter.MOTOR_BIKE_CADENCE,
    BikeParameter.MOTOR_POWER,
    BikeParameter.MOTOR_RIDER_INPUT_POWER,
    BikeParameter.MOTOR_TEMPERATURE,
)


def parse_notification(
    session: ProtocolSession,
    data: bytes,
) -> ParsedMessage:
    """Parse a BLE notification using the appropriate protocol format.

    Auto-detects whether *data* is a CRC-framed TCX packet or a bare
    TCU1 message, unpacks it through *session*, and returns a
    :class:`ParsedMessage`.

    Raises on parse failure (caller should catch and log).
    """
    if is_framed_packet(data):
        unpacked = session.unpack(data)
        return parse_tcx_message(unpacked)
    return parse_message(data)


def _wire_message_to_parsed_message(msg: WireMessage) -> ParsedMessage:
    """Adapt a profile-aware :class:`WireMessage` into a legacy :class:`ParsedMessage`.

    Reuses the ``BikeParameter``-keyed field metadata in
    :mod:`specialized_turbo.parameters` (name/unit/conversion) so existing
    consumers (:meth:`TelemetrySnapshot.update_from_message`, the
    ``_FIELD_NAME_MAP`` field-name routing) keep working unchanged.  Unlike
    :func:`specialized_turbo.protocol.parse_tcx_message`, ``sender``/
    ``channel`` here are derived from *msg.wire_id* -- the actual wire
    command id -- rather than assuming it equals the ``BikeParameter`` enum
    value.
    """
    sender = msg.wire_id >> 8
    channel = msg.wire_id & 0xFF

    if msg.is_nak:
        return ParsedMessage(
            sender=sender,
            channel=channel,
            raw_value=msg.wire_id,
            converted_value=None,
            field_name=None,
            unit="",
            nak_reason=msg.nak_reason,
        )

    field_def = get_tcx_field(int(msg.parameter)) if msg.parameter is not None else None
    payload = msg.data.rstrip(b"\x00")

    if field_def is None:
        # Unknown/unmapped parameter -- surface the raw bytes without a name.
        raw = int.from_bytes(payload, "little") if payload else 0
        return ParsedMessage(
            sender=sender,
            channel=channel,
            raw_value=raw,
            converted_value=raw if payload else None,
            field_name=None,
            unit="",
        )

    if not payload:
        return ParsedMessage(
            sender=sender,
            channel=channel,
            raw_value=0,
            converted_value=None,
            field_name=field_def.name,
            unit=field_def.unit,
        )

    actual_size = min(field_def.data_size, len(payload))
    raw = int.from_bytes(payload[:actual_size], "little")
    return ParsedMessage(
        sender=sender,
        channel=channel,
        raw_value=raw,
        converted_value=field_def.convert(raw),
        field_name=field_def.name,
        unit=field_def.unit,
    )


def parse_tcx_wire_payload(
    payload: bytes | bytearray,
    revision: ProtocolRevision,
) -> ParsedMessage:
    """Profile-aware parse of an already-unpacked TCX response *payload*.

    Resolves *payload*'s wire id back to a ``BikeParameter`` for the given
    *revision* (via :func:`specialized_turbo.identification.parse_wire_message`,
    which uses :mod:`specialized_turbo.wire_profiles`) instead of assuming
    the wire id equals the ``BikeParameter`` enum value, then adapts the
    result into a legacy :class:`ParsedMessage`.

    *payload* must already be CRC-stripped and (for an encrypted session)
    decrypted -- i.e. what :meth:`TCXNotificationTransport.request_wire_parameter`
    returns, or what :func:`parse_tcx_notification` passes it internally.
    """
    wire_msg = parse_wire_message(payload, revision.generation, revision.revision)
    return _wire_message_to_parsed_message(wire_msg)


def parse_tcx_notification(
    session: TCXSession,
    data: bytes | bytearray,
    revision: ProtocolRevision,
) -> ParsedMessage:
    """Unpack a raw TCX notification/response and parse it profile-aware.

    Pure function: unpacks *data* through *session* (CRC-strip and, for an
    encrypted session, AES-CTR decrypt) and resolves it to a
    :class:`ParsedMessage` for the negotiated *revision* via
    :func:`parse_tcx_wire_payload`.  Use this for raw bytes straight off a
    BLE notification; if a transport has already unpacked the payload (e.g.
    :meth:`TCXNotificationTransport.request_wire_parameter`), call
    :func:`parse_tcx_wire_payload` directly instead.
    """
    payload = session.unpack(data)
    return parse_tcx_wire_payload(payload, revision)


async def poll_tcu1(
    client: BleakClient,
    char_request_write: str,
    char_request_read: str,
    snapshot: TelemetrySnapshot,
) -> bool:
    """Poll all TCU1 fields via request-read and update *snapshot*.

    Returns ``True`` if any field was updated.
    """
    updated = False
    for sender, channel in TCU1_POLL_FIELDS:
        try:
            await client.write_gatt_char(
                char_request_write, build_request(sender, channel)
            )
            await asyncio.sleep(0.1)
            response = await client.read_gatt_char(char_request_read)
            msg = parse_message(response)
            if msg.sender == sender and msg.channel == channel:
                snapshot.update_from_message(msg)
                updated = True
        except Exception:  # noqa: BLE001
            logger.debug(
                "Failed to poll TCU1 field (%02x, %02x)",
                sender,
                channel,
                exc_info=True,
            )
    return updated


async def poll_tcx(
    transport: TCXNotificationTransport,
    snapshot: TelemetrySnapshot,
    revision: ProtocolRevision,
) -> bool:
    """Poll TCX fields through write/notification transactions.

    Each entry in :data:`TCX_POLL_PARAMS` is resolved to its wire command id
    for the active *revision* (see :mod:`specialized_turbo.wire_profiles`)
    and requested through the transport's wire-aware
    :meth:`TCXNotificationTransport.request_wire_parameter`.  Parameters with
    no known wire id for this revision, NAKed reads, and any parse/snapshot
    failure (e.g. an unexpectedly short or malformed response) are contained
    to the current parameter and skipped -- logged with the parameter and
    wire id for context -- so one bad field can't abort the rest of the
    poll.  A bike disconnect is the one failure that propagates immediately
    to the caller.

    Returns ``True`` if any field was updated.
    """
    updated = False
    for param in TCX_POLL_PARAMS:
        try:
            wire_id = wire_id_for(param, revision.generation, revision.revision)
        except UnmappedParameterError:
            logger.debug(
                "No wire id for %s on %s revision 0x%02x; skipping poll",
                param.name,
                revision.generation.name,
                revision.revision,
            )
            continue
        try:
            payload = await transport.request_wire_parameter(wire_id)
        except TCXTransportDisconnectedError:
            raise
        except Exception:  # noqa: BLE001
            logger.debug(
                "Failed to poll TCX %s (wire 0x%04x)",
                param.name,
                wire_id,
                exc_info=True,
            )
            continue
        try:
            msg = parse_tcx_wire_payload(payload, revision)
        except Exception:  # noqa: BLE001
            logger.debug(
                "Failed to parse TCX %s (wire 0x%04x) response: %s",
                param.name,
                wire_id,
                payload.hex(),
                exc_info=True,
            )
            continue
        if msg.nak_reason is not None:
            logger.debug(
                "TCX %s (wire 0x%04x) rejected with reason 0x%02x",
                param.name,
                wire_id,
                msg.nak_reason,
            )
            continue
        try:
            snapshot.update_from_message(msg)
        except Exception:  # noqa: BLE001
            logger.debug(
                "Failed to update snapshot from TCX %s (wire 0x%04x)",
                param.name,
                wire_id,
                exc_info=True,
            )
            continue
        updated = True
    return updated


async def identify_tcx(
    transport: TCXNotificationTransport,
) -> TCXSession:
    """Run the legacy identification read sequence and return a session.

    .. deprecated::
       This predates the official TCX2+ handshake in
       :mod:`specialized_turbo.identification`.  It used to derive an
       "encryption key" from the ``BATTERY1_FIRMWARE`` response -- that
       response is a 3-byte firmware version string, never key material,
       and no valid AES key can be recovered from it (the length guard
       below meant this path never actually fired on a real bike; it just
       silently fell back to an unencrypted session).  That false key
       derivation has been removed outright rather than left as dead code.

       New code should use :class:`specialized_turbo.identification.TCXIdentification`
       (or the :func:`specialized_turbo.identification.identify` convenience
       wrapper), which fetches the real key from the account keystore and
       negotiates generation/revision-correct wire ids.  This function is
       kept only so existing callers (e.g. :class:`SpecializedConnection`)
       keep importing and calling it; it now always returns an unencrypted
       :class:`TCXSession`.
    """
    steps = [
        BikeParameter.SYSTEM_GET_NEW_VI,
        BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION,
        BikeParameter.SYSTEM_STATE,
        BikeParameter.BATTERY1_FIRMWARE,
        BikeParameter.SYSTEM_HMI_HW_VERSION,
        BikeParameter.SYSTEM_MOTOR_TYPE,
        BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER,
    ]

    try:
        for param in steps:
            inner = await transport.request_parameter(int(param))

            if is_nak_packet(inner):
                echoed, reason = parse_nak_packet(inner)
                logger.warning(
                    "Identification step %d (%s) rejected by bike: "
                    "echoed_param=%d reason=0x%02x",
                    int(param),
                    param.name,
                    echoed,
                    reason,
                )
    except TCXTransportDisconnectedError:
        raise
    except Exception:  # noqa: BLE001
        logger.warning(
            "TCX identification handshake failed, using unencrypted session",
            exc_info=True,
        )

    return TCXSession()
