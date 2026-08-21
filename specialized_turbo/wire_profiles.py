"""
Generation/revision-aware BikeParameter -> TCX wire-ID mapping.

``BikeParameter`` (see :mod:`specialized_turbo.parameters`) is the *app-level*
parameter identifier: a stable, generation-independent integer used
throughout this library and in the upstream Specialized app's own model
layer. It is **not** what goes on the wire.

The *wire command ID* is the 16-bit big-endian value written into the
2-byte header of a TCX packet (see :func:`specialized_turbo.parameters.
encode_parameter_id`). The same ``BikeParameter`` can map to different wire
IDs depending on:

- **generation** -- TCX2, TCX3, or TCX4 (:class:`TCXGeneration`) -- different
  firmware families support different parameter sets.
- **revision** -- a single-byte protocol revision code reported by the bike
  during identification (``HmiProtocolVersion.ble``, see
  ``docs/protocol.md``); a handful of parameters (e.g. ``SYSTEM_MOTOR_TYPE``)
  use different wire IDs across revisions of the *same* generation.
- **wire profile** -- most parameters use one wire ID both during the
  identification handshake and on the full post-identification protocol, but
  a few (e.g. ``SYSTEM_HMI_PROTOCOL_VERSION``) use a distinct ID during
  identification. See :class:`IdentificationProtocol`.

This module only provides lookups; it does not change how the bike is
identified, connected to, or how any existing message gets built or parsed.

The underlying data (:mod:`specialized_turbo._wire_map_data`) was
reverse-engineered from the Specialized Mission Control Android app --
see that module's docstring for full provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from functools import cache

from . import _wire_map_data as _data
from .parameters import BikeParameter, decode_parameter_id, encode_parameter_id

# ---------------------------------------------------------------------------
# Generation / revision / profile types
# ---------------------------------------------------------------------------


class TCXGeneration(IntEnum):
    """TCX protocol generation, as determined by the identification handshake."""

    TCX2 = 2
    TCX3 = 3
    TCX4 = 4


class IdentificationProtocol(StrEnum):
    """Which identification-phase parameter map a wire ID belongs to.

    ``TCX2`` is ``ProtocolIdentificationTCX2``, used by the modern 7-step
    unknown-bike identification sequence (``SYSTEM_GET_NEW_VI`` ->
    ``SYSTEM_HMI_PROTOCOL_VERSION`` -> full protocol). ``BASE`` is the older
    ``ProtocolIdentification`` map, which shares wire IDs with the
    TCU1/legacy generation and is unrelated to the TCX2+ handshake.
    """

    TCX2 = "ident_tcx2"
    BASE = "ident_base"


@dataclass(frozen=True, slots=True)
class ProtocolRevision:
    """A specific TCX protocol revision, e.g. TCX2 revision ``0x12``."""

    generation: TCXGeneration
    revision: int

    def __post_init__(self) -> None:
        _validate_revision(self.generation, self.revision)


# ---------------------------------------------------------------------------
# Datatype metadata
# ---------------------------------------------------------------------------


class WireDatatype(StrEnum):
    """Wire-level datatype of a parameter's payload (``ParameterType`` in the app)."""

    BOOL = "BOOL"
    INT = "INT"
    FLOAT = "FLOAT"
    FIRMWARE_VERSION = "FIRMWARE_VERSION"
    STRING = "STRING"
    BIKE_TYPE = "BIKE_TYPE"
    SYSTEM_STATE = "SYSTEM_STATE"


@dataclass(frozen=True, slots=True)
class WireDatatypeInfo:
    """Datatype and framing metadata for a single ``BikeParameter``."""

    datatype: WireDatatype
    length_bytes: int
    group_id: int
    group_offset_bytes: int | None


# Native ``ParameterInfo`` stores each grouped field's byte offset separately
# from its datatype, length, and group ID. These offsets are identical across
# the checked TCX2, TCX3, and TCX4 protocol constructors in app v1.70.1.
_GROUP_OFFSETS: dict[BikeParameter, int] = {
    BikeParameter.BATTERY1_CHARGING_ACTIVE: 7,
    BikeParameter.BATTERY1_CURRENT_LEVEL: 5,
    BikeParameter.BATTERY1_FIRMWARE: 2,
    BikeParameter.BATTERY1_FULL_CAPACITY: 0,
    BikeParameter.BATTERY1_HEALTH: 2,
    BikeParameter.BATTERY1_ON_BIKE_CHARGE_CYCLES: 5,
    BikeParameter.BATTERY1_REMAINING_CAPACITY: 1,
    BikeParameter.BATTERY1_STATE_OF_CHARGE: 0,
    BikeParameter.BATTERY1_TEMPERATURE: 3,
    BikeParameter.BATTERY1_TOTAL_CHARGE_CYCLES: 3,
    BikeParameter.BATTERY1_VOLTAGE_LEVEL: 4,
    BikeParameter.BATTERY2_CURRENT_LEVEL: 5,
    BikeParameter.BATTERY2_FULL_CAPACITY: 0,
    BikeParameter.BATTERY2_HEALTH: 2,
    BikeParameter.BATTERY2_REMAINING_CAPACITY: 1,
    BikeParameter.BATTERY2_STATE_OF_CHARGE: 0,
    BikeParameter.BATTERY2_TEMPERATURE: 3,
    BikeParameter.BATTERY2_TOTAL_CHARGE_CYCLES: 3,
    BikeParameter.BATTERY2_VOLTAGE_LEVEL: 4,
    BikeParameter.MOTOR_ACTIVE_TRAVEL_MODE: 13,
    BikeParameter.MOTOR_BIKE_CADENCE: 2,
    BikeParameter.MOTOR_BIKE_SPEED: 0,
    BikeParameter.MOTOR_MAX_SPEED_LIMIT: 8,
    BikeParameter.MOTOR_ODOMETER: 8,
    BikeParameter.MOTOR_POWER: 6,
    BikeParameter.MOTOR_RIDER_INPUT_POWER: 4,
    BikeParameter.MOTOR_TEMPERATURE: 12,
    BikeParameter.MOTOR_WHEEL_SIZE: 10,
    BikeParameter.SYSTEM_ALT: 8,
    BikeParameter.SYSTEM_ALT_DESCENT: 3,
    BikeParameter.SYSTEM_ALT_GAIN: 0,
    BikeParameter.SYSTEM_BIKE_TYPE: 14,
    BikeParameter.SYSTEM_CONSUMPTION: 13,
    BikeParameter.SYSTEM_GRADIENT: 11,
    BikeParameter.SYSTEM_HMI_HW_VERSION: 0,
    BikeParameter.SYSTEM_KCAL: 6,
    BikeParameter.SYSTEM_MOTOR_TYPE: 2,
    BikeParameter.SYSTEM_RANGE_LONG: 8,
    BikeParameter.SYSTEM_RANGE_SHORT: 10,
    BikeParameter.SYSTEM_RANGE_TREND: 12,
    BikeParameter.SYSTEM_STATE: 0,
    BikeParameter.SYSTEM_TEMPERATURE: 10,
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WireProfileError(Exception):
    """Base class for wire-profile lookup errors."""


class UnsupportedRevisionError(WireProfileError):
    """The requested revision byte is not a known revision for the generation."""


class UnmappedParameterError(WireProfileError):
    """The parameter has no known wire ID for the requested generation/revision."""


# ---------------------------------------------------------------------------
# Generation / revision queries
# ---------------------------------------------------------------------------


def known_revisions(generation: TCXGeneration) -> frozenset[int]:
    """Return the set of known protocol revision bytes for a TCX generation."""
    revisions = _data.KNOWN_REVISIONS.get(int(generation))
    if revisions is None:
        raise UnsupportedRevisionError(
            f"No known revisions for generation {generation!r}"
        )
    return frozenset(revisions)


def _validate_revision(generation: TCXGeneration, revision: int) -> None:
    if revision not in known_revisions(generation):
        raise UnsupportedRevisionError(
            f"Revision 0x{revision:02x} is not a known revision for {generation.name}"
        )


# ---------------------------------------------------------------------------
# Full-protocol wire ID lookups
# ---------------------------------------------------------------------------


def wire_id_for(
    param: BikeParameter,
    generation: TCXGeneration,
    revision: int | None = None,
) -> int:
    """Return the full-protocol wire command ID for ``param``.

    If ``revision`` is given, it is validated against the known revisions for
    ``generation`` and used to resolve parameters whose wire ID varies across
    revisions of the same generation (e.g. ``SYSTEM_MOTOR_TYPE``). If omitted,
    only parameters with a single wire ID shared by every known revision of
    ``generation`` can be resolved.

    Raises:
        UnsupportedRevisionError: ``revision`` is not a known revision of ``generation``.
        UnmappedParameterError: ``param`` has no known wire ID for the given
            generation/revision (either it was never observed there, or a
            revision is required to disambiguate it and none was given).
    """
    if revision is not None:
        _validate_revision(generation, revision)
        override = _data.REVISION_OVERRIDES.get(int(param), {}).get(
            (int(generation), revision)
        )
        if override is not None:
            return override

    default = _data.GENERATION_DEFAULTS.get(int(param), {}).get(int(generation))
    if default is not None:
        return default

    raise UnmappedParameterError(
        f"{param.name} has no known TCX wire ID for {generation.name}"
        + (
            f" revision 0x{revision:02x}"
            if revision is not None
            else " (a specific revision may be required)"
        )
    )


@cache
def _reverse_generation_only(generation: int) -> dict[int, int]:
    return {
        gens[generation]: value
        for value, gens in _data.GENERATION_DEFAULTS.items()
        if generation in gens
    }


@cache
def _reverse_for_revision(generation: int, revision: int) -> dict[int, int]:
    table = dict(_reverse_generation_only(generation))
    for value, overrides in _data.REVISION_OVERRIDES.items():
        wire_id = overrides.get((generation, revision))
        if wire_id is not None:
            table[wire_id] = value
    return table


def bike_parameter_for_wire_id(
    wire_id: int,
    generation: TCXGeneration,
    revision: int | None = None,
) -> BikeParameter:
    """Reverse of :func:`wire_id_for`: resolve a wire command ID back to a ``BikeParameter``.

    Raises:
        UnsupportedRevisionError: ``revision`` is not a known revision of ``generation``.
        UnmappedParameterError: no known ``BikeParameter`` maps to ``wire_id`` for
            the given generation/revision.
    """
    if revision is not None:
        _validate_revision(generation, revision)
        table = _reverse_for_revision(int(generation), revision)
    else:
        table = _reverse_generation_only(int(generation))

    value = table.get(wire_id)
    if value is None:
        raise UnmappedParameterError(
            f"No BikeParameter maps to wire id 0x{wire_id:04x} for {generation.name}"
            + (f" revision 0x{revision:02x}" if revision is not None else "")
        )
    return BikeParameter(value)


# ---------------------------------------------------------------------------
# Identification-phase wire ID lookups
# ---------------------------------------------------------------------------


def identification_wire_id_for(
    param: BikeParameter,
    protocol: IdentificationProtocol = IdentificationProtocol.TCX2,
) -> int:
    """Return the identification-phase wire command ID for ``param``.

    Raises:
        UnmappedParameterError: ``param`` has no known wire ID for ``protocol``.
    """
    entry = _data.IDENTIFICATION_WIRE_IDS.get(int(param))
    if entry is None or protocol.value not in entry:
        raise UnmappedParameterError(
            f"{param.name} has no known identification-phase wire ID for {protocol.name}"
        )
    return entry[protocol.value]


@cache
def _reverse_identification(protocol: str) -> dict[int, int]:
    return {
        entry[protocol]: value
        for value, entry in _data.IDENTIFICATION_WIRE_IDS.items()
        if protocol in entry
    }


def bike_parameter_for_identification_wire_id(
    wire_id: int,
    protocol: IdentificationProtocol = IdentificationProtocol.TCX2,
) -> BikeParameter:
    """Reverse of :func:`identification_wire_id_for`."""
    table = _reverse_identification(protocol.value)
    value = table.get(wire_id)
    if value is None:
        raise UnmappedParameterError(
            f"No BikeParameter maps to identification wire id 0x{wire_id:04x} for {protocol.name}"
        )
    return BikeParameter(value)


def identification_parameters() -> frozenset[BikeParameter]:
    """Return every ``BikeParameter`` with at least one known identification-phase wire ID.

    This includes parameters read only during the modern TCX2+ handshake
    (:attr:`IdentificationProtocol.TCX2`), only during the legacy/base
    identification protocol (:attr:`IdentificationProtocol.BASE`), or both.
    """
    return frozenset(BikeParameter(value) for value in _data.IDENTIFICATION_WIRE_IDS)


# ---------------------------------------------------------------------------
# Datatype metadata lookups
# ---------------------------------------------------------------------------


def get_wire_datatype(param: BikeParameter) -> WireDatatypeInfo | None:
    """Return datatype and group-layout metadata, or ``None`` if unknown."""
    entry = _data.DATATYPES.get(int(param))
    if entry is None:
        return None
    datatype, length_bytes, group_id = entry
    return WireDatatypeInfo(
        datatype=WireDatatype(datatype),
        length_bytes=length_bytes,
        group_id=group_id,
        group_offset_bytes=_GROUP_OFFSETS.get(param),
    )


def extract_group_parameter_payload(
    payload: bytes | bytearray,
    param: BikeParameter,
    generation: TCXGeneration,
    revision: int,
) -> bytes:
    """Extract one field from a native group response.

    A grouped response retains the group ID in its 2-byte header and packs
    every member into fixed offsets in the 16-byte body. Individual field
    responses are returned unchanged.
    """
    if len(payload) < 2:
        raise ValueError(f"Payload too short ({len(payload)} bytes), need at least 2")

    response_wire_id = decode_parameter_id(payload)
    target_wire_id = wire_id_for(param, generation, revision)
    info = get_wire_datatype(param)
    if (
        info is None
        or info.group_offset_bytes is None
        or response_wire_id != info.group_id
    ):
        if response_wire_id != target_wire_id:
            raise ValueError(
                f"Response wire id 0x{response_wire_id:04x} does not match "
                f"{param.name} (wire 0x{target_wire_id:04x})"
            )
        return bytes(payload)

    start = 2 + info.group_offset_bytes
    end = start + info.length_bytes
    if len(payload) < end:
        raise ValueError(
            f"Group 0x{info.group_id:04x} payload is too short for {param.name}: "
            f"{len(payload)} bytes, need at least {end}"
        )
    return encode_parameter_id(target_wire_id) + bytes(payload[start:end])
