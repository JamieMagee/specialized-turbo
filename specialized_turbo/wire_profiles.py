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

from enum import IntEnum, StrEnum
from dataclasses import dataclass
from functools import lru_cache

from . import _wire_map_data as _data
from .parameters import BikeParameter

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


@lru_cache(maxsize=None)
def _reverse_generation_only(generation: int) -> dict[int, int]:
    return {
        gens[generation]: value
        for value, gens in _data.GENERATION_DEFAULTS.items()
        if generation in gens
    }


@lru_cache(maxsize=None)
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


@lru_cache(maxsize=None)
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
    """Return datatype/length/group metadata for ``param``, or ``None`` if unknown."""
    entry = _data.DATATYPES.get(int(param))
    if entry is None:
        return None
    datatype, length_bytes, group_id = entry
    return WireDatatypeInfo(
        datatype=WireDatatype(datatype), length_bytes=length_bytes, group_id=group_id
    )
