"""
BLE advertisement -> ``BikeInfo`` parsing.

A Python port of ``TurboConnectCore::getBikeInfo``/``isBike``, reverse
engineered from ``libturbo-core.so`` (Specialized app 1.66.0). This is a
*pre-connect* parse: it only ever looks at the advertised name and BLE
manufacturer data, never at a GATT connection.

Key findings this module implements (see the BLE advertisement -> BikeInfo
report for full evidence):

- The Nordic (``0x0059``) manufacturer-data payload is a **structured
  10-byte record** for TCX2+ bikes, carrying the HMI serial, HMI hardware
  version, bike type, and system state -- it is not unrelated/opaque data.
- ``hmiType`` is derived from the HMI hardware-version string (built from
  Nordic bytes 4-6, e.g. ``"B.3.3"``) looked up in a hardware-compatibility
  table (:mod:`specialized_turbo._hmi_compat_data`), not from the
  advertisement bytes directly and not from the device name.
- The Apple iBeacon frame (``0x004C``) is **detection magic only**;
  ``getBikeInfo``/``isBike`` never read its bytes for fields. If a Nordic
  10-byte record is also present, it is used; otherwise the result is
  marked incomplete rather than guessing fields from Apple data.
- The AES key is never present in the advertisement -- it is provisioned
  out-of-band by the backend -- so it has no field here.
- Simplo (``0x020D``) advertisements are TCU1 (legacy, unencrypted) bikes.

``BLEProfile`` (which GATT UUID family a bike speaks -- TCU1/Simplo vs.
TCX/Nordic) and ``TCXGeneration`` (the fine-grained TCX2/TCX3/TCX4
identification-protocol generation) are two different, independent axes.
A Nordic advertisement is always ``BLEProfile.TCX`` -- even when its
HMI-hardware family (``HmiType``) happens to be one of the legacy
``TCU1``/``TCDw`` families with no TCX2+ generation -- because the
company ID (and thus which GATT characteristics/UUIDs the bike will
speak) is Nordic. ``TCXGeneration`` is therefore only ever set when the
looked-up ``HmiType`` maps to one of TCU2/TCDw2 (TCX2), T3/H3 (TCX3), or
C4/T4 (TCX4); it stays ``None`` for any other (including unknown/legacy)
hardware.

This module's ``is_bike`` is a *strict*, native-faithful reimplementation
of ``isBike`` and intentionally does **not** match every advertisement
the existing, more permissive :func:`specialized_turbo.protocol.
detect_generation`/:func:`specialized_turbo.protocol.
is_specialized_advertisement` helpers do (e.g. a bike whose *only*
discovery signal is the ``TURBOHMI2017`` magic inside an Apple iBeacon
frame, with a name that doesn't contain ``"SPECIALIZED"``, is not
``is_bike`` here -- native ``isBike`` never reads company ``0x004C``
either). Production **discovery** (deciding whether to attempt a BLE
connection at all) should keep using the existing, broader
``detect_generation``/``is_specialized_advertisement`` superset, not this
module's ``is_bike``. To help bridge the two, :func:`parse_bike_info`
still best-efforts a coarse ``ble_profile`` via ``detect_generation`` for
any advertisement it can't fully or partially decode -- so ``ble_profile``
can be non-``None`` even when ``is_bike`` is ``False``.

This module does not change ``detect_generation``/
``is_specialized_advertisement`` themselves, and does not open or manage
a BLE connection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from . import _hmi_compat_data as _hmi_compat
from .protocol import (
    NORDIC_COMPANY_ID,
    SIMPLO_COMPANY_ID,
    BLEProfile,
    detect_generation,
)
from .wire_profiles import TCXGeneration

# ---------------------------------------------------------------------------
# Enums (DWARF-confirmed: HmiType, BikeType, SystemState, ProtocolEncryptionMethod)
# ---------------------------------------------------------------------------


class HmiType(IntEnum):
    """HMI hardware family, looked up from the HMI hardware-version string."""

    UNKNOWN = 0
    TCU1 = 1
    TCDw = 2
    TCU2 = 3
    TCDw2 = 4
    T3 = 5
    H3 = 6
    C4 = 7
    T4 = 8


class BikeType(IntEnum):
    """Bike model/platform, as advertised in the Nordic payload's byte 8."""

    PROTOTYPE = 0
    TURBO = 1
    LEVO1 = 2
    VADO = 3
    PLW = 4
    LEVO2 = 5
    COMO2 = 6
    PLW2 = 7
    APLW2 = 8
    PLUTO = 9
    APLUTO = 10
    APLUTOPLUS = 11
    PLUTO2 = 12


class BikeSystemState(IntEnum):
    """Bike system state, as advertised in the Nordic payload's byte 9.

    Named distinctly from :class:`specialized_turbo.models.SystemState`
    (post-connection telemetry state) to avoid confusion: this enum only
    describes the coarse on/off/reset/locked state visible pre-connect.
    """

    OFF = 0
    ON = 1
    RESET = 2
    LOCKED = 3


class ProtocolEncryptionMethod(IntEnum):
    """Wire-level encryption method implied by the advertisement."""

    NONE = 0
    AES_CTR = 1


# ---------------------------------------------------------------------------
# Internal lookup tables
# ---------------------------------------------------------------------------

# getHmiType()'s category-check order. "TCUArterytek" is intentionally
# excluded: getHmiType() skips that category and falls through to UNKNOWN.
_HMI_CATEGORY_TO_TYPE: dict[str, HmiType] = {
    "TCU": HmiType.TCU1,
    "TCDw": HmiType.TCDw,
    "TCU2": HmiType.TCU2,
    "TCDw2": HmiType.TCDw2,
    "T3": HmiType.T3,
    "H3": HmiType.H3,
    "C4": HmiType.C4,
    "T4": HmiType.T4,
}

# knownVersionsNoTcx1(): union of HW-version strings for TCU2-and-newer
# categories, used by isBike()'s HW-version-membership detection branch.
_KNOWN_NO_TCX1: frozenset[str] = frozenset(
    hw
    for category in ("TCU2", "TCDw2", "T3", "H3", "C4", "T4")
    for hw in _hmi_compat.HW_COMPATIBILITY[category]
)

# getBikeTypeAsString(): used to build the composite bikeName display
# string, including the "?<value>" fallback for unrecognized byte values.
_BIKE_TYPE_NAMES: dict[int, str] = {int(bt): bt.name for bt in BikeType}

# TCU1 (Simplo) payload byte-0 model code -> display name.
_TCU1_MODEL_NAMES: dict[int, str] = {1: "TURBO", 2: "LEVO"}

_MAGIC = b"TURBOHMI2017"


def _hmi_hw_string(three_bytes: bytes) -> str:
    """Build the "X.Y.Z" HMI hardware-version string from 3 raw bytes.

    Matches the native implementation exactly: each byte is decoded as a
    single ASCII/Latin-1 character with no validation. A non-ASCII byte
    still yields a (non-matching) string deterministically -- it simply
    fails every hardware-compatibility lookup below and results in
    :attr:`HmiType.UNKNOWN`, exactly as the native parser would.
    """
    return f"{chr(three_bytes[0])}.{chr(three_bytes[1])}.{chr(three_bytes[2])}"


def _hmi_type_for_hw(hmi_hw: str) -> HmiType:
    for category, hmi_type in _HMI_CATEGORY_TO_TYPE.items():
        if hmi_hw in _hmi_compat.HW_COMPATIBILITY[category]:
            return hmi_type
    return HmiType.UNKNOWN


def _tcx_generation_for_hmi_type(hmi_type: HmiType) -> TCXGeneration | None:
    """isTCX2/isTCX3/isTCX4 classification.

    Returns ``None`` for anything that isn't a TCX2/TCX3/TCX4 HMI-hardware
    family -- including :attr:`HmiType.UNKNOWN` and the legacy
    :attr:`HmiType.TCU1`/:attr:`HmiType.TCDw` families. This is *only* the
    fine-grained protocol generation; it says nothing about which
    ``BLEProfile`` the advertisement uses (see module docstring).
    """
    if hmi_type in (HmiType.TCU2, HmiType.TCDw2):
        return TCXGeneration.TCX2
    if hmi_type in (HmiType.T3, HmiType.H3):
        return TCXGeneration.TCX3
    if hmi_type in (HmiType.C4, HmiType.T4):
        return TCXGeneration.TCX4
    return None


def _is_bike(name: str, manufacturer_data: dict[int, bytes]) -> bool:
    """Reimplementation of ``TurboConnectCore::isBike``.

    True if the name contains the literal, uppercase ``"SPECIALIZED"``
    (case-sensitive -- the native memchr-based scan matches that exact
    byte sequence, not a case-folded one; a `name` shorter than 11
    characters can never satisfy this by construction), a Simplo (TCU1)
    entry is present, or a Nordic entry is present that either carries the
    ``TURBOHMI2017`` magic (>=12 bytes) or is a 10-byte record whose
    HW-version string belongs to a TCU2-or-newer category. Company
    ``0x004C`` (Apple) is never consulted, matching the native
    implementation.
    """
    if "SPECIALIZED" in name:
        return True
    if SIMPLO_COMPANY_ID in manufacturer_data:
        return True
    nordic = manufacturer_data.get(NORDIC_COMPANY_ID)
    if nordic is not None:
        if len(nordic) >= 12 and _MAGIC in nordic:
            return True
        if len(nordic) == 10 and _hmi_hw_string(nordic[4:7]) in _KNOWN_NO_TCX1:
            return True
    return False


# ---------------------------------------------------------------------------
# BikeInfo
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BikeInfo:
    """Fields derivable from a BLE advertisement, before any GATT connection.

    Mirrors ``TurboConnectCore::getBikeInfo``'s output. Many upstream
    ``BikeInfo`` fields (protocol version, firmware versions, serials, the
    AES key) are never populated from the advertisement alone and have no
    equivalent here -- they require the encrypted post-connect
    identification handshake.

    ``complete`` distinguishes a fully-decoded record (TCU1, or a Nordic
    10-byte structured record) from a detection-only result: ``is_bike``
    can be ``True`` while ``complete`` is ``False`` (e.g. a bike detected
    only by name or by the Nordic ``TURBOHMI2017`` magic, with no Nordic
    10-byte payload present). Callers must not treat an incomplete result's
    unset fields as "unknown bike" -- they mean "not yet derivable from
    this advertisement".

    ``ble_profile`` and ``tcx_generation`` are two independent axes:

    - ``ble_profile`` is which GATT UUID family the bike speaks (mirrors
      :func:`specialized_turbo.protocol.detect_generation`'s return type).
      It is set precisely (``BLEProfile.TCU1``/``BLEProfile.TCX``) whenever
      ``complete`` is ``True``. When ``complete`` is ``False``, it is
      instead a *coarse best-effort hint* from the existing, more
      permissive ``detect_generation`` heuristic -- so it can be non-
      ``None`` even when ``is_bike`` is ``False`` (e.g. an advertisement
      whose only signal is the Apple iBeacon ``TURBOHMI2017`` magic).
      ``is_bike`` itself is never inferred from this hint; production
      *discovery* should keep using ``detect_generation``/
      ``is_specialized_advertisement`` directly, not this field.
    - ``tcx_generation`` is the fine-grained TCX2/TCX3/TCX4 identification
      generation, set **only** for a complete Nordic 10-byte record whose
      looked-up ``hmi_type`` is one of TCU2/TCDw2 (TCX2), T3/H3 (TCX3), or
      C4/T4 (TCX4). It is ``None`` for TCU1-profile bikes, for any other
      (including unknown or legacy TCU1/TCDw-family) Nordic hardware, and
      whenever ``complete`` is ``False``. A Nordic record with unrecognized
      HMI hardware therefore still reports ``ble_profile=BLEProfile.TCX``
      -- it is unambiguously a Nordic/TCX advertisement -- while
      ``tcx_generation`` stays ``None``.

    ``encryption_method`` is ``None`` whenever ``complete`` is ``False`` --
    "unknown" must never be confused with "no encryption". It is only ever
    :attr:`ProtocolEncryptionMethod.NONE` for a complete TCU1 record, or
    :attr:`ProtocolEncryptionMethod.AES_CTR` for a complete Nordic 10-byte
    record (hardcoded for every such record, matching the native
    implementation).
    """

    name: str
    bike_name: str
    is_bike: bool
    complete: bool
    hmi_serial: str | None = None
    hmi_hardware_version: str | None = None
    hmi_type: HmiType | None = None
    ble_profile: BLEProfile | None = None
    tcx_generation: TCXGeneration | None = None
    encryption_method: ProtocolEncryptionMethod | None = None
    bike_type: BikeType | None = None
    system_state: BikeSystemState | None = None


def parse_bike_info(name: str, manufacturer_data: dict[int, bytes]) -> BikeInfo:
    """Parse a BLE advertisement (name + manufacturer data) into a ``BikeInfo``.

    - Simplo (``0x020D``) advertisements (with no Nordic entry) yield a
      complete TCU1 record: ``hmi_type=HmiType.TCU1``,
      ``ble_profile=BLEProfile.TCU1``, ``tcx_generation=None``,
      ``encryption_method=ProtocolEncryptionMethod.NONE``.
    - A Nordic (``0x0059``) entry with an exactly-10-byte payload yields a
      complete TCX record: HMI serial/hardware version, bike type, system
      state, ``hmi_type`` (looked up from the hardware-version string,
      falling back to :attr:`HmiType.UNKNOWN` for unrecognized hardware),
      ``ble_profile=BLEProfile.TCX`` (always, regardless of ``hmi_type``),
      ``tcx_generation`` set only for a TCX2/TCX3/TCX4 ``hmi_type`` (``None``
      otherwise), and ``encryption_method=ProtocolEncryptionMethod.AES_CTR``
      (hardcoded for every such record, matching the native implementation).
    - Any other advertisement recognized as a bike (by name, Simplo
      presence, or a non-10-byte Nordic ``TURBOHMI2017`` payload -- this
      includes advertisements where only the Apple iBeacon frame carries
      discovery magic) yields an incomplete, name-only result:
      ``is_bike=True``, ``complete=False``, ``encryption_method=None``,
      ``tcx_generation=None``, and a best-effort ``ble_profile`` from the
      existing ``detect_generation`` heuristic (``None`` if it can't
      determine one either).
    - Anything else yields ``is_bike=False``, ``complete=False``, with the
      same best-effort ``ble_profile`` handling as above -- ``is_bike``
      being ``False`` does not imply ``ble_profile`` is ``None``.

    Unrecognized ``bike_type``/``system_state`` byte values are reported as
    ``None`` (there is no verified "unknown" member for those enums); an
    unrecognized HMI hardware version is reported as
    :attr:`HmiType.UNKNOWN` (the native enum's own definition for this
    case). No exception is raised for malformed/short/non-ASCII input --
    the native parser degrades the same way.
    """
    if not _is_bike(name, manufacturer_data):
        return BikeInfo(
            name=name,
            bike_name=name,
            is_bike=False,
            complete=False,
            ble_profile=detect_generation(manufacturer_data),
        )

    if (
        SIMPLO_COMPANY_ID in manufacturer_data
        and NORDIC_COMPANY_ID not in manufacturer_data
    ):
        payload = manufacturer_data[SIMPLO_COMPANY_ID]
        model = _TCU1_MODEL_NAMES.get(payload[0], "") if payload else ""
        bike_name = f"{model} {name}".strip()
        return BikeInfo(
            name=name,
            bike_name=bike_name,
            is_bike=True,
            complete=True,
            hmi_type=HmiType.TCU1,
            ble_profile=BLEProfile.TCU1,
            tcx_generation=None,
            encryption_method=ProtocolEncryptionMethod.NONE,
        )

    nordic = manufacturer_data.get(NORDIC_COMPANY_ID)
    if nordic is not None and len(nordic) == 10:
        hmi_serial = str(int.from_bytes(nordic[0:4], "little"))
        hmi_hw = _hmi_hw_string(nordic[4:7])
        hmi_type = _hmi_type_for_hw(hmi_hw)
        bike_type_value = nordic[8]
        system_state_value = nordic[9]
        try:
            bike_type = BikeType(bike_type_value)
        except ValueError:
            bike_type = None
        try:
            system_state = BikeSystemState(system_state_value)
        except ValueError:
            system_state = None
        bike_type_label = _BIKE_TYPE_NAMES.get(bike_type_value, f"?{bike_type_value}")
        return BikeInfo(
            name=name,
            bike_name=f"{bike_type_label} {name}",
            is_bike=True,
            complete=True,
            hmi_serial=hmi_serial,
            hmi_hardware_version=hmi_hw,
            hmi_type=hmi_type,
            ble_profile=BLEProfile.TCX,
            tcx_generation=_tcx_generation_for_hmi_type(hmi_type),
            encryption_method=ProtocolEncryptionMethod.AES_CTR,
            bike_type=bike_type,
            system_state=system_state,
        )

    # Detected (by name, Simplo presence, or Nordic TURBOHMI2017 magic) but
    # no structured 10-byte record available -- e.g. Apple-only
    # advertisements, or a Nordic payload that isn't exactly 10 bytes.
    # ble_profile is a best-effort hint from the existing, more permissive
    # detect_generation heuristic; encryption_method/tcx_generation stay
    # None (unknown, not "none").
    return BikeInfo(
        name=name,
        bike_name=name,
        is_bike=True,
        complete=False,
        ble_profile=detect_generation(manufacturer_data),
    )
