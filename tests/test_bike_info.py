"""
Unit tests for bike_info.py -- BLE advertisement -> BikeInfo parsing.

Fixture vectors (including the real ``ha-specialized-turbo#9`` bike) are
transcribed from the verified ``advertisement_fixtures.json`` companion
artifact for the BLE advertisement -> BikeInfo report (reverse engineered
from ``libturbo-core.so``, Specialized app 1.66.0).
"""

import pytest

from specialized_turbo.bike_info import (
    BikeInfo,
    BikeSystemState,
    BikeType,
    HmiType,
    ProtocolEncryptionMethod,
    parse_bike_info,
)
from specialized_turbo.protocol import BLEProfile
from specialized_turbo.wire_profiles import TCXGeneration


def _mfr_data(raw: dict[str, str]) -> dict[int, bytes]:
    """Convert a fixture's {"<decimal company id>": "<hex payload>"} map."""
    return {
        int(company_id): bytes.fromhex(hex_payload)
        for company_id, hex_payload in raw.items()
    }


class TestIssue9RealVector:
    """ha-specialized-turbo#9 -- the real "Vado 3.0"/2022 bike dump.

    Confirms the bike remains classified TCX2/AES_CTR after splitting the
    old combined ``generation`` field into ``ble_profile``/``tcx_generation``.
    """

    NAME = "WSBC001057439S"
    MFR = _mfr_data(
        {
            "76": "0215545552424f484d4932303137010000005fe033060a",
            "89": "dac8c404423333330601",
        }
    )

    def test_parses_full_record(self):
        info = parse_bike_info(self.NAME, self.MFR)
        assert info.is_bike is True
        assert info.complete is True
        assert info.bike_name == "COMO2 WSBC001057439S"
        assert info.bike_type is BikeType.COMO2
        assert info.hmi_type is HmiType.TCDw2
        assert info.system_state is BikeSystemState.ON
        assert info.encryption_method is ProtocolEncryptionMethod.AES_CTR
        assert info.hmi_serial == "80005338"
        assert info.hmi_hardware_version == "B.3.3"
        assert info.ble_profile is BLEProfile.TCX
        assert info.tcx_generation is TCXGeneration.TCX2


# Each entry: (id, name, mfr_data, expected fields dict).
#
# All of these are complete Nordic (0x0059) records, so ble_profile is
# always BLEProfile.TCX -- regardless of hmi_type -- and tcx_generation is
# only set for a TCX2/TCX3/TCX4 hmi_type (None for the legacy TCU1/TCDw
# families and for UNKNOWN).
_SYNTHETIC_HMI_TYPE_VECTORS = [
    (
        "synthetic_TCU_A.1.0",
        "SPECIALIZED-TEST",
        {"89": "2a000001413130300101"},
        dict(
            bike_name="TURBO SPECIALIZED-TEST",
            bike_type=BikeType.TURBO,
            hmi_type=HmiType.TCU1,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="A.1.0",
            tcx_generation=None,
        ),
    ),
    (
        "synthetic_TCUArterytek_A.5.0",
        "SPECIALIZED-TEST",
        {"89": "2a000001413530300101"},
        dict(
            bike_name="TURBO SPECIALIZED-TEST",
            bike_type=BikeType.TURBO,
            hmi_type=HmiType.UNKNOWN,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="A.5.0",
            tcx_generation=None,
        ),
    ),
    (
        "synthetic_TCDw_A.2.0",
        "SPECIALIZED-TEST",
        {"89": "2a000001413230300201"},
        dict(
            bike_name="LEVO1 SPECIALIZED-TEST",
            bike_type=BikeType.LEVO1,
            hmi_type=HmiType.TCDw,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="A.2.0",
            tcx_generation=None,
        ),
    ),
    (
        "synthetic_TCU2_B.4.3",
        "SPECIALIZED-TEST",
        {"89": "2a000001423433330601"},
        dict(
            bike_name="COMO2 SPECIALIZED-TEST",
            bike_type=BikeType.COMO2,
            hmi_type=HmiType.TCU2,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="B.4.3",
            tcx_generation=TCXGeneration.TCX2,
        ),
    ),
    (
        "synthetic_TCDw2_B.3.2",
        "SPECIALIZED-TEST",
        {"89": "2a000001423332320601"},
        dict(
            bike_name="COMO2 SPECIALIZED-TEST",
            bike_type=BikeType.COMO2,
            hmi_type=HmiType.TCDw2,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="B.3.2",
            tcx_generation=TCXGeneration.TCX2,
        ),
    ),
    (
        "synthetic_T3_A.6.0",
        "SPECIALIZED-TEST",
        {"89": "2a000001413630300301"},
        dict(
            bike_name="VADO SPECIALIZED-TEST",
            bike_type=BikeType.VADO,
            hmi_type=HmiType.T3,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="A.6.0",
            tcx_generation=TCXGeneration.TCX3,
        ),
    ),
    (
        "synthetic_H3_A.8.1",
        "SPECIALIZED-TEST",
        {"89": "2a000001413831310301"},
        dict(
            bike_name="VADO SPECIALIZED-TEST",
            bike_type=BikeType.VADO,
            hmi_type=HmiType.H3,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="A.8.1",
            tcx_generation=TCXGeneration.TCX3,
        ),
    ),
    (
        "synthetic_C4_A.7.0",
        "SPECIALIZED-TEST",
        {"89": "2a000001413730300501"},
        dict(
            bike_name="LEVO2 SPECIALIZED-TEST",
            bike_type=BikeType.LEVO2,
            hmi_type=HmiType.C4,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="A.7.0",
            tcx_generation=TCXGeneration.TCX4,
        ),
    ),
    (
        "synthetic_T4_A.D.0",
        "SPECIALIZED-TEST",
        {"89": "2a000001414430300501"},
        dict(
            bike_name="LEVO2 SPECIALIZED-TEST",
            bike_type=BikeType.LEVO2,
            hmi_type=HmiType.T4,
            system_state=BikeSystemState.ON,
            hmi_serial="16777258",
            hmi_hardware_version="A.D.0",
            tcx_generation=TCXGeneration.TCX4,
        ),
    ),
]


class TestAllHmiTypes:
    """Every HmiType (incl. UNKNOWN via TCUArterytek) from the artifact fixtures."""

    @pytest.mark.parametrize(
        "vector_id,name,mfr_raw,expected",
        _SYNTHETIC_HMI_TYPE_VECTORS,
        ids=[v[0] for v in _SYNTHETIC_HMI_TYPE_VECTORS],
    )
    def test_synthetic_vector(self, vector_id, name, mfr_raw, expected):
        info = parse_bike_info(name, _mfr_data(mfr_raw))
        assert info.is_bike is True
        assert info.complete is True
        assert info.bike_name == expected["bike_name"]
        assert info.bike_type is expected["bike_type"]
        assert info.hmi_type is expected["hmi_type"]
        assert info.system_state is expected["system_state"]
        assert info.hmi_serial == expected["hmi_serial"]
        assert info.hmi_hardware_version == expected["hmi_hardware_version"]
        # Every complete Nordic record is unambiguously BLEProfile.TCX,
        # regardless of the looked-up hmi_type (even legacy TCU1/TCDw or
        # UNKNOWN hardware) -- it's the company ID, not the HMI hardware
        # family, that determines the BLE profile.
        assert info.ble_profile is BLEProfile.TCX
        assert info.tcx_generation == expected["tcx_generation"]
        assert info.encryption_method is ProtocolEncryptionMethod.AES_CTR

    def test_all_hmi_type_members_are_reachable(self):
        """Every HmiType member (except UNKNOWN, covered separately) appears
        in the synthetic vectors above -- guards against a member being
        added to the enum without a corresponding fixture."""
        covered = {v[3]["hmi_type"] for v in _SYNTHETIC_HMI_TYPE_VECTORS}
        assert covered == set(HmiType)

    def test_unknown_and_legacy_hardware_have_tcx_profile_but_no_generation(self):
        """Unknown or legacy (TCU1/TCDw-family) HMI hardware inside a
        Nordic record still yields ble_profile=TCX (it's unambiguously a
        Nordic advertisement) but tcx_generation stays None (there is no
        TCX2/3/4 generation for it)."""
        no_generation_ids = {
            "synthetic_TCU_A.1.0",
            "synthetic_TCUArterytek_A.5.0",
            "synthetic_TCDw_A.2.0",
        }
        for vector_id, name, mfr_raw, expected in _SYNTHETIC_HMI_TYPE_VECTORS:
            if vector_id not in no_generation_ids:
                continue
            info = parse_bike_info(name, _mfr_data(mfr_raw))
            assert info.ble_profile is BLEProfile.TCX, vector_id
            assert info.tcx_generation is None, vector_id


class TestTCU1:
    def test_tcu1_simplo_levo(self):
        info = parse_bike_info(
            "SPECIALIZED LEVO", _mfr_data({"525": "02000000000000000000"})
        )
        assert info.is_bike is True
        assert info.complete is True
        assert info.bike_name == "LEVO SPECIALIZED LEVO"
        assert info.hmi_type is HmiType.TCU1
        assert info.ble_profile is BLEProfile.TCU1
        assert info.tcx_generation is None
        assert info.encryption_method is ProtocolEncryptionMethod.NONE
        assert info.bike_type is None
        assert info.system_state is None
        assert info.hmi_serial is None
        assert info.hmi_hardware_version is None

    def test_tcu1_unknown_model_byte(self):
        """An unrecognized Simplo byte-0 model code degrades to an empty
        model name rather than raising."""
        info = parse_bike_info("SPECIALIZED BIKE", _mfr_data({"525": "ff"}))
        assert info.is_bike is True
        assert info.complete is True
        assert info.bike_name == "SPECIALIZED BIKE"
        assert info.hmi_type is HmiType.TCU1
        assert info.ble_profile is BLEProfile.TCU1
        assert info.encryption_method is ProtocolEncryptionMethod.NONE

    def test_tcu1_empty_payload(self):
        """An empty Simplo payload does not raise (no byte-0 to read)."""
        info = parse_bike_info("SPECIALIZED BIKE", _mfr_data({"525": ""}))
        assert info.is_bike is True
        assert info.complete is True
        assert info.bike_name == "SPECIALIZED BIKE"
        assert info.ble_profile is BLEProfile.TCU1
        assert info.tcx_generation is None
        assert info.encryption_method is ProtocolEncryptionMethod.NONE

    def test_nordic_present_takes_priority_over_simplo(self):
        """If both Simplo and a valid Nordic 10-byte record are present,
        the Nordic record wins (per the report: "if Nordic structured
        data is also present, use it")."""
        info = parse_bike_info(
            "WSBC001057439S",
            _mfr_data({"525": "02000000000000000000", "89": "dac8c404423333330601"}),
        )
        assert info.hmi_type is HmiType.TCDw2
        assert info.ble_profile is BLEProfile.TCX
        assert info.tcx_generation is TCXGeneration.TCX2
        assert info.encryption_method is ProtocolEncryptionMethod.AES_CTR


class TestNotABike:
    def test_not_a_bike(self):
        info = parse_bike_info("Some Headphones", _mfr_data({"76": "0215aabbccdd"}))
        assert info.is_bike is False
        assert info.complete is False
        assert info.bike_name == "Some Headphones"
        assert info.bike_type is None
        assert info.hmi_type is None
        assert info.system_state is None
        assert info.ble_profile is None
        assert info.tcx_generation is None
        # Incomplete: encryption method is unknown, never NONE.
        assert info.encryption_method is None

    def test_empty_advertisement(self):
        info = parse_bike_info("Random Device", {})
        assert info.is_bike is False
        assert info.complete is False
        assert info.ble_profile is None
        assert info.encryption_method is None

    def test_lowercase_specialized_name_is_not_detected(self):
        """isBike matches the literal uppercase "SPECIALIZED" byte
        sequence; the native scan is case-sensitive, so a differently
        cased name must not trigger name-based detection."""
        info = parse_bike_info("specialized-test", {})
        assert info.is_bike is False
        assert info.complete is False

    def test_mixed_case_specialized_name_is_not_detected(self):
        info = parse_bike_info("Specialized-Test", {})
        assert info.is_bike is False

    def test_name_shorter_than_specialized_is_not_detected(self):
        """A name shorter than len("SPECIALIZED") == 11 can never satisfy
        the substring check."""
        info = parse_bike_info("SPECIALIZE", {})
        assert info.is_bike is False


class TestAppleDiscoveryOnly:
    """Apple 0x004C is discovery-only; without Nordic structured data (or a
    "SPECIALIZED" name) no HMI/bike fields may be invented from it.

    ``is_bike`` stays strictly native-faithful (native ``isBike`` never
    reads company ``0x004C``), but ``ble_profile`` is still populated as a
    coarse hint via the existing, more permissive ``detect_generation``
    whenever it can determine one -- which it can here, since the Apple
    iBeacon frame does carry the ``TURBOHMI2017`` magic that
    ``detect_generation`` (unlike this module's ``is_bike``) checks for in
    *any* manufacturer-data payload. This is exactly why production
    discovery must keep using the existing
    ``detect_generation``/``is_specialized_advertisement`` superset rather
    than this module's ``is_bike``.
    """

    def test_apple_ibeacon_only_no_nordic(self):
        info = parse_bike_info(
            "WSBC000000000S",
            _mfr_data({"76": "0215545552424f484d4932303137010000005fe033060a"}),
        )
        assert info.is_bike is False
        assert info.complete is False
        assert info.bike_name == "WSBC000000000S"
        assert info.hmi_type is None
        assert info.bike_type is None
        assert info.hmi_serial is None
        assert info.hmi_hardware_version is None
        assert info.tcx_generation is None
        assert info.encryption_method is None
        # Coarse hint still available despite is_bike being False: the
        # existing detect_generation() superset does check Apple payloads
        # for the TURBOHMI2017 magic.
        assert info.ble_profile is BLEProfile.TCX

    def test_apple_ibeacon_with_specialized_name_is_incomplete(self):
        """Name-based detection still fires, but no structured Nordic
        record means the result stays incomplete (no invented fields)."""
        info = parse_bike_info(
            "SPECIALIZED-TEST",
            _mfr_data({"76": "0215545552424f484d4932303137010000005fe033060a"}),
        )
        assert info.is_bike is True
        assert info.complete is False
        assert info.bike_name == "SPECIALIZED-TEST"
        assert info.hmi_type is None
        assert info.bike_type is None
        assert info.tcx_generation is None
        assert info.encryption_method is None
        assert info.ble_profile is BLEProfile.TCX

    def test_apple_and_nordic_together_uses_nordic(self):
        """When Nordic structured data coexists with the Apple frame, the
        Nordic record is used (matches the real issue-#9 vector)."""
        info = parse_bike_info(
            "WSBC001057439S",
            _mfr_data(
                {
                    "76": "0215545552424f484d4932303137010000005fe033060a",
                    "89": "dac8c404423333330601",
                }
            ),
        )
        assert info.is_bike is True
        assert info.complete is True
        assert info.hmi_type is HmiType.TCDw2
        assert info.ble_profile is BLEProfile.TCX
        assert info.tcx_generation is TCXGeneration.TCX2
        assert info.encryption_method is ProtocolEncryptionMethod.AES_CTR


class TestMalformedNordicPayloads:
    def test_short_nordic_payload_is_incomplete_not_error(self):
        """A Nordic payload that's too short for the 10-byte record (and
        without the TURBOHMI2017 magic) yields no detection at all."""
        info = parse_bike_info("Random Device", _mfr_data({"89": "dac8c404"}))
        assert info.is_bike is False
        assert info.complete is False
        assert info.ble_profile is None
        assert info.encryption_method is None

    def test_short_nordic_payload_with_specialized_name(self):
        """Same short payload, but the name alone makes it a detected,
        incomplete bike -- fields are not guessed from a short payload."""
        info = parse_bike_info("SPECIALIZED-TEST", _mfr_data({"89": "dac8c404"}))
        assert info.is_bike is True
        assert info.complete is False
        assert info.hmi_type is None
        assert info.hmi_serial is None
        # detect_generation() also can't find the magic in this short,
        # non-conforming payload, so the coarse hint is unavailable too.
        assert info.ble_profile is None
        assert info.encryption_method is None

    def test_oversized_nordic_payload_with_magic(self):
        """>=12 bytes carrying TURBOHMI2017 is detected as a bike (isBike),
        but getBikeInfo only extracts fields from the exact 10-byte form,
        so the result stays incomplete -- though the coarse ble_profile
        hint from detect_generation is still available (same magic)."""
        payload = b"\x00" * 4 + b"TURBOHMI2017"
        info = parse_bike_info("WSBC999999999S", {0x0059: payload})
        assert info.is_bike is True
        assert info.complete is False
        assert info.hmi_type is None
        assert info.bike_type is None
        assert info.tcx_generation is None
        assert info.encryption_method is None
        assert info.ble_profile is BLEProfile.TCX

    def test_eleven_byte_nordic_payload_without_magic_is_undetected(self):
        payload = bytes(11)
        info = parse_bike_info("Random Device", {0x0059: payload})
        assert info.is_bike is False
        assert info.complete is False
        assert info.ble_profile is None

    def test_non_ascii_hardware_bytes_yield_unknown_hmi_type(self):
        """Non-ASCII HW-version bytes don't raise -- they simply never
        match a hardware-compatibility entry, exactly like the native
        parser, and fall through to HmiType.UNKNOWN. The record is still a
        complete Nordic parse (ble_profile=TCX, encryption_method=AES_CTR)
        -- only the fine-grained tcx_generation is unavailable."""
        # bytes[4:7] = 0xff,0xfe,0xfd (non-ASCII); bytes[8]=0x01 (TURBO),
        # bytes[9]=0x01 (ON). Not auto-detected by HW membership or name,
        # so route through the TURBOHMI2017-magic-detection path instead.
        payload = bytes.fromhex("dac8c404") + bytes(
            [0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x01]
        )
        assert len(payload) == 10
        info = parse_bike_info("SPECIALIZED-TEST", {0x0059: payload})
        assert info.is_bike is True
        assert info.complete is True
        assert info.hmi_type is HmiType.UNKNOWN
        assert info.hmi_hardware_version == f"{chr(0xFF)}.{chr(0xFE)}.{chr(0xFD)}"
        assert info.ble_profile is BLEProfile.TCX
        assert info.tcx_generation is None
        assert info.encryption_method is ProtocolEncryptionMethod.AES_CTR
        assert info.bike_type is BikeType.TURBO
        assert info.system_state is BikeSystemState.ON

    def test_unknown_bike_type_and_system_state_bytes(self):
        """Byte values with no defined BikeType/SystemState enum member
        degrade to None rather than raising, while the display name still
        falls back to a "?<value>" label (matching the native
        getBikeTypeAsString behavior for unrecognized values). ble_profile
        and tcx_generation are unaffected by unrelated unknown bytes."""
        # hw bytes 4:7 = "B.3.3" (TCDw2, a known-no-tcx1 HW string, so this
        # advertisement is detected as a bike purely by HW membership).
        payload = bytes.fromhex("dac8c404") + b"B33" + b"3" + bytes([0x63, 0x63])
        assert len(payload) == 10
        info = parse_bike_info("WSBC001057439S", {0x0059: payload})
        assert info.is_bike is True
        assert info.complete is True
        assert info.hmi_type is HmiType.TCDw2
        assert info.bike_type is None
        assert info.system_state is None
        assert info.bike_name == "?99 WSBC001057439S"
        assert info.ble_profile is BLEProfile.TCX
        assert info.tcx_generation is TCXGeneration.TCX2
        assert info.encryption_method is ProtocolEncryptionMethod.AES_CTR


class TestEncryptionMethodSemantics:
    """Regression tests: an incomplete/unknown result must never be
    mistaken for ProtocolEncryptionMethod.NONE. ``None`` means "we don't
    know"; ``ProtocolEncryptionMethod.NONE`` means "confirmed unencrypted"
    (only ever true for a complete TCU1 record)."""

    def test_not_a_bike_encryption_is_none_not_NONE(self):
        info = parse_bike_info("Some Headphones", {})
        assert info.encryption_method is None
        assert info.encryption_method is not ProtocolEncryptionMethod.NONE

    def test_incomplete_bike_encryption_is_none_not_NONE(self):
        info = parse_bike_info("SPECIALIZED-TEST", _mfr_data({"89": "dac8c404"}))
        assert info.complete is False
        assert info.encryption_method is None
        assert info.encryption_method is not ProtocolEncryptionMethod.NONE

    def test_complete_tcu1_encryption_is_explicit_NONE(self):
        info = parse_bike_info(
            "SPECIALIZED LEVO", _mfr_data({"525": "02000000000000000000"})
        )
        assert info.complete is True
        assert info.encryption_method is ProtocolEncryptionMethod.NONE
        assert info.encryption_method is not None

    def test_complete_nordic_encryption_is_explicit_aes_ctr(self):
        info = parse_bike_info(
            "SPECIALIZED-TEST", _mfr_data({"89": "2a000001423433330601"})
        )
        assert info.complete is True
        assert info.encryption_method is ProtocolEncryptionMethod.AES_CTR


class TestBikeInfoIsFrozen:
    def test_bike_info_is_immutable(self):
        info = parse_bike_info("Random Device", {})
        with pytest.raises(AttributeError):
            setattr(info, "is_bike", True)

    def test_bike_info_is_a_dataclass_instance(self):
        info = parse_bike_info("Random Device", {})
        assert isinstance(info, BikeInfo)
