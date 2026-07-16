"""
Unit tests for wire_profiles.py -- generation/revision-aware BikeParameter to
TCX wire-ID mapping.

Known-vector wire IDs are cross-checked against the vendored extraction
artifacts and against ``docs/protocol.md`` / the identification handshake
(``SYSTEM_GET_NEW_VI`` -> ``SYSTEM_HMI_PROTOCOL_VERSION`` -> full protocol).
"""

import pytest

from specialized_turbo.parameters import BikeParameter
from specialized_turbo.wire_profiles import (
    IdentificationProtocol,
    ProtocolRevision,
    TCXGeneration,
    UnmappedParameterError,
    UnsupportedRevisionError,
    WireDatatype,
    bike_parameter_for_identification_wire_id,
    bike_parameter_for_wire_id,
    get_wire_datatype,
    identification_parameters,
    identification_wire_id_for,
    known_revisions,
    wire_id_for,
)

# SYSTEM_HMI_HW_INFO and SYSTEM_HMI_SW_VERSION are genuine identification-map
# parameters (present in `IDENTIFICATION_WIRE_IDS`) that were not part of the
# curated datatype extraction (`bikeparameter_datatypes.json` only documents
# the 7-step unknown-bike sequence from `identification_state_machine.md`, not
# every parameter the identification protocols expose). They are the only
# identification parameters without known datatype metadata today.
_IDENTIFICATION_PARAMS_WITHOUT_DATATYPE = frozenset(
    {
        BikeParameter.SYSTEM_HMI_HW_INFO,
        BikeParameter.SYSTEM_HMI_SW_VERSION,
    }
)


class TestKnownVectors:
    """Wire IDs required by spec, verified against the extraction artifacts."""

    def test_get_new_vi(self):
        assert (
            wire_id_for(BikeParameter.SYSTEM_GET_NEW_VI, TCXGeneration.TCX2) == 0x0A00
        )

    def test_get_new_vi_all_generations(self):
        for gen in TCXGeneration:
            assert wire_id_for(BikeParameter.SYSTEM_GET_NEW_VI, gen) == 0x0A00

    def test_protocol_version(self):
        assert (
            wire_id_for(BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION, TCXGeneration.TCX2)
            == 0x0A01
        )

    def test_soc(self):
        assert (
            wire_id_for(BikeParameter.BATTERY1_STATE_OF_CHARGE, TCXGeneration.TCX2)
            == 0x0500
        )

    def test_system_state(self):
        assert wire_id_for(BikeParameter.SYSTEM_STATE, TCXGeneration.TCX2) == 0x0801

    def test_real_time_enable(self):
        assert (
            wire_id_for(BikeParameter.SYSTEM_REAL_TIME_DATA_ENB, TCXGeneration.TCX2)
            == 0x080F
        )


class TestRevisionSpecificMotorType:
    """SYSTEM_MOTOR_TYPE's wire id varies by revision within a generation."""

    def test_ambiguous_without_revision(self):
        with pytest.raises(UnmappedParameterError):
            wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX2)

    def test_tcx2_rev_0x12(self):
        assert (
            wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX2, 0x12)
            == 0x08D2
        )

    def test_tcx2_rev_0x1d(self):
        assert (
            wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX2, 0x1D)
            == 0x08D1
        )

    def test_tcx3_rev_0x06(self):
        assert (
            wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX3, 0x06)
            == 0x08D1
        )

    def test_tcx4_rev_0x0a(self):
        assert (
            wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX4, 0x0A)
            == 0x08C4
        )

    def test_different_revisions_can_disagree(self):
        rev_12 = wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX2, 0x12)
        rev_1d = wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX2, 0x1D)
        assert rev_12 != rev_1d


class TestIdentificationWireIds:
    def test_get_new_vi_identification(self):
        assert identification_wire_id_for(BikeParameter.SYSTEM_GET_NEW_VI) == 0x0A00

    def test_protocol_version_identification(self):
        assert (
            identification_wire_id_for(BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION)
            == 0x0A01
        )

    def test_protocol_version_identification_base(self):
        assert (
            identification_wire_id_for(
                BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION, IdentificationProtocol.BASE
            )
            == 0x0224
        )

    def test_reverse_identification(self):
        assert (
            bike_parameter_for_identification_wire_id(0x0A00)
            == BikeParameter.SYSTEM_GET_NEW_VI
        )
        assert (
            bike_parameter_for_identification_wire_id(0x0A01)
            == BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION
        )

    def test_unmapped_identification_param(self):
        # SYSTEM_HMI_HW_VERSION is only present on the full protocol, not the
        # identification-phase map.
        with pytest.raises(UnmappedParameterError):
            identification_wire_id_for(BikeParameter.SYSTEM_HMI_HW_VERSION)


class TestReverseLookup:
    def test_reverse_soc(self):
        assert (
            bike_parameter_for_wire_id(0x0500, TCXGeneration.TCX2)
            == BikeParameter.BATTERY1_STATE_OF_CHARGE
        )

    def test_reverse_system_state(self):
        assert (
            bike_parameter_for_wire_id(0x0801, TCXGeneration.TCX2)
            == BikeParameter.SYSTEM_STATE
        )

    def test_reverse_motor_type_by_revision(self):
        assert (
            bike_parameter_for_wire_id(0x08D2, TCXGeneration.TCX2, 0x12)
            == BikeParameter.SYSTEM_MOTOR_TYPE
        )

    def test_round_trip_for_many_params(self):
        params = [
            BikeParameter.BATTERY1_STATE_OF_CHARGE,
            BikeParameter.BATTERY1_VOLTAGE_LEVEL,
            BikeParameter.MOTOR_BIKE_SPEED,
            BikeParameter.MOTOR_BIKE_CADENCE,
            BikeParameter.MOTOR_ODOMETER,
            BikeParameter.SYSTEM_STATE,
            BikeParameter.SYSTEM_REAL_TIME_DATA_ENB,
        ]
        for param in params:
            wire_id = wire_id_for(param, TCXGeneration.TCX2)
            assert bike_parameter_for_wire_id(wire_id, TCXGeneration.TCX2) == param

    def test_reverse_uniqueness_within_revision(self):
        """No two BikeParameters may share a wire id within one generation/revision."""
        seen: dict[int, BikeParameter] = {}
        for param in BikeParameter:
            try:
                wire_id = wire_id_for(param, TCXGeneration.TCX2, 0x12)
            except UnmappedParameterError:
                continue
            assert wire_id not in seen, (
                f"{param.name} and {seen[wire_id].name} both map to "
                f"0x{wire_id:04x} on TCX2 rev 0x12"
            )
            seen[wire_id] = param
        assert len(seen) > 50  # sanity: plenty of parameters were checked


class TestErrors:
    def test_unsupported_revision(self):
        with pytest.raises(UnsupportedRevisionError):
            wire_id_for(BikeParameter.SYSTEM_MOTOR_TYPE, TCXGeneration.TCX2, 0x99)

    def test_unsupported_revision_reverse(self):
        with pytest.raises(UnsupportedRevisionError):
            bike_parameter_for_wire_id(0x08D2, TCXGeneration.TCX2, 0x99)

    def test_unmapped_parameter(self):
        with pytest.raises(UnmappedParameterError):
            wire_id_for(BikeParameter.SYSTEM_STATUS, TCXGeneration.TCX2)

    def test_unmapped_parameter_all_generations(self):
        for gen in TCXGeneration:
            with pytest.raises(UnmappedParameterError):
                wire_id_for(BikeParameter.SYSTEM_STATUS, gen)

    def test_unmapped_wire_id_reverse(self):
        with pytest.raises(UnmappedParameterError):
            bike_parameter_for_wire_id(0xFFFF, TCXGeneration.TCX2)

    def test_protocol_revision_rejects_unknown_revision(self):
        with pytest.raises(UnsupportedRevisionError):
            ProtocolRevision(generation=TCXGeneration.TCX2, revision=0x99)

    def test_protocol_revision_accepts_known_revision(self):
        rev = ProtocolRevision(generation=TCXGeneration.TCX2, revision=0x12)
        assert rev.revision == 0x12


class TestKnownRevisions:
    def test_tcx2_known_revisions_nonempty(self):
        revisions = known_revisions(TCXGeneration.TCX2)
        assert 0x12 in revisions
        assert 0x34 in revisions

    def test_tcx4_known_revisions(self):
        revisions = known_revisions(TCXGeneration.TCX4)
        assert 0x01 in revisions
        assert 0x0A in revisions

    def test_revisions_differ_by_generation(self):
        assert known_revisions(TCXGeneration.TCX2) != known_revisions(
            TCXGeneration.TCX4
        )


class TestDatatypes:
    def test_soc_datatype(self):
        info = get_wire_datatype(BikeParameter.BATTERY1_STATE_OF_CHARGE)
        assert info is not None
        assert info.datatype == WireDatatype.INT
        assert info.length_bytes == 1

    def test_voltage_is_float(self):
        info = get_wire_datatype(BikeParameter.BATTERY1_VOLTAGE_LEVEL)
        assert info is not None
        assert info.datatype == WireDatatype.FLOAT

    def test_firmware_datatype(self):
        info = get_wire_datatype(BikeParameter.BATTERY1_FIRMWARE)
        assert info is not None
        assert info.datatype == WireDatatype.FIRMWARE_VERSION
        assert info.length_bytes == 3

    def test_system_state_datatype(self):
        info = get_wire_datatype(BikeParameter.SYSTEM_STATE)
        assert info is not None
        assert info.datatype == WireDatatype.SYSTEM_STATE

    def test_bike_type_datatype(self):
        info = get_wire_datatype(BikeParameter.SYSTEM_BIKE_TYPE)
        assert info is not None
        assert info.datatype == WireDatatype.BIKE_TYPE

    def test_string_datatype(self):
        info = get_wire_datatype(BikeParameter.SYSTEM_HMI_HW_VERSION)
        assert info is not None
        assert info.datatype == WireDatatype.STRING

    def test_bool_datatype(self):
        info = get_wire_datatype(BikeParameter.BATTERY1_CHARGING_ACTIVE)
        assert info is not None
        assert info.datatype == WireDatatype.BOOL

    def test_all_identification_params_have_datatype_or_documented_exception(self):
        """Every identification-map parameter has datatype metadata, except a
        documented, explicitly tested set of bespoke exceptions."""
        params = identification_parameters()
        assert len(params) == 8, (
            f"Expected 8 identification-map parameters, found {len(params)}: "
            f"{sorted(p.name for p in params)}"
        )
        for param in params:
            if param in _IDENTIFICATION_PARAMS_WITHOUT_DATATYPE:
                continue
            assert get_wire_datatype(param) is not None, (
                f"{param.name} is missing datatype metadata"
            )

    def test_documented_datatype_exceptions_are_actually_missing(self):
        """Guards the exception list above against silently going stale."""
        for param in _IDENTIFICATION_PARAMS_WITHOUT_DATATYPE:
            assert param in identification_parameters()
            assert get_wire_datatype(param) is None, (
                f"{param.name} now has datatype metadata -- remove it from "
                "_IDENTIFICATION_PARAMS_WITHOUT_DATATYPE"
            )

    def test_unknown_param_returns_none(self):
        assert get_wire_datatype(BikeParameter.SYSTEM_STATUS) is None


class TestParamVsWireIdDistinction:
    """BikeParameter (app id) and the wire command id are different spaces."""

    def test_app_id_differs_from_wire_id(self):
        param = BikeParameter.SYSTEM_STATE
        wire_id = wire_id_for(param, TCXGeneration.TCX2)
        assert int(param) == 363
        assert wire_id == 0x0801
        assert int(param) != wire_id

    def test_wire_id_for_returns_plain_int(self):
        wire_id = wire_id_for(BikeParameter.SYSTEM_GET_NEW_VI, TCXGeneration.TCX2)
        assert isinstance(wire_id, int)
        assert not isinstance(wire_id, BikeParameter)
