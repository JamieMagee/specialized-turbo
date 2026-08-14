#!/usr/bin/env python3
"""
Generate ``specialized_turbo/_wire_map_data.py`` from the raw wire-map
extraction artifacts (not included in this repository).

The raw artifacts are produced by reverse-engineering
``libturbo-core.so`` from the Specialized Mission Control Android app
(see ``README_wire_map.md`` in the extraction bundle for methodology).
This script distills them into a compact table containing only the
``BikeParameter`` values already defined in :mod:`specialized_turbo.parameters`,
keeping the checked-in package small while preserving full generation/
revision fidelity for every parameter that has a known wire mapping.

Usage::

    python scripts/generate_wire_profiles.py \\
        --wire-map /path/to/bikeparameter_wire_map.json \\
        --datatypes /path/to/bikeparameter_datatypes.json \\
        [--source-label "Specialized Mission Control app v1.66.0"]

Regenerate whenever a newer extraction bundle becomes available, then
run ``uvx ruff format .`` on the output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specialized_turbo.parameters import BikeParameter

_REVISION_RE = re.compile(r"^ProtocolRx([0-9A-F]{2})(TCX[234])$")

_GENERATION_NUMBER = {"TCX2": 2, "TCX3": 3, "TCX4": 4}

_IDENT_PROTOCOL_KEYS = {
    "ProtocolIdentificationTCX2": "ident_tcx2",
    "ProtocolIdentification": "ident_base",
}


def _generation_revisions(protocols: dict[str, Any]) -> dict[str, list[str]]:
    """Group protocol labels (e.g. ``ProtocolRx12TCX2``) by generation."""
    revisions: dict[str, list[str]] = {"TCX2": [], "TCX3": [], "TCX4": []}
    for label in protocols:
        m = _REVISION_RE.match(label)
        if m:
            revisions[m.group(2)].append(label)
    return revisions


def _revision_byte(label: str) -> int:
    m = _REVISION_RE.match(label)
    assert m is not None
    return int(m.group(1), 16)


def build_tables(
    wire_map: dict[str, Any], known_param_values: set[int]
) -> tuple[
    dict[int, dict[int, int]],
    dict[int, dict[tuple[int, int], int]],
    dict[int, dict[str, int]],
    dict[int, tuple[int, ...]],
]:
    """Build the generation-default, revision-override, and identification tables.

    Only ``BikeParameter`` values already present in ``known_param_values`` are
    considered, since unmapped values are not addressable through the app-level
    enum today.
    """
    gen_revisions = _generation_revisions(wire_map["protocols"])
    known_revisions = {
        _GENERATION_NUMBER[gen]: tuple(sorted(_revision_byte(r) for r in revs))
        for gen, revs in gen_revisions.items()
    }

    generation_defaults: dict[int, dict[int, int]] = {}
    revision_overrides: dict[int, dict[tuple[int, int], int]] = {}
    identification: dict[int, dict[str, int]] = {}

    for param in wire_map["parameters"]:
        value = param["value"]
        if value not in known_param_values:
            continue

        wire_ids: dict[str, str] = param["wire_ids"]

        # Identification-phase wire ids (ProtocolIdentificationTCX2 / ProtocolIdentification).
        ident_entry: dict[str, int] = {}
        for label, key in _IDENT_PROTOCOL_KEYS.items():
            if label in wire_ids:
                ident_entry[key] = int(wire_ids[label], 16)
        if ident_entry:
            identification[value] = ident_entry

        # Full-protocol wire ids, per generation.
        for gen, gen_num in _GENERATION_NUMBER.items():
            revs = gen_revisions[gen]
            present = {r: int(wire_ids[r], 16) for r in revs if r in wire_ids}
            if not present:
                continue
            distinct = set(present.values())
            if len(present) == len(revs) and len(distinct) == 1:
                # Every known revision of this generation agrees -- safe default.
                generation_defaults.setdefault(value, {})[gen_num] = distinct.pop()
            else:
                # Partial coverage or disagreement across revisions -- record
                # each revision explicitly so lookups without a matching
                # revision correctly fail instead of guessing.
                overrides = revision_overrides.setdefault(value, {})
                for r, wire_id in present.items():
                    overrides[(gen_num, _revision_byte(r))] = wire_id

    return generation_defaults, revision_overrides, identification, known_revisions


def build_datatypes(
    datatypes_doc: dict[str, Any], known_param_values: set[int]
) -> dict[int, tuple[str, int, int]]:
    """Build the BikeParameter -> (datatype, length_bytes, group_id) table."""
    out: dict[int, tuple[str, int, int]] = {}
    for section in ("identification_steps", "python_telemetry_fields"):
        for field in datatypes_doc[section]:
            value = field["value"]
            if value not in known_param_values:
                continue
            out[value] = (
                field["datatype"],
                field["length_bytes"],
                int(field["groupId"], 16),
            )
    return out


def _format_hex(n: int) -> str:
    """Format a 16-bit wire id / group id as a 4-digit hex literal."""
    return f"0x{n:04x}"


def _format_byte(n: int) -> str:
    """Format an 8-bit protocol revision code as a 2-digit hex literal."""
    return f"0x{n:02x}"


def render(
    generation_defaults: dict[int, dict[int, int]],
    revision_overrides: dict[int, dict[tuple[int, int], int]],
    identification: dict[int, dict[str, int]],
    known_revisions: dict[int, tuple[int, ...]],
    datatypes: dict[int, tuple[str, int, int]],
    source_label: str,
) -> str:
    lines: list[str] = []
    lines.append('"""')
    lines.append("Generated TCX wire-ID and datatype mapping data.")
    lines.append("")
    lines.append("DO NOT EDIT BY HAND.  Regenerate with:")
    lines.append("")
    lines.append("    python scripts/generate_wire_profiles.py \\")
    lines.append("        --wire-map <bikeparameter_wire_map.json> \\")
    lines.append("        --datatypes <bikeparameter_datatypes.json>")
    lines.append("")
    lines.append(f"Source: {source_label}, `libturbo-core.so` (TurboConnectCore, C++,")
    lines.append(
        "clang-19, arm64-v8a, full DWARF). Wire ids were extracted by disassembling"
    )
    lines.append(
        "each `ProtocolXxx` constructor's `ParameterInfo::ParameterInfo(...)` calls"
    )
    lines.append(
        "and reading the 16-bit id written immediately after each call. Validated:"
    )
    lines.append("within every protocol all wire ids are unique; spot values match the")
    lines.append("official-app HCI trace (e.g. SYSTEM_GET_NEW_VI=0x0a00).")
    lines.append("")
    lines.append("Only `BikeParameter` values already defined in `parameters.py` are")
    lines.append(
        "included. See `specialized_turbo.wire_profiles` for the public API that"
    )
    lines.append("reads this data.")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")

    lines.append(
        "# BikeParameter value -> known revision bytes, per TCXGeneration (2/3/4)."
    )
    lines.append("KNOWN_REVISIONS: dict[int, tuple[int, ...]] = {")
    for gen in sorted(known_revisions):
        revs = ", ".join(_format_byte(r) for r in known_revisions[gen])
        lines.append(f"    {gen}: ({revs}),")
    lines.append("}")
    lines.append("")

    lines.append(
        "# BikeParameter value -> {generation: wire id}, for generations where every"
    )
    lines.append("# known protocol revision agrees on the same wire id.")
    lines.append("GENERATION_DEFAULTS: dict[int, dict[int, int]] = {")
    for value in sorted(generation_defaults):
        gens = generation_defaults[value]
        gens_str = ", ".join(f"{g}: {_format_hex(gens[g])}" for g in sorted(gens))
        lines.append(f"    {value}: {{{gens_str}}},")
    lines.append("}")
    lines.append("")

    lines.append(
        "# BikeParameter value -> {(generation, revision): wire id}, for revisions"
    )
    lines.append(
        "# whose wire id differs from other revisions of the same generation, or"
    )
    lines.append(
        "# where the parameter is only present on some revisions of that generation."
    )
    lines.append("REVISION_OVERRIDES: dict[int, dict[tuple[int, int], int]] = {")
    for value in sorted(revision_overrides):
        entries = revision_overrides[value]
        lines.append(f"    {value}: {{")
        for gen, rev in sorted(entries):
            wire_id = entries[(gen, rev)]
            lines.append(
                f"        ({gen}, {_format_byte(rev)}): {_format_hex(wire_id)},"
            )
        lines.append("    },")
    lines.append("}")
    lines.append("")

    lines.append(
        "# BikeParameter value -> {identification protocol key: wire id}. Keys match"
    )
    lines.append("# `IdentificationProtocol.value` (ident_tcx2 / ident_base).")
    lines.append("IDENTIFICATION_WIRE_IDS: dict[int, dict[str, int]] = {")
    for value in sorted(identification):
        entries = identification[value]
        entries_str = ", ".join(
            f'"{k}": {_format_hex(entries[k])}' for k in sorted(entries)
        )
        lines.append(f"    {value}: {{{entries_str}}},")
    lines.append("}")
    lines.append("")

    lines.append(
        "# BikeParameter value -> (datatype name, length in bytes, wire group id)."
    )
    lines.append("DATATYPES: dict[int, tuple[str, int, int]] = {")
    for value in sorted(datatypes):
        dt, length, group = datatypes[value]
        lines.append(f'    {value}: ("{dt}", {length}, {_format_hex(group)}),')
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wire-map", type=Path, required=True)
    parser.add_argument("--datatypes", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "specialized_turbo" / "_wire_map_data.py",
    )
    parser.add_argument(
        "--source-label",
        default="Specialized Mission Control app v1.66.0",
    )
    args = parser.parse_args()

    wire_map = json.loads(args.wire_map.read_text())
    datatypes_doc = json.loads(args.datatypes.read_text())
    known_param_values = {int(p) for p in BikeParameter}

    generation_defaults, revision_overrides, identification, known_revisions = (
        build_tables(wire_map, known_param_values)
    )
    datatypes = build_datatypes(datatypes_doc, known_param_values)

    rendered = render(
        generation_defaults,
        revision_overrides,
        identification,
        known_revisions,
        datatypes,
        args.source_label,
    )
    args.output.write_text(rendered)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
