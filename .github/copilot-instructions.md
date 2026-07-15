# Copilot Instructions -- specialized-turbo

## Project overview

Python library for reading and writing telemetry from Specialized Turbo e-bikes over Bluetooth Low Energy. Supports four protocol generations (TCU1, TCX2, TCX3, TCX4). Async throughout, built on [bleak](https://github.com/hbldh/bleak). Protocol reference in `docs/protocol.md`.

## Architecture

```
protocol.py     Stateless protocol layer: UUIDs, enums, field definitions, parse_message()
parameters.py   BikeParameter enum (352 IDs) and TCX field definitions for TCX2+ protocol
framing.py      CRC-16/CCITT-FALSE framing for TCX2+ 20-byte packets
encryption.py   AES-128-CTR encryption/decryption and key derivation for TCX2+
session.py      ProtocolSession ABC with TCU1Session (passthrough) and TCXSession (CRC + encryption)
models.py       Mutable dataclass state containers (BatteryState, MotorState, BikeSettings, TelemetrySnapshot)
transport.py    TCX write-without-response + notification correlation and raw packet tracing
connection.py   BLE lifecycle: connect, pair, identify, subscribe, query, write commands
telemetry.py    High-level TelemetryMonitor wiring notifications into a TelemetrySnapshot
cli.py          CLI: scan, telemetry, read, write, services, capture
```

Data flow: BLE bytes -> `session.unpack()` -> `parse_message()` -> `ParsedMessage` -> `TelemetrySnapshot.update_from_message()` -> sub-model `update()`.

TCU1 uses `[sender][channel][data]` messages. TCX2+ uses `[param_id_be][data][zero-pad] + [CRC-16 LE]` = 20 bytes, optionally AES-128-CTR encrypted.

## Protocol generations

- **TCU1**: bare `[sender][channel][data]`, no CRC, no encryption. `BLEProfile.TCU1`.
- **TCX2/TCX3/TCX4**: 2-byte big-endian parameter ID + CRC-16 + optional AES-128-CTR. `BLEProfile.TCX`. All three share the same wire format; they differ in which `BikeParameter` IDs the bike supports.

`BLEProfile(StrEnum)` with values `TCU1="tcu1"` and `TCX="tcx"` controls UUID selection. GATT UUIDs use the TURBOHMI base (`000000xx-3731-3032-494d-484f42525554`) for TCX and GIGATRONIK base for TCU1.

## Key conventions

- `from __future__ import annotations` in every module. PEP 604 unions (`X | None`).
- Enums use `IntEnum` (protocol bytes). `BikeParameter(IntEnum)` for TCX2+ parameter IDs.
- `ParsedMessage` is a `NamedTuple`. `FieldDefinition` and `TCXFieldDefinition` are frozen slotted dataclasses.
- State models are mutable dataclasses. All fields default to `None`; `as_dict()` excludes `None`.
- `_CHANNEL_MAP` is a `ClassVar` dict mapping channel int -> attribute name. `update()` calls `setattr()`.
- Writable fields have `writable=True` and an `encode` function (inverse of `convert`).
- `pin` parameter is `str | None` (preserves leading zeros in 6-digit PINs).
- CRC-16 uses `binascii.crc_hqx(data, 0xFFFF)` (stdlib, no extra deps).
- AES-128-CTR uses `cryptography` package.
- mypy strict. PEP 561 typed (`py.typed` marker).
- Public API via `__init__.py` with `X as X` re-export idiom and `__all__`.

## Adding a TCU1 field

1. Add the channel to the `IntEnum` in `protocol.py`.
2. Register with `_reg(sender, channel, name, unit, size, convert, writable=..., encode=...)`.
3. Battery channels on sender 0x00 are auto-duplicated for sender 0x04.
4. Add the attribute to the matching dataclass in `models.py` + `_CHANNEL_MAP` + `as_dict()`.
5. Re-export in `__init__.py` if it's a new public type.
6. Add parse tests with hex vectors. Update `test_all_field_defs_count`.

## Adding a TCX field

1. Add to `BikeParameter` enum in `parameters.py` if not already there.
2. Register with `_tcx(param, name, unit, size, convert, writable=..., encode=...)`.
3. Add tests in `tests/test_parameters.py`.

## Development

```bash
uv sync --extra dev
uv run pytest
```

Build: hatchling. Python >= 3.11. Runtime deps: `bleak>=0.21.0`, `cryptography>=41.0.0`.

## Testing

Tests in `tests/`, organized as classes. Self-contained (no conftest). Use `pytest.approx()` for floats. Hex test vectors with inline comments. No BLE hardware needed. Regression guard: `test_all_field_defs_count`.

## CLI

Entry point: `specialized-turbo` -> `specialized_turbo.cli:main`. Subcommands: `scan`, `telemetry`, `read`, `write`, `services`, `capture`. `_FIELD_NAME_MAP` maps field names to `(sender, channel)` for read. `_WRITABLE_FIELD_MAP` for write.
