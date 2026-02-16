# Copilot Instructions — specialized-turbo

## Project overview

Python library for reading telemetry from Specialized Turbo e-bikes (Vado, Levo, Creo) over Bluetooth Low Energy. Implements the Gen 2 "TURBOHMI2017" protocol reverse-engineered from [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble). Async throughout, built on [bleak](https://github.com/hbldh/bleak).

## Architecture

Four-layer design — each module has a single responsibility:

1. **`protocol.py`** — Stateless protocol layer. UUIDs, enums (`Sender`, `BatteryChannel`, `MotorChannel`, `BikeSettingsChannel`), field definitions with conversion functions, and `parse_message()`. All fields are registered at module load via `_reg()` into a `_FIELD_DEFS` dict keyed by `(sender, channel)` tuples.
2. **`models.py`** — Mutable dataclass state containers (`BatteryState`, `MotorState`, `BikeSettings`, `TelemetrySnapshot`). Each sub-model has a `_CHANNEL_MAP` that routes channel IDs to attribute names. `TelemetrySnapshot.update_from_message()` dispatches by sender.
3. **`connection.py`** — BLE transport via bleak. `SpecializedConnection` is an async context manager handling connect, pair (passkey), subscribe notifications, and request-read queries. `scan_for_bikes()` filters by `TURBOHMI` manufacturer data.
4. **`telemetry.py`** — High-level `TelemetryMonitor` that wires connection notifications into a `TelemetrySnapshot`. Supports three consumption patterns: direct snapshot reads, `on_update` callback, and `async for msg in monitor.stream()`.

**Data flow:** BLE bytes → `parse_message()` → `ParsedMessage` (NamedTuple) → `TelemetrySnapshot.update_from_message()` → sub-model `update()`.

## Key conventions

- **`from __future__ import annotations`** in every module — use PEP 604 union syntax (`X | None`) everywhere.
- **Enums use `IntEnum`** so they double as ints in protocol bytes. `AssistLevel`, `Sender`, `BatteryChannel`, etc.
- **`ParsedMessage` is a `NamedTuple`**, not a dataclass — keep it immutable.
- **State models are mutable dataclasses** with `field(default_factory=...)` for the `_CHANNEL_MAP`. All fields default to `None`; `as_dict()` excludes `None` values.
- **Channel routing pattern:** each sub-model's `_CHANNEL_MAP` maps channel int → attribute name string; `update()` calls `setattr()`. Follow this pattern when adding new fields.
- **Hex test vectors** from the protocol spec drive all parser tests. Format: `bytes.fromhex("000c34")`. Always include the expected raw value and converted value.

## Adding a new telemetry field

1. Add the channel to the appropriate `IntEnum` in `protocol.py` (e.g., `MotorChannel`).
2. Register with `_reg(sender, channel, name, unit, data_size, convert)` in `protocol.py`.
3. Add the attribute (typed `X | None = None`) to the matching dataclass in `models.py`.
4. Add the channel → attribute mapping in that model's `_CHANNEL_MAP`.
5. Include the attribute in `as_dict()`.
6. Add parse tests in `tests/test_protocol.py` using hex test vectors from the protocol spec.
7. Add model routing tests in `tests/test_models.py`.

## BLE protocol essentials

- Messages are `[sender: 1B] [channel: 1B] [data: 1-4B little-endian]`.
- UUIDs share base `000000xx-3731-3032-494d-484f42525554` (encodes "TURBOHMI2017" reversed).
- Three GATT patterns: notifications (passive telemetry on `CHAR_NOTIFY`), request-read (write query to `CHAR_REQUEST_WRITE`, read response from `CHAR_REQUEST_READ`), and write commands (`CHAR_WRITE`).
- Pairing requires a 6-digit PIN displayed on the bike's TCU. See `docs/protocol.md` for full reference.

## Development commands

```bash
uv sync --extra dev     # Install deps (uses uv, not pip)
uv run pytest           # Run tests (pytest-asyncio with asyncio_mode = "auto")
```

- Build system: **hatchling** (pyproject.toml, no setup.py).
- Python ≥ 3.10 required.
- Only runtime dependency: `bleak>=0.21.0`. Dev extras: `pytest`, `pytest-asyncio`.

## Testing patterns

- Tests are in `tests/`, organized as classes by component (`TestParseBattery`, `TestMotorState`, etc.).
- Use `pytest.approx()` for any floating-point conversions (cadence, speed, voltage, acceleration).
- Test unknown/edge cases: unknown senders return `field_name=None`, messages < 3 bytes raise `ValueError`.
- No BLE hardware needed — tests exercise `protocol.py` and `models.py` only (pure logic).

## CLI

Entry point: `specialized-turbo` → `specialized_turbo.cli:main`. Subcommands: `scan`, `telemetry`, `read`, `services`. Uses `argparse` (no click dependency yet). The `_FIELD_NAME_MAP` in `cli.py` maps human-readable field names to `(sender, channel)` tuples for the `read` subcommand.
