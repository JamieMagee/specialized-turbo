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

- **`from __future__ import annotations`** in every source module — use PEP 604 union syntax (`X | None`) everywhere.
- **Enums use `IntEnum`** so they double as ints in protocol bytes. `AssistLevel`, `Sender`, `BatteryChannel`, etc.
- **`ParsedMessage` is a `NamedTuple`**, not a dataclass — keep it immutable.
- **`FieldDefinition` is a frozen, slotted dataclass** — stored in `_FIELD_DEFS`, created by `_reg()`.
- **State models are mutable dataclasses.** All fields default to `None`; `as_dict()` excludes `None` values. Enum-valued fields (e.g., `AssistLevel`) must convert to `.name` string in `as_dict()`.
- **`_CHANNEL_MAP` is a `ClassVar`** (class-level dict literal), not a per-instance field. Maps channel int → attribute name string; `update()` calls `setattr()`.
- **Hex test vectors** from the protocol spec drive all parser tests. Format: `bytes.fromhex("000c34")`. Always include the expected raw value and converted value.
- **mypy strict mode** — `[tool.mypy] strict = true`. All new code must pass strict type checking: explicit return types, no `Any` leaks.
- **PEP 561 typed package** — `py.typed` marker is present. Maintain type annotations in all modules.
- **Public API via `__init__.py`** — re-export with the `X as X` idiom and add to `__all__`. Version lives in `__version__` (read by hatch for builds).
- **Logging:** `logger = logging.getLogger(__name__)` at module top level. CLI configures output via `_setup_logging()`.
- **Error patterns:** `ValueError` for protocol violations, `RuntimeError` for connection state violations, silent `warning`-level logging for non-fatal notification parse failures.

## Adding a new telemetry field

1. Add the channel to the appropriate `IntEnum` in `protocol.py` (e.g., `MotorChannel`).
2. Register with `_reg(sender, channel, name, unit, data_size, convert)` in `protocol.py`. Note: battery channels on sender 0x00 are **auto-duplicated** for secondary battery (sender 0x04) — no manual duplication needed.
3. Add the attribute (typed `X | None = None`) to the matching dataclass in `models.py`.
4. Add the channel → attribute mapping in that model's `_CHANNEL_MAP`.
5. Include the attribute in `as_dict()`. If enum-valued, convert to `.name` string.
6. If it's a new public enum/type, re-export in `__init__.py` with `X as X` and add to `__all__`.
7. Add parse tests in `tests/test_protocol.py` using hex test vectors from the protocol spec.
8. Update the field count assertion in `TestFieldDefs.test_all_field_defs_count`.
9. Add model routing tests in `tests/test_models.py`.

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
- **Self-contained** — no `conftest.py` or shared fixtures. Each test creates its instances inline.
- Use `pytest.approx()` for any floating-point conversions (cadence, speed, voltage, acceleration).
- **Annotate test vectors** with inline comments showing raw→converted math.
- Test unknown/edge cases: unknown senders return `field_name=None`, messages < 3 bytes raise `ValueError`.
- **Regression guard:** `test_all_field_defs_count` asserts the total number of registered fields.
- No BLE hardware needed — tests exercise `protocol.py` and `models.py` only (pure logic).

## CLI

Entry point: `specialized-turbo` → `specialized_turbo.cli:main`. Subcommands: `scan`, `telemetry`, `read`, `services`. Uses `argparse` (no click dependency yet). The `_FIELD_NAME_MAP` in `cli.py` maps human-readable field names to `(sender, channel)` tuples for the `read` subcommand.
