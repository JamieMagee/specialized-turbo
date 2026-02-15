# specialized-turbo

Read telemetry from Specialized Turbo e-bikes (Vado, Levo, Creo) over Bluetooth Low Energy. Speed, power, cadence, battery, motor temp, odometer, assist level -- all the data the Mission Control app sees, in Python.

Based on the Gen 2 "TURBOHMI2017" protocol, reverse-engineered by [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble).

Uses [bleak](https://github.com/hbldh/bleak) for BLE, async throughout. Includes a CLI. Full protocol docs in [docs/protocol.md](docs/protocol.md).

## Installation

```bash
pip install specialized-turbo
```

## Quick Start

### Python API

```python
import asyncio
from specialized_turbo import SpecializedConnection, TelemetryMonitor

async def main():
    async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin=946166) as conn:
        monitor = TelemetryMonitor(conn)
        await monitor.start()

        # Stream telemetry as it arrives
        async for msg in monitor.stream():
            print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

asyncio.run(main())
```

### Access the snapshot

Instead of streaming, you can just read the snapshot after collecting for a bit:

```python
async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin=946166) as conn:
    monitor = TelemetryMonitor(conn)
    await monitor.start()
    await asyncio.sleep(5)  # collect data

    snap = monitor.snapshot
    print(f"Speed: {snap.motor.speed_kmh} km/h")
    print(f"Battery: {snap.battery.charge_pct}%")
    print(f"Power: {snap.motor.rider_power_w} W (rider) + {snap.motor.motor_power_w} W (motor)")
    print(f"Cadence: {snap.motor.cadence_rpm} RPM")
    print(f"Assist: {snap.motor.assist_level}")
```

### Query a specific value

```python
from specialized_turbo import SpecializedConnection, Sender, BatteryChannel

async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin=946166) as conn:
    msg = await conn.request_value(Sender.BATTERY, BatteryChannel.CHARGE_PERCENT)
    print(f"Battery: {msg.converted_value}%")
```

## CLI

Scan for bikes:

```bash
specialized-turbo scan
specialized-turbo scan --timeout 15
```

Stream telemetry:

```bash
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166 --format json
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166 --duration 30
```

Read a single value:

```bash
specialized-turbo read list                                    # show available fields
specialized-turbo read battery_charge_percent DC:DD:BB:4A:D6:55 --pin 946166
specialized-turbo read speed DC:DD:BB:4A:D6:55 --pin 946166 --format json
```

Dump GATT services (for debugging):

```bash
specialized-turbo services DC:DD:BB:4A:D6:55 --pin 946166
```

## Available fields

| Field | Unit | Description |
| --- | --- | --- |
| `battery_capacity_wh` | Wh | Total battery capacity |
| `battery_remaining_wh` | Wh | Remaining energy |
| `battery_health` | % | Battery health |
| `battery_temp` | °C | Battery temperature |
| `battery_charge_cycles` | cycles | Number of charge cycles |
| `battery_voltage` | V | Battery voltage |
| `battery_current` | A | Battery current draw |
| `battery_charge_percent` | % | State of charge |
| `rider_power` | W | Rider pedal power |
| `cadence` | RPM | Pedaling cadence |
| `speed` | km/h | Current speed |
| `odometer` | km | Total distance |
| `assist_level` | — | OFF / ECO / TRAIL / TURBO |
| `motor_temp` | °C | Motor temperature |
| `motor_power` | W | Electric motor power |
| `wheel_circumference` | mm | Wheel circumference setting |
| `assist_lev1_pct` | % | ECO assist percentage |
| `assist_lev2_pct` | % | TRAIL assist percentage |
| `assist_lev3_pct` | % | TURBO assist percentage |
| `acceleration` | % | Acceleration sensitivity |

## Pairing

The bike needs a 6-digit PIN for BLE pairing, shown on its TCU screen. Pass it via `--pin` (CLI) or `pin=` (Python).

On Windows, bleak's WinRT backend can handle passkey pairing programmatically. If that doesn't work, pair through Windows Bluetooth Settings first, then connect without `--pin`.

## Protocol docs

See [docs/protocol.md](docs/protocol.md) for the full protocol reference: UUIDs, message format, field definitions with conversion formulas, authentication, and communication patterns.

## Development

```bash
uv sync --extra dev
uv run pytest
```

## License

MIT

## Credits

Protocol reverse-engineered by [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble) (C++/ESP32, MIT).
