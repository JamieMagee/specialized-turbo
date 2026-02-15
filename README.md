# specialized-turbo

Python library for communicating with **Specialized Turbo** e-bikes (Vado, Levo, Creo, etc.) over Bluetooth Low Energy.

Implements the Gen 2 "TURBOHMI2017" BLE protocol as reverse-engineered by [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble).

## Features

- **Scan** for nearby Specialized Turbo bikes
- **Connect** with BLE pairing (passkey/PIN support)
- **Stream** real-time telemetry: speed, power, cadence, battery, motor temp, odometer, assist level
- **Query** specific values on demand
- **CLI** for quick access from the terminal
- Fully **async** (built on [bleak](https://github.com/hbldh/bleak))
- Comprehensive **protocol documentation** in [docs/protocol.md](docs/protocol.md)

## Installation

```bash
pip install -e .
```

Or with CLI support:
```bash
pip install -e ".[cli]"
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

### Access the Snapshot

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

### Query a Specific Value

```python
from specialized_turbo import SpecializedConnection, Sender, BatteryChannel

async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin=946166) as conn:
    msg = await conn.request_value(Sender.BATTERY, BatteryChannel.CHARGE_PERCENT)
    print(f"Battery: {msg.converted_value}%")
```

## CLI Usage

### Scan for bikes

```bash
specialized-turbo scan
specialized-turbo scan --timeout 15
```

### Stream telemetry

```bash
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166 --format json
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166 --duration 30
```

### Read a specific value

```bash
specialized-turbo read list                                    # show available fields
specialized-turbo read battery_charge_percent DC:DD:BB:4A:D6:55 --pin 946166
specialized-turbo read speed DC:DD:BB:4A:D6:55 --pin 946166 --format json
```

### Debug: enumerate GATT services

```bash
specialized-turbo services DC:DD:BB:4A:D6:55 --pin 946166
```

## Available Telemetry Fields

| Field | Unit | Description |
|---|---|---|
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

The bike requires a **6-digit PIN** for BLE pairing, displayed on the bike's TCU (Turbo Connect Unit) screen. Pass it via `--pin` on the CLI or the `pin=` parameter in Python.

**On Windows:** bleak uses the WinRT backend which supports programmatic passkey pairing. If that fails, pair manually via Windows Bluetooth Settings first, then connect without the `--pin` flag.

## Protocol Documentation

See [docs/protocol.md](docs/protocol.md) for the complete reverse-engineered protocol reference, including:
- UUID structure and all service/characteristic definitions
- Message format and byte-level encoding
- All data fields with conversion formulas and example hex values
- Authentication flow
- Communication patterns (notifications, request-read, write commands)

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT

## Credits

Protocol reverse-engineered by [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble) (C++/ESP32, MIT license). This Python implementation is an independent port.
