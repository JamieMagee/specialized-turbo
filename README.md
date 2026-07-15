# specialized-turbo

Python library for talking to Specialized Turbo e-bikes (Vado, Levo, Creo) over Bluetooth Low Energy. Reads speed, power, cadence, battery, motor temp, odometer, assist level, range. Can also write settings like assist level and acceleration.

Async, built on [bleak](https://github.com/hbldh/bleak). Includes a CLI. Protocol docs in [docs/protocol.md](docs/protocol.md).

## Installation

```bash
pip install specialized-turbo
```

## Quick start

### Stream telemetry

```python
import asyncio
from specialized_turbo import SpecializedConnection, TelemetryMonitor

async def main():
    async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin="946166") as conn:
        monitor = TelemetryMonitor(conn)
        await monitor.start()

        async for msg in monitor.stream():
            print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

asyncio.run(main())
```

### Read the snapshot

```python
async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin="946166") as conn:
    monitor = TelemetryMonitor(conn)
    await monitor.start()
    await asyncio.sleep(5)

    snap = monitor.snapshot
    print(f"Speed: {snap.motor.speed_kmh} km/h")
    print(f"Battery: {snap.battery.charge_pct}%")
    print(f"Power: {snap.motor.rider_power_w} W (rider) + {snap.motor.motor_power_w} W (motor)")
    print(f"Cadence: {snap.motor.cadence_rpm} RPM")
    print(f"Assist: {snap.motor.assist_level}")
```

### Query a single value

```python
from specialized_turbo import SpecializedConnection, Sender, BatteryChannel

async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin="946166") as conn:
    msg = await conn.request_value(Sender.BATTERY, BatteryChannel.CHARGE_PERCENT)
    print(f"Battery: {msg.converted_value}%")
```

### Write commands

```python
async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin="946166") as conn:
    await conn.set_assist_level(2)          # TRAIL
    await conn.set_acceleration(50.0)       # 50%
    await conn.set_shuttle(25)
    await conn.set_assist_percentage(0, 35) # ECO = 35%
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
specialized-turbo read list                                             # show available fields
specialized-turbo read battery_charge_percent DC:DD:BB:4A:D6:55 --pin 946166
specialized-turbo read speed DC:DD:BB:4A:D6:55 --pin 946166 --format json
```

Write a value:

```bash
specialized-turbo write list                                            # show writable fields
specialized-turbo write assist_level 2 DC:DD:BB:4A:D6:55 --pin 946166  # set to TRAIL
specialized-turbo write acceleration 50 DC:DD:BB:4A:D6:55 --pin 946166 # 50% sensitivity
```

Dump GATT services (debugging):

```bash
specialized-turbo services DC:DD:BB:4A:D6:55 --pin 946166
```

Capture complete TCX writes and notifications for protocol debugging:

```bash
specialized-turbo capture DC:DD:BB:4A:D6:55 --duration 60 > tcx-capture.tsv
```

## Available fields

| Field | Unit | Writable | Description |
| --- | --- | --- | --- |
| `battery_capacity_wh` | Wh | | Total battery capacity |
| `battery_remaining_wh` | Wh | | Remaining energy |
| `battery_health` | % | | Battery health |
| `battery_temp` | °C | | Battery temperature |
| `battery_charge_cycles` | cycles | | Number of charge cycles |
| `battery_voltage` | V | | Battery voltage |
| `battery_current` | A | | Battery current draw |
| `battery_charge_percent` | % | | State of charge |
| `rider_power` | W | | Rider pedal power |
| `cadence` | RPM | | Pedaling cadence |
| `speed` | km/h | | Current speed |
| `odometer` | km | | Total distance |
| `assist_level` | -- | yes | OFF / ECO / TRAIL / TURBO |
| `motor_temp` | °C | | Motor temperature |
| `motor_power` | W | | Electric motor power |
| `peak_assist` | % | | ECO / TRAIL / TURBO percentages |
| `shuttle` | -- | yes | Shuttle mode value (0-100) |
| `wheel_circumference` | mm | yes | Wheel circumference setting |
| `assist_lev1_pct` | % | yes | ECO assist percentage |
| `assist_lev2_pct` | % | yes | TRAIL assist percentage |
| `assist_lev3_pct` | % | yes | TURBO assist percentage |
| `fake_channel` | -- | | Bit-coded internal channel |
| `acceleration` | % | yes | Acceleration sensitivity |

TCX2+ bikes have additional fields (range, altitude, gradient, calories, system temperature, and more). See [docs/protocol.md](docs/protocol.md) for the full list.

## Protocol support

Four protocol generations exist:

| Protocol | Message format | Encryption |
| --- | --- | --- |
| TCU1 | `[sender][channel][data]` | None |
| TCX2 | 2-byte parameter ID + CRC-16 | Optional AES-128-CTR |
| TCX3 | Same as TCX2 | Optional AES-128-CTR |
| TCX4 | Same as TCX2 | Optional AES-128-CTR |

TCX2/3/4 share one wire format and differ only in which parameters the bike supports. The `BLEProfile` enum (`TCU1` / `TCX`) controls which GATT UUIDs to use.

See [docs/protocol.md](docs/protocol.md) for the full spec.

## Pairing

The bike needs a 6-digit PIN for BLE pairing, shown on its TCU screen. Pass it via `--pin` (CLI) or `pin=` (Python).

On Windows, bleak's WinRT backend can handle passkey pairing programmatically. If that doesn't work, pair through Windows Bluetooth Settings first, then connect without `--pin`.

Some newer bikes use numeric comparison instead of passkey entry. On those, pair through your OS Bluetooth settings first.

## Development

```bash
uv sync --extra dev
uv run pytest
```

## License

MIT
