"""
Command-line interface for the Specialized Turbo Vado BLE library.

Provides subcommands for scanning, connecting, and reading telemetry.

Uses ``argparse`` (no extra dependencies) with optional ``click`` upgrade path.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time

from bleak.backends.characteristic import BleakGATTCharacteristic

from .connection import SpecializedConnection, scan_for_bikes
from .parameters import all_tcx_fields
from .protocol import (
    all_field_defs,
)
from .telemetry import run_telemetry_session
from .transport import BLETraceEvent


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


async def _cmd_scan(args: argparse.Namespace) -> None:
    """Scan for nearby Specialized Turbo bikes."""
    print(f"Scanning for Specialized bikes ({args.timeout}s) ...")
    results = await scan_for_bikes(timeout=args.timeout)

    if not results:
        print("No Specialized bikes found.")
        print("Make sure the bike is powered on and Bluetooth is enabled.")
        return

    print(f"\nFound {len(results)} bike(s):\n")
    for device, adv in results:
        print(f"  Name:    {device.name or '(unknown)'}")
        print(f"  Address: {device.address}")
        print(f"  RSSI:    {adv.rssi} dBm")
        mfr = adv.manufacturer_data.get(0x0059, b"")
        if mfr:
            print(f"  Mfr:     {mfr.hex()}")
        print()


# ---------------------------------------------------------------------------
# telemetry
# ---------------------------------------------------------------------------


async def _cmd_telemetry(args: argparse.Namespace) -> None:
    """Connect and stream live telemetry."""
    print(f"Connecting to {args.address} ...")

    snapshot = await run_telemetry_session(
        args.address,
        pin=args.pin,
        duration=args.duration,
        output_format=args.format,
    )

    # Print final summary
    print("\n--- Session Summary ---")
    d = snapshot.as_dict()
    if args.format == "json":
        print(json.dumps(d, indent=2, default=str))
    else:
        for section, values in d.items():
            if isinstance(values, dict):
                print(f"\n  {section}:")
                for k, v in values.items():
                    print(f"    {k:<28s} = {v}")
            else:
                print(f"  {section}: {values}")


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------

# Map human-readable names → (sender, channel)
_FIELD_NAME_MAP: dict[str, tuple[int, int]] = {}
for _key, _fd in all_field_defs().items():
    _FIELD_NAME_MAP[_fd.name] = _key

# Map human-readable names → TCX parameter ID
_TCX_FIELD_NAME_MAP: dict[str, int] = {}
for _param_id, _tfd in all_tcx_fields().items():
    _TCX_FIELD_NAME_MAP[_tfd.name] = _param_id


async def _cmd_read(args: argparse.Namespace) -> None:
    """Connect, read a specific value, and disconnect."""
    field_name = args.field

    if field_name == "list":
        print("Available fields:\n")
        print("  TCU1 fields:")
        for name, (sender, channel) in sorted(_FIELD_NAME_MAP.items()):
            fd = all_field_defs()[(sender, channel)]
            print(
                f"    {name:<28s}  (sender=0x{sender:02x} channel=0x{channel:02x})  [{fd.unit}]"
            )
        print("\n  TCX fields:")
        for name, param_id in sorted(_TCX_FIELD_NAME_MAP.items()):
            tfd = all_tcx_fields()[param_id]
            print(f"    {name:<28s}  (param={param_id})  [{tfd.unit}]")
        return

    # Prefer TCX field lookup, fall back to TCU1
    tcx_param_id = _TCX_FIELD_NAME_MAP.get(field_name)
    tcu1_key = _FIELD_NAME_MAP.get(field_name)

    if tcx_param_id is None and tcu1_key is None:
        print(f"Unknown field: {field_name}")
        print("Use 'read list' to see available fields.")
        sys.exit(1)

    print(f"Connecting to {args.address} to read '{field_name}' ...")

    async with SpecializedConnection(args.address, pin=args.pin) as conn:
        if tcx_param_id is not None:
            msg = await conn.request_tcx_value(tcx_param_id)
        else:
            assert tcu1_key is not None
            sender, channel = tcu1_key
            msg = await conn.request_value(sender, channel)
        if args.format == "json":
            if msg.nak_reason is not None:
                print(
                    json.dumps(
                        {
                            "field": field_name,
                            "rejected": True,
                            "reason": msg.nak_reason,
                        },
                        default=str,
                    )
                )
            else:
                print(
                    json.dumps(
                        {
                            "field": msg.field_name,
                            "value": msg.converted_value,
                            "raw": msg.raw_value,
                            "unit": msg.unit,
                        },
                        default=str,
                    )
                )
        else:
            if msg.nak_reason is not None:
                print(f"{field_name}: rejected by bike (reason 0x{msg.nak_reason:02x})")
            else:
                print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------

# Writable fields: name → (sender, channel, FieldDefinition)
_WRITABLE_FIELD_MAP: dict[str, tuple[int, int]] = {}
for _key, _fd in all_field_defs().items():
    if _fd.writable:
        _WRITABLE_FIELD_MAP[_fd.name] = _key


async def _cmd_write(args: argparse.Namespace) -> None:
    """Connect, write a value, and disconnect."""
    field_name = args.field

    if field_name == "list":
        print("Writable fields:\n")
        for name, (sender, channel) in sorted(_WRITABLE_FIELD_MAP.items()):
            fd = all_field_defs()[(sender, channel)]
            print(
                f"  {name:<28s}  (sender=0x{sender:02x} channel=0x{channel:02x})  [{fd.unit}]"
            )
        return

    if field_name not in _WRITABLE_FIELD_MAP:
        print(f"Unknown or read-only field: {field_name}")
        print("Use 'write list' to see writable fields.")
        sys.exit(1)

    if args.value is None or args.address is None:
        print("Usage: specialized-turbo write <field> <value> <address>")
        sys.exit(1)

    sender, channel = _WRITABLE_FIELD_MAP[field_name]
    fd = all_field_defs()[(sender, channel)]

    # Parse and encode the value
    raw_value = float(args.value) if "." in args.value else int(args.value)
    if fd.encode is not None:
        wire_value = fd.encode(raw_value)
    else:
        wire_value = int(raw_value)

    from .protocol import build_write_command

    data_bytes = wire_value.to_bytes(fd.data_size, "little")
    command = build_write_command(sender, channel, data_bytes)

    print(f"Connecting to {args.address} to write '{field_name}' = {raw_value} ...")

    async with SpecializedConnection(args.address, pin=args.pin) as conn:
        await conn.write_command(command)
        print(
            f"Wrote {field_name} = {raw_value} (raw: {wire_value}, bytes: {command.hex()})"
        )


# ---------------------------------------------------------------------------
# services (debug helper)
# ---------------------------------------------------------------------------


async def _cmd_services(args: argparse.Namespace) -> None:
    """Connect and enumerate all GATT services/characteristics (debug)."""
    from bleak import BleakClient
    from bleak.exc import BleakError

    print(f"Connecting to {args.address} ...")
    async with BleakClient(args.address) as client:
        if args.pin is not None:
            try:
                await client.pair(protection_level=2)
            except (BleakError, NotImplementedError) as e:
                print(f"Pairing note: {e}")

        print("Connected. Enumerating services ...\n")
        for service in client.services:
            print(f"Service: {service.uuid}  [{service.description}]")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"  Char: {char.uuid}  [{props}]  {char.description}")
                for desc in char.descriptors:
                    print(f"    Desc: {desc.uuid}  {desc.description}")
            print()


# ---------------------------------------------------------------------------
# capture (debug helper)
# ---------------------------------------------------------------------------


async def _cmd_capture(args: argparse.Namespace) -> None:
    """Capture complete TCX writes and notifications as tab-separated hex."""
    started = time.monotonic()

    def trace(event: BLETraceEvent) -> None:
        elapsed = event.timestamp - started
        print(
            f"{elapsed:.6f}\t{event.direction.upper()}\t"
            f"{int(event.service_id)}\t{event.characteristic}\t{event.data.hex()}",
            flush=True,
        )

    def discard(
        _sender: BleakGATTCharacteristic,
        _data: bytearray,
    ) -> None:
        pass

    print("seconds\tdirection\tservice\tcharacteristic\tpayload", flush=True)
    async with SpecializedConnection(
        args.address,
        pin=args.pin,
        trace_callback=trace,
    ) as conn:
        await conn.subscribe_notifications(discard)
        try:
            if args.duration > 0:
                await asyncio.sleep(args.duration)
            else:
                await asyncio.Event().wait()
        finally:
            await conn.unsubscribe_notifications()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="specialized-turbo",
        description="Interact with Specialized Turbo e-bikes over Bluetooth LE",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    p_scan = sub.add_parser("scan", help="Scan for nearby Specialized bikes")
    p_scan.add_argument(
        "-t", "--timeout", type=float, default=10.0, help="Scan duration (seconds)"
    )

    # --- telemetry ---
    p_tel = sub.add_parser("telemetry", help="Stream live telemetry")
    p_tel.add_argument("address", help="BLE MAC address (e.g. DC:DD:BB:4A:D6:55)")
    p_tel.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    p_tel.add_argument(
        "-d",
        "--duration",
        type=float,
        default=0,
        help="Duration in seconds (0=forever)",
    )
    p_tel.add_argument("-f", "--format", choices=["table", "json"], default="table")

    # --- read ---
    p_read = sub.add_parser(
        "read", help="Read a specific value (use 'read list' to see fields)"
    )
    p_read.add_argument("field", help="Field name or 'list'")
    p_read.add_argument("address", nargs="?", default=None, help="BLE MAC address")
    p_read.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    p_read.add_argument("-f", "--format", choices=["table", "json"], default="table")

    # --- services ---
    p_svc = sub.add_parser("services", help="Enumerate GATT services (debug)")
    p_svc.add_argument("address", help="BLE MAC address")
    p_svc.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")

    # --- capture ---
    p_capture = sub.add_parser(
        "capture",
        help="Capture raw TCX writes and notifications",
    )
    p_capture.add_argument("address", help="BLE MAC address")
    p_capture.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    p_capture.add_argument(
        "-d",
        "--duration",
        type=float,
        default=60,
        help="Capture duration in seconds (0=forever)",
    )

    # --- write ---
    p_write = sub.add_parser(
        "write",
        help="Write a value to the bike (use 'write list' to see writable fields)",
    )
    p_write.add_argument("field", help="Field name or 'list'")
    p_write.add_argument("value", nargs="?", default=None, help="Value to write")
    p_write.add_argument("address", nargs="?", default=None, help="BLE MAC address")
    p_write.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    coro = {
        "scan": _cmd_scan,
        "telemetry": _cmd_telemetry,
        "read": _cmd_read,
        "services": _cmd_services,
        "capture": _cmd_capture,
        "write": _cmd_write,
    }[args.command](args)

    try:
        asyncio.run(coro)
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
