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

from .connection import scan_for_bikes, SpecializedConnection
from .protocol import (
    all_field_defs,
)
from .telemetry import run_telemetry_session


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


async def _cmd_read(args: argparse.Namespace) -> None:
    """Connect, read a specific value, and disconnect."""
    field_name = args.field

    if field_name == "list":
        print("Available fields:\n")
        for name, (sender, channel) in sorted(_FIELD_NAME_MAP.items()):
            fd = all_field_defs()[(sender, channel)]
            print(
                f"  {name:<28s}  (sender=0x{sender:02x} channel=0x{channel:02x})  [{fd.unit}]"
            )
        return

    if field_name not in _FIELD_NAME_MAP:
        print(f"Unknown field: {field_name}")
        print("Use 'read list' to see available fields.")
        sys.exit(1)

    sender, channel = _FIELD_NAME_MAP[field_name]
    print(f"Connecting to {args.address} to read '{field_name}' ...")

    async with SpecializedConnection(args.address, pin=args.pin) as conn:
        msg = await conn.request_value(sender, channel)
        if args.format == "json":
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
            print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")


# ---------------------------------------------------------------------------
# services (debug helper)
# ---------------------------------------------------------------------------


async def _cmd_services(args: argparse.Namespace) -> None:
    """Connect and enumerate all GATT services/characteristics (debug)."""
    from bleak import BleakClient

    print(f"Connecting to {args.address} ...")
    async with BleakClient(args.address) as client:
        if args.pin is not None:
            try:
                await client.pair(protection_level=2)
            except Exception as e:
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
    p_tel.add_argument("-p", "--pin", type=int, default=None, help="Pairing PIN")
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
    p_read.add_argument("-p", "--pin", type=int, default=None, help="Pairing PIN")
    p_read.add_argument("-f", "--format", choices=["table", "json"], default="table")

    # --- services ---
    p_svc = sub.add_parser("services", help="Enumerate GATT services (debug)")
    p_svc.add_argument("address", help="BLE MAC address")
    p_svc.add_argument("-p", "--pin", type=int, default=None, help="Pairing PIN")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    coro = {
        "scan": _cmd_scan,
        "telemetry": _cmd_telemetry,
        "read": _cmd_read,
        "services": _cmd_services,
    }[args.command](args)

    try:
        asyncio.run(coro)
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
