"""
specialized_turbo -- talk to Specialized Turbo e-bikes over BLE.

Quick start::

    import asyncio
    from specialized_turbo import SpecializedConnection, TelemetryMonitor

    async def main():
        async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin=946166) as conn:
            monitor = TelemetryMonitor(conn)
            await monitor.start()

            async for msg in monitor.stream():
                print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

    asyncio.run(main())
"""

from .protocol import (
    # UUIDs (Gen 2 defaults)
    SERVICE_DATA_NOTIFY as SERVICE_DATA_NOTIFY,
    SERVICE_DATA_REQUEST as SERVICE_DATA_REQUEST,
    SERVICE_DATA_WRITE as SERVICE_DATA_WRITE,
    CHAR_NOTIFY as CHAR_NOTIFY,
    CHAR_REQUEST_READ as CHAR_REQUEST_READ,
    CHAR_REQUEST_WRITE as CHAR_REQUEST_WRITE,
    CHAR_WRITE as CHAR_WRITE,
    # Gen 1 UUIDs
    SERVICE_DATA_NOTIFY_GEN1 as SERVICE_DATA_NOTIFY_GEN1,
    SERVICE_DATA_REQUEST_GEN1 as SERVICE_DATA_REQUEST_GEN1,
    SERVICE_DATA_WRITE_GEN1 as SERVICE_DATA_WRITE_GEN1,
    CHAR_NOTIFY_GEN1 as CHAR_NOTIFY_GEN1,
    CHAR_REQUEST_READ_GEN1 as CHAR_REQUEST_READ_GEN1,
    CHAR_REQUEST_WRITE_GEN1 as CHAR_REQUEST_WRITE_GEN1,
    CHAR_WRITE_GEN1 as CHAR_WRITE_GEN1,
    # Generation-aware UUID helpers
    ProtocolGeneration as ProtocolGeneration,
    get_uuid as get_uuid,
    get_char_notify as get_char_notify,
    get_char_request_read as get_char_request_read,
    get_char_request_write as get_char_request_write,
    get_char_write as get_char_write,
    detect_generation as detect_generation,
    # Enums
    Sender as Sender,
    BatteryChannel as BatteryChannel,
    MotorChannel as MotorChannel,
    BikeSettingsChannel as BikeSettingsChannel,
    AssistLevel as AssistLevel,
    # Parsing
    parse_message as parse_message,
    ParsedMessage as ParsedMessage,
    FieldDefinition as FieldDefinition,
    get_field_def as get_field_def,
    all_field_defs as all_field_defs,
    build_request as build_request,
    is_specialized_advertisement as is_specialized_advertisement,
    # Company IDs
    NORDIC_COMPANY_ID as NORDIC_COMPANY_ID,
    SIMPLO_COMPANY_ID as SIMPLO_COMPANY_ID,
)
from .models import (
    BatteryState as BatteryState,
    MotorState as MotorState,
    BikeSettings as BikeSettings,
    TelemetrySnapshot as TelemetrySnapshot,
)
from .connection import (
    SpecializedConnection as SpecializedConnection,
    scan_for_bikes as scan_for_bikes,
    find_bike_by_address as find_bike_by_address,
)
from .telemetry import (
    TelemetryMonitor as TelemetryMonitor,
    run_telemetry_session as run_telemetry_session,
)

__all__ = [
    # Protocol — Gen 2 UUIDs (backward-compatible defaults)
    "SERVICE_DATA_NOTIFY",
    "SERVICE_DATA_REQUEST",
    "SERVICE_DATA_WRITE",
    "CHAR_NOTIFY",
    "CHAR_REQUEST_READ",
    "CHAR_REQUEST_WRITE",
    "CHAR_WRITE",
    # Protocol — Gen 1 UUIDs
    "SERVICE_DATA_NOTIFY_GEN1",
    "SERVICE_DATA_REQUEST_GEN1",
    "SERVICE_DATA_WRITE_GEN1",
    "CHAR_NOTIFY_GEN1",
    "CHAR_REQUEST_READ_GEN1",
    "CHAR_REQUEST_WRITE_GEN1",
    "CHAR_WRITE_GEN1",
    # Protocol — generation-aware helpers
    "ProtocolGeneration",
    "get_uuid",
    "get_char_notify",
    "get_char_request_read",
    "get_char_request_write",
    "get_char_write",
    "detect_generation",
    # Enums
    "Sender",
    "BatteryChannel",
    "MotorChannel",
    "BikeSettingsChannel",
    "AssistLevel",
    # Parsing
    "parse_message",
    "ParsedMessage",
    "FieldDefinition",
    "get_field_def",
    "all_field_defs",
    "build_request",
    "is_specialized_advertisement",
    # Company IDs
    "NORDIC_COMPANY_ID",
    "SIMPLO_COMPANY_ID",
    # Models
    "BatteryState",
    "MotorState",
    "BikeSettings",
    "TelemetrySnapshot",
    # Connection
    "SpecializedConnection",
    "scan_for_bikes",
    "find_bike_by_address",
    # Telemetry
    "TelemetryMonitor",
    "run_telemetry_session",
]

__version__ = "0.2.1"
