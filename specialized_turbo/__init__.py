"""
specialized_turbo -- talk to Specialized Turbo e-bikes over BLE.

Quick start (TCX2+ bikes)::

    import asyncio
    from specialized_turbo import (
        SpecializedConnection,
        TelemetryMonitor,
        parse_bike_info,
    )
    from specialized_turbo.keystore import BikeEncryptionKey

    async def main():
        # ``bike_info`` comes from the BLE advertisement (parse_bike_info)
        # and ``key`` from the Specialized account keystore -- a TCX2+ bike
        # cannot be identified without both.
        async with SpecializedConnection(
            "DC:DD:BB:4A:D6:55", pin="946166", bike_info=info, key=key
        ) as conn:
            monitor = TelemetryMonitor(conn)
            await monitor.start()

            async for msg in monitor.stream():
                print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

    asyncio.run(main())

``BikeEncryptionKey`` and the keystore models import without the optional
``aiohttp`` dependency; only the network ``KeystoreClient`` needs the
``keystore`` extra (``pip install "specialized-turbo[keystore]"``).
"""

from __future__ import annotations

from .protocol import (
    # UUIDs (TCX defaults)
    SERVICE_DATA_NOTIFY as SERVICE_DATA_NOTIFY,
    SERVICE_DATA_REQUEST as SERVICE_DATA_REQUEST,
    SERVICE_DATA_WRITE as SERVICE_DATA_WRITE,
    CHAR_NOTIFY as CHAR_NOTIFY,
    CHAR_REQUEST_READ as CHAR_REQUEST_READ,
    CHAR_REQUEST_WRITE as CHAR_REQUEST_WRITE,
    CHAR_WRITE as CHAR_WRITE,
    CHAR_REQUEST_NOTIFY as CHAR_REQUEST_NOTIFY,
    CHAR_COMMAND_NOTIFY as CHAR_COMMAND_NOTIFY,
    CHAR_COMMAND_WRITE as CHAR_COMMAND_WRITE,
    CHAR_DATA_NOTIFY as CHAR_DATA_NOTIFY,
    CHAR_DATA_WRITE as CHAR_DATA_WRITE,
    # TCU1 UUIDs
    SERVICE_DATA_NOTIFY_TCU1 as SERVICE_DATA_NOTIFY_TCU1,
    SERVICE_DATA_REQUEST_TCU1 as SERVICE_DATA_REQUEST_TCU1,
    SERVICE_DATA_WRITE_TCU1 as SERVICE_DATA_WRITE_TCU1,
    CHAR_NOTIFY_TCU1 as CHAR_NOTIFY_TCU1,
    CHAR_REQUEST_READ_TCU1 as CHAR_REQUEST_READ_TCU1,
    CHAR_REQUEST_WRITE_TCU1 as CHAR_REQUEST_WRITE_TCU1,
    CHAR_WRITE_TCU1 as CHAR_WRITE_TCU1,
    # Generation-aware UUID helpers
    BLEProfile as BLEProfile,
    BLEServiceID as BLEServiceID,
    BLEServiceCharacteristics as BLEServiceCharacteristics,
    BikeAdvertisement as BikeAdvertisement,
    ProtocolEncryptionMethod as ProtocolEncryptionMethod,
    get_uuid as get_uuid,
    get_char_notify as get_char_notify,
    get_char_request_read as get_char_request_read,
    get_char_request_write as get_char_request_write,
    get_char_write as get_char_write,
    get_service_characteristics as get_service_characteristics,
    detect_generation as detect_generation,
    parse_bike_advertisement as parse_bike_advertisement,
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
    build_write_command as build_write_command,
    is_specialized_advertisement as is_specialized_advertisement,
    TCU1_POLL_FIELDS as TCU1_POLL_FIELDS,
    # Company IDs
    NORDIC_COMPANY_ID as NORDIC_COMPANY_ID,
    APPLE_COMPANY_ID as APPLE_COMPANY_ID,
    SIMPLO_COMPANY_ID as SIMPLO_COMPANY_ID,
)
from .models import (
    BatteryState as BatteryState,
    MotorState as MotorState,
    BikeSettings as BikeSettings,
    SystemState as SystemState,
    TelemetrySnapshot as TelemetrySnapshot,
)
from .connection import (
    SpecializedConnection as SpecializedConnection,
    UnsupportedTCXOperationError as UnsupportedTCXOperationError,
    scan_for_bikes as scan_for_bikes,
    find_bike_by_address as find_bike_by_address,
    find_advertisement_by_address as find_advertisement_by_address,
    find_bike_advertisement_by_address as find_bike_advertisement_by_address,
)
from .bike_info import (
    BikeInfo as BikeInfo,
    parse_bike_info as parse_bike_info,
)
from .keystore.models import (
    BikeEncryptionKey as BikeEncryptionKey,
)
from .wire_profiles import (
    ProtocolRevision as ProtocolRevision,
    TCXGeneration as TCXGeneration,
    WireProfileError as WireProfileError,
    UnmappedParameterError as UnmappedParameterError,
)
from .identification import (
    TCXIdentification as TCXIdentification,
    identify as identify,
    parse_wire_message as parse_wire_message,
    WireMessage as WireMessage,
    IdentificationResult as IdentificationResult,
    IdentificationPhase as IdentificationPhase,
    IdentificationError as IdentificationError,
    IncompleteBikeInfoError as IncompleteBikeInfoError,
    UnsupportedGenerationError as UnsupportedGenerationError,
    UnsupportedRevisionError as UnsupportedRevisionError,
    MissingEncryptionKeyError as MissingEncryptionKeyError,
    MalformedIVError as MalformedIVError,
    MalformedProtocolResponseError as MalformedProtocolResponseError,
    DecryptionError as DecryptionError,
    IdentificationNakError as IdentificationNakError,
)
from .telemetry import (
    TelemetryMonitor as TelemetryMonitor,
    run_telemetry_session as run_telemetry_session,
)
from .framing import (
    compute_crc16_ccitt as compute_crc16_ccitt,
    pack_tcx as pack_tcx,
    unpack_tcx as unpack_tcx,
    is_framed_packet as is_framed_packet,
    is_nak_packet as is_nak_packet,
    is_realtime_packet as is_realtime_packet,
    parse_nak_packet as parse_nak_packet,
    strip_clear_prefix as strip_clear_prefix,
    NAK_PREFIX as NAK_PREFIX,
    REALTIME_PREFIX as REALTIME_PREFIX,
)
from .parameters import (
    BikeParameter as BikeParameter,
    TCXFieldDefinition as TCXFieldDefinition,
    get_tcx_field as get_tcx_field,
    all_tcx_fields as all_tcx_fields,
    encode_parameter_id as encode_parameter_id,
    decode_parameter_id as decode_parameter_id,
)
from .encryption import (
    EncryptionError as EncryptionError,
    WrappedKeyError as WrappedKeyError,
    PRODUCTION_WRAPPING_KEY as PRODUCTION_WRAPPING_KEY,
    STAGING_WRAPPING_KEY as STAGING_WRAPPING_KEY,
    encrypt_packet as encrypt_packet,
    decrypt_packet as decrypt_packet,
    derive_key as derive_key,
    unwrap_keystore_key as unwrap_keystore_key,
    is_encryptable as is_encryptable,
)
from .key_provider import (
    EncryptionKeyProvider as EncryptionKeyProvider,
    EncryptionKeyProviderError as EncryptionKeyProviderError,
    EncryptionKeyRequiredError as EncryptionKeyRequiredError,
    StaticKeyProvider as StaticKeyProvider,
    resolve_bike_key as resolve_bike_key,
)
from .session import (
    ProtocolSession as ProtocolSession,
    TCU1Session as TCU1Session,
    TCXSession as TCXSession,
)
from .transport import (
    BLETraceEvent as BLETraceEvent,
    TCXNotificationTransport as TCXNotificationTransport,
    TCXProtocolNotNegotiatedError as TCXProtocolNotNegotiatedError,
    TCXRequestTimeoutError as TCXRequestTimeoutError,
    TCXTransportDisconnectedError as TCXTransportDisconnectedError,
)
from .protocol import (
    parse_tcx_message as parse_tcx_message,
    build_tcx_request as build_tcx_request,
    build_tcx_write as build_tcx_write,
)
from .coordinator_helpers import (
    TCX_POLL_PARAMS as TCX_POLL_PARAMS,
    parse_notification as parse_notification,
    parse_tcx_notification as parse_tcx_notification,
    parse_tcx_wire_payload as parse_tcx_wire_payload,
    poll_tcu1 as poll_tcu1,
    poll_tcx as poll_tcx,
    identify_tcx as identify_tcx,
)

__all__ = [
    # Protocol — TCX UUIDs (backward-compatible defaults)
    "SERVICE_DATA_NOTIFY",
    "SERVICE_DATA_REQUEST",
    "SERVICE_DATA_WRITE",
    "CHAR_NOTIFY",
    "CHAR_REQUEST_READ",
    "CHAR_REQUEST_WRITE",
    "CHAR_WRITE",
    "CHAR_REQUEST_NOTIFY",
    "CHAR_COMMAND_NOTIFY",
    "CHAR_COMMAND_WRITE",
    "CHAR_DATA_NOTIFY",
    "CHAR_DATA_WRITE",
    # Protocol — TCU1 UUIDs
    "SERVICE_DATA_NOTIFY_TCU1",
    "SERVICE_DATA_REQUEST_TCU1",
    "SERVICE_DATA_WRITE_TCU1",
    "CHAR_NOTIFY_TCU1",
    "CHAR_REQUEST_READ_TCU1",
    "CHAR_REQUEST_WRITE_TCU1",
    "CHAR_WRITE_TCU1",
    # Protocol — generation-aware helpers
    "BLEProfile",
    "BLEServiceID",
    "BLEServiceCharacteristics",
    "BikeAdvertisement",
    "ProtocolEncryptionMethod",
    "get_uuid",
    "get_char_notify",
    "get_char_request_read",
    "get_char_request_write",
    "get_char_write",
    "get_service_characteristics",
    "detect_generation",
    "parse_bike_advertisement",
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
    "build_write_command",
    "is_specialized_advertisement",
    "TCU1_POLL_FIELDS",
    # Company IDs
    "NORDIC_COMPANY_ID",
    "APPLE_COMPANY_ID",
    "SIMPLO_COMPANY_ID",
    # Models
    "BatteryState",
    "MotorState",
    "BikeSettings",
    "SystemState",
    "TelemetrySnapshot",
    # Connection
    "SpecializedConnection",
    "UnsupportedTCXOperationError",
    "scan_for_bikes",
    "find_bike_by_address",
    "find_advertisement_by_address",
    "find_bike_advertisement_by_address",
    # Advertisement parsing / identification
    "BikeInfo",
    "parse_bike_info",
    "BikeEncryptionKey",
    "ProtocolRevision",
    "TCXGeneration",
    "WireProfileError",
    "UnmappedParameterError",
    "TCXIdentification",
    "identify",
    "parse_wire_message",
    "WireMessage",
    "IdentificationResult",
    "IdentificationPhase",
    "IdentificationError",
    "IncompleteBikeInfoError",
    "UnsupportedGenerationError",
    "UnsupportedRevisionError",
    "MissingEncryptionKeyError",
    "MalformedIVError",
    "MalformedProtocolResponseError",
    "DecryptionError",
    "IdentificationNakError",
    # Telemetry
    "TelemetryMonitor",
    "run_telemetry_session",
    # Framing
    "compute_crc16_ccitt",
    "pack_tcx",
    "unpack_tcx",
    "is_framed_packet",
    "is_nak_packet",
    "is_realtime_packet",
    "parse_nak_packet",
    "strip_clear_prefix",
    "NAK_PREFIX",
    "REALTIME_PREFIX",
    # Parameters (TCX2+)
    "BikeParameter",
    "TCXFieldDefinition",
    "get_tcx_field",
    "all_tcx_fields",
    "encode_parameter_id",
    "decode_parameter_id",
    "parse_tcx_message",
    "build_tcx_request",
    "build_tcx_write",
    # Encryption
    "EncryptionError",
    "WrappedKeyError",
    "PRODUCTION_WRAPPING_KEY",
    "STAGING_WRAPPING_KEY",
    "encrypt_packet",
    "decrypt_packet",
    "derive_key",
    "unwrap_keystore_key",
    "is_encryptable",
    # Encryption key providers
    "EncryptionKeyProvider",
    "EncryptionKeyProviderError",
    "EncryptionKeyRequiredError",
    "StaticKeyProvider",
    "resolve_bike_key",
    # Session
    "ProtocolSession",
    "TCU1Session",
    "TCXSession",
    # TCX notification transport
    "BLETraceEvent",
    "TCXNotificationTransport",
    "TCXProtocolNotNegotiatedError",
    "TCXRequestTimeoutError",
    "TCXTransportDisconnectedError",
    # Coordinator helpers
    "TCX_POLL_PARAMS",
    "parse_notification",
    "parse_tcx_notification",
    "parse_tcx_wire_payload",
    "poll_tcu1",
    "poll_tcx",
    "identify_tcx",
]

__version__ = "0.7.6"
