"""Optional client for Specialized's undocumented account and keystore APIs."""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass
from typing import Self

import httpx

from .key_provider import EncryptionKeyProviderError

_AUTH_BASE_URL = "https://api-sp.todaysplan.com.au"
_APPLICATION_ID_URL = "https://api-sp.zone5cloud.com/logging-service/open/v2/uuid/"
_KEYSTORE_URL = "https://api.specialized.com/keystore-service/v2/keystores"
_APP_API_KEY = "1rubr0dkih8dqtum7jvii3arvo"


class CloudAuthenticationError(EncryptionKeyProviderError):
    """Raised when Specialized account authentication fails."""


class CloudRequestError(EncryptionKeyProviderError):
    """Raised when a Specialized cloud request fails."""


@dataclass(frozen=True, slots=True)
class CloudToken:
    """Specialized account token state."""

    access_token: str
    refresh_token: str | None = None
    expires_at_ms: int | None = None

    def expires_soon(self, *, now_ms: int | None = None) -> bool:
        """Return whether the access token expires within 30 seconds."""
        if self.expires_at_ms is None:
            return False
        current = int(time.time() * 1000) if now_ms is None else now_ms
        return self.expires_at_ms <= current + 30_000


class SpecializedCloudClient:
    """Authenticate and retrieve wrapped bike keys from Specialized."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        token: CloudToken | None = None,
        email: str | None = None,
        application_id: str | None = None,
    ) -> None:
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None
        self._token = token
        self._email = email
        self._application_id = application_id

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    @property
    def token(self) -> CloudToken | None:
        """Return the current token state."""
        return self._token

    @property
    def application_id(self) -> str | None:
        """Return the cached installation UUID."""
        return self._application_id

    async def aclose(self) -> None:
        """Close the internally owned HTTP client."""
        if self._owns_client:
            await self._client.aclose()

    async def login(self, email: str, password: str) -> CloudToken:
        """Authenticate with a Specialized account."""
        response = await self._client.post(
            f"{_AUTH_BASE_URL}/rest/auth/login",
            headers=self._auth_api_headers(),
            json={"username": email, "password": password, "accept": []},
        )
        if response.status_code in {401, 403}:
            raise CloudAuthenticationError("Specialized account login failed")
        self._raise_for_status(response, "Specialized account login failed")

        self._email = email
        self._token = self._parse_token(response)
        return self._token

    async def refresh(self) -> CloudToken:
        """Refresh the current Specialized account access token."""
        token = self._token
        if self._email is None or token is None or token.refresh_token is None:
            raise CloudAuthenticationError("No Specialized refresh token is available")

        response = await self._client.post(
            f"{_AUTH_BASE_URL}/rest/auth/refresh",
            headers=self._auth_api_headers(),
            json={"email": self._email, "refresh": token.refresh_token},
        )
        if response.status_code in {401, 403}:
            raise CloudAuthenticationError("Specialized token refresh failed")
        self._raise_for_status(response, "Specialized token refresh failed")

        self._token = self._parse_token(response)
        return self._token

    async def get_application_id(self) -> str:
        """Return the installation UUID required by Specialized API headers."""
        if self._application_id is not None:
            return self._application_id

        response = await self._client.get(_APPLICATION_ID_URL)
        self._raise_for_status(response, "Application ID request failed")
        uuid = self._response_json(response, "Application ID response").get("uuid")
        if not isinstance(uuid, str) or not uuid:
            raise CloudRequestError("Application ID response did not contain a UUID")
        self._application_id = uuid
        return uuid

    async def get_wrapped_key(
        self,
        *,
        hmi_hardware: str,
        hmi_serial: str,
    ) -> str:
        """Return the wrapped AES key for one HMI."""
        token = await self._valid_token()
        application_id = await self.get_application_id()
        response = await self._request_key(
            token.access_token,
            application_id,
            hmi_hardware,
            hmi_serial,
        )

        if response.status_code == 401 and token.refresh_token is not None:
            token = await self.refresh()
            response = await self._request_key(
                token.access_token,
                application_id,
                hmi_hardware,
                hmi_serial,
            )

        if response.status_code in {401, 403}:
            raise CloudAuthenticationError("Specialized keystore authorization failed")
        self._raise_for_status(response, "Specialized keystore request failed")

        payload = self._response_json(response, "Specialized keystore response")
        key = payload.get("key")
        if not isinstance(key, str) or not key:
            raise CloudRequestError(
                "Specialized keystore response did not contain a key"
            )
        if payload.get("hmiHW") not in {None, hmi_hardware}:
            raise CloudRequestError(
                "Specialized keystore response HMI hardware mismatch"
            )
        if payload.get("hmiSN") not in {None, hmi_serial}:
            raise CloudRequestError("Specialized keystore response HMI serial mismatch")
        return key

    async def _valid_token(self) -> CloudToken:
        token = self._token
        if token is None:
            raise CloudAuthenticationError("No Specialized access token is available")
        if token.expires_soon() and token.refresh_token is not None:
            return await self.refresh()
        return token

    async def _request_key(
        self,
        access_token: str,
        application_id: str,
        hmi_hardware: str,
        hmi_serial: str,
    ) -> httpx.Response:
        return await self._client.get(
            _KEYSTORE_URL,
            params={"hmiHW": hmi_hardware, "hmiSN": hmi_serial},
            headers=self._keystore_headers(access_token, application_id),
        )

    @staticmethod
    def _parse_token(response: httpx.Response) -> CloudToken:
        payload = SpecializedCloudClient._response_json(
            response,
            "Specialized authentication response",
        )
        access_token = payload.get("token")
        if not isinstance(access_token, str) or not access_token:
            raise CloudAuthenticationError(
                "Specialized authentication response did not contain a token"
            )
        refresh_token = payload.get("refresh")
        expires_at_ms = payload.get("tokenExp")
        return CloudToken(
            access_token=access_token,
            refresh_token=refresh_token if isinstance(refresh_token, str) else None,
            expires_at_ms=expires_at_ms if isinstance(expires_at_ms, int) else None,
        )

    @staticmethod
    def _raise_for_status(response: httpx.Response, message: str) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise CloudRequestError(f"{message}: HTTP {response.status_code}") from exc

    @staticmethod
    def _response_json(response: httpx.Response, message: str) -> dict[str, object]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise CloudRequestError(f"{message} was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise CloudRequestError(f"{message} was not a JSON object")
        return payload

    @staticmethod
    def _auth_api_headers() -> dict[str, str]:
        return {
            "Api-Key": _APP_API_KEY,
            "X-SBC-APPLICATION": "Specialized App",
            "X-SBC-APPLICATION-VERSION": "1.70.1",
            "X-SBC-APPLICATION-BUILD": "261910614",
            "X-SBC-APPLICATION-OS": "Android",
        }

    @staticmethod
    def _keystore_headers(
        access_token: str,
        application_id: str,
    ) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {access_token}",
            "X-SBC-APPLICATION-ID": application_id,
            "X-SBC-APPLICATION": "Specialized App",
            "X-SBC-APPLICATION-VERSION": "1.70.1",
            "X-SBC-APPLICATION-BUILD": "261910614",
            "X-SBC-APPLICATION-SDK-VERSION": "0.0.1",
            "X-SBC-APPLICATION-MODULE": "TURBO",
            "X-SBC-APPLICATION-OS": "Android",
            "X-SBC-APPLICATION-OS-VERSION": platform.release(),
            "X-SBC-APPLICATION-DEVICE-VERSION": platform.machine(),
        }
