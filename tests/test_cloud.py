"""Tests for the optional Specialized cloud client."""

from __future__ import annotations

import json

import httpx
import pytest

from specialized_turbo.cloud import (
    CloudAuthenticationError,
    CloudRequestError,
    CloudToken,
    SpecializedCloudClient,
)


async def test_login_and_get_wrapped_key() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/rest/auth/login":
            assert json.loads(request.content) == {
                "username": "rider@example.com",
                "password": "secret",
                "accept": [],
            }
            assert request.headers["Api-Key"]
            return httpx.Response(
                200,
                json={
                    "token": "access",
                    "refresh": "refresh",
                    "tokenExp": 9999999999999,
                },
            )
        if request.url.host == "api-sp.zone5cloud.com":
            return httpx.Response(200, json={"uuid": "application-id"})
        assert request.url.path == "/keystore-service/v2/keystores"
        assert dict(request.url.params) == {
            "hmiHW": "3.2.1",
            "hmiSN": "123456789",
        }
        assert request.headers["Authorization"] == "Bearer access"
        assert request.headers["X-SBC-APPLICATION-ID"] == "application-id"
        return httpx.Response(
            200,
            json={
                "id": "key-id",
                "hmiHW": "3.2.1",
                "hmiSN": "123456789",
                "key": "A" * 64,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        cloud = SpecializedCloudClient(client=http)
        await cloud.login("rider@example.com", "secret")
        key = await cloud.get_wrapped_key(
            hmi_hardware="3.2.1",
            hmi_serial="123456789",
        )

    assert key == "A" * 64
    assert len(requests) == 3


async def test_keystore_401_refreshes_once() -> None:
    keystore_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal keystore_calls
        if request.url.host == "api-sp.zone5cloud.com":
            return httpx.Response(200, json={"uuid": "application-id"})
        if request.url.path == "/rest/auth/refresh":
            return httpx.Response(
                200,
                json={"token": "new-access", "refresh": "new-refresh"},
            )
        keystore_calls += 1
        if keystore_calls == 1:
            return httpx.Response(401, json={"message": "Unauthorized"})
        assert request.headers["Authorization"] == "Bearer new-access"
        return httpx.Response(
            200,
            json={"hmiHW": "3.2.1", "hmiSN": "123456789", "key": "A" * 64},
        )

    token = CloudToken(access_token="old-access", refresh_token="refresh")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        cloud = SpecializedCloudClient(
            client=http,
            token=token,
            email="rider@example.com",
        )
        key = await cloud.get_wrapped_key(
            hmi_hardware="3.2.1",
            hmi_serial="123456789",
        )

    assert key == "A" * 64
    assert keystore_calls == 2


async def test_login_rejects_invalid_credentials() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(401, json={"message": "Unauthorized"})
    )
    async with httpx.AsyncClient(transport=transport) as http:
        cloud = SpecializedCloudClient(client=http)
        with pytest.raises(CloudAuthenticationError):
            await cloud.login("rider@example.com", "wrong")


async def test_rejects_malformed_keystore_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api-sp.zone5cloud.com":
            return httpx.Response(200, json={"uuid": "application-id"})
        return httpx.Response(200, content=b"not-json")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        cloud = SpecializedCloudClient(
            client=http,
            token=CloudToken(access_token="access"),
        )
        with pytest.raises(CloudRequestError, match="valid JSON"):
            await cloud.get_wrapped_key(
                hmi_hardware="3.2.1",
                hmi_serial="123456789",
            )
