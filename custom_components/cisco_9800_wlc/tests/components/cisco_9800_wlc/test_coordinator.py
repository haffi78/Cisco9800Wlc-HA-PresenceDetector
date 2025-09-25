"""Tests for the Cisco 9800 WLC update coordinator."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.const import DOMAIN


class MockClientResponse:
    def __init__(self, status: int = 200, payload: dict | None = None) -> None:
        self.status = status
        self._payload = payload or {}

    async def __aenter__(self) -> "MockClientResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def text(self) -> str:
        return json.dumps(self._payload)

    async def json(self) -> dict:
        return self._payload


class MockSession:
    def __init__(self, responses: list[MockClientResponse | Exception]) -> None:
        self._responses = responses
        self.closed = False

    def get(self, *args, **kwargs):
        if not self._responses:
            raise AssertionError("No queued response for session.get")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def coordinator_config() -> dict:
    return {
        CONF_HOST: "wlc.example.com",
        CONF_USERNAME: "admin",
        CONF_PASSWORD: "secret",
    }


@pytest.mark.asyncio
async def test_coordinator_refresh_discovers_new_client(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure coordinator publishes signal when a new client is discovered."""

    response_payload = {
        "Cisco-IOS-XE-wireless-client-oper:sisf-db-mac": [
            {
                "mac-addr": "aa:bb:cc:dd:ee:ff",
                "ipv4-binding": {"ip-key": {"ip-addr": "192.0.2.10"}},
            }
        ]
    }
    session = MockSession([MockClientResponse(200, response_payload)])

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=session,
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.async_dispatcher_send"
    ) as mock_dispatch:
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_1")
        await coordinator.async_config_entry_first_refresh()

    assert "aa:bb:cc:dd:ee:ff" in coordinator.data
    mock_dispatch.assert_called_once()
    args = mock_dispatch.call_args[0]
    assert args[0] == hass
    assert args[1] == "cisco_9800_wlc_new_clients"
    assert "aa:bb:cc:dd:ee:ff" in args[3]


@pytest.mark.asyncio
async def test_coordinator_refresh_timeout_raises_update_failed(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure timeouts are wrapped in UpdateFailed."""

    session = MockSession([asyncio.TimeoutError()])

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=session,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_2")
        with pytest.raises(UpdateFailed):
            await coordinator._async_update_data()
