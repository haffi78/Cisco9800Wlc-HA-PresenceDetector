"""Tests for the Cisco 9800 WLC config flow."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.cisco_9800_wlc.const import (
    CONF_DETAILED_MACS,
    CONF_IGNORE_SSL,
    DOMAIN,
)


@pytest.fixture
def mock_session() -> AsyncMock:
    """Return a mocked aiohttp session."""
    session = AsyncMock()
    response = AsyncMock()
    response.__aenter__.return_value = response
    response.__aexit__.return_value = False
    session.get.return_value = response
    return session


async def test_form_success(hass: HomeAssistant, mock_session: AsyncMock) -> None:
    """Test we successfully create an entry when credentials work."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": config_entries.SOURCE_USER},
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"

    mock_session.get.return_value.status = 200

    with patch(
        "custom_components.cisco_9800_wlc.config_flow.async_get_clientsession",
        return_value=mock_session,
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "wlc.example.com",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
                CONF_IGNORE_SSL: True,
                "enable_new_entities": True,
            },
        )

    assert result2["type"] is FlowResultType.CREATE_ENTRY
    assert result2["title"] == "wlc.example.com"
    assert result2["data"][CONF_HOST] == "wlc.example.com"
    assert result2["options"]["enable_new_entities"] is True
    assert result2["options"][CONF_DETAILED_MACS] == []


async def test_form_invalid_auth(hass: HomeAssistant, mock_session: AsyncMock) -> None:
    """Test invalid credentials show an error."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": config_entries.SOURCE_USER},
    )
    assert result["type"] is FlowResultType.FORM

    mock_session.get.return_value.status = 401

    with patch(
        "custom_components.cisco_9800_wlc.config_flow.async_get_clientsession",
        return_value=mock_session,
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "wlc.example.com",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
            },
        )

    assert result2["type"] is FlowResultType.FORM
    assert result2["errors"] == {"base": "invalid_auth"}


async def test_form_cannot_connect(hass: HomeAssistant, mock_session: AsyncMock) -> None:
    """Test other HTTP errors show cannot_connect."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": config_entries.SOURCE_USER},
    )
    assert result["type"] is FlowResultType.FORM

    mock_session.get.return_value.status = 500

    with patch(
        "custom_components.cisco_9800_wlc.config_flow.async_get_clientsession",
        return_value=mock_session,
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "wlc.example.com",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
            },
        )

    assert result2["type"] is FlowResultType.FORM
    assert result2["errors"] == {"base": "cannot_connect"}
