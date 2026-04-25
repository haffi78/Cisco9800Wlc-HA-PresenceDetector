"""Tests for the Cisco 9800 WLC update coordinator."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.const import DOMAIN

FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "cisco_9800_wlc"


def load_fixture(name: str) -> dict:
    """Load a sanitized Cisco WLC RESTCONF fixture."""

    path = FIXTURE_DIR / name
    if not path.exists():
        pytest.skip(f"Local Cisco WLC fixture is not present: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


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


@pytest.mark.asyncio
async def test_ap_metadata_uses_local_fixture_payloads(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure AP telemetry from local captures stays numeric after polling."""

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_3")

    coordinator._get = AsyncMock(
        side_effect=[
            (200, load_fixture("ap_join_stats.json"), None),
            (200, load_fixture("access_point_oper_data.json"), None),
        ]
    )

    devices = await coordinator._async_fetch_ap_metadata()

    assert devices
    devices_with_radios = [
        device for device in devices.values()
        if isinstance(device.get("radios"), dict) and device["radios"]
    ]
    assert devices_with_radios

    for device in devices_with_radios:
        assert isinstance(device["client_count"], int)
        assert isinstance(device["clients_24ghz"], int)
        assert isinstance(device["clients_5ghz"], int)
        assert isinstance(device["clients_6ghz"], int)

    for device in devices_with_radios:
        for slot_info in device["radios"].values():
            assert isinstance(slot_info, dict)
            assert isinstance(slot_info.get("client_count"), int)
            for key in ("channel", "channel_width_mhz", "tx_power_dbm"):
                if key in slot_info:
                    assert isinstance(slot_info[key], (int, float))

    sample_device = devices_with_radios[0]
    for slot_info in sample_device["radios"].values():
        for key in ("channel", "channel_width_mhz", "tx_power_dbm", "client_count"):
            if key in slot_info:
                assert slot_info[key] == int(slot_info[key])


@pytest.mark.asyncio
async def test_ap_environment_uses_realistic_fixture_payloads(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure environmental payloads keep numeric sensor values."""

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_4")

    coordinator._get = AsyncMock(
        side_effect=[
            (200, load_fixture("ap_temperature.json"), None),
            (200, load_fixture("ap_air_quality.json"), None),
        ]
    )

    sensors = await coordinator._async_fetch_ap_environment()

    assert sensors
    for sensor_data in sensors.values():
        if "temperature" in sensor_data:
            assert isinstance(sensor_data["temperature"], float)
        if "humidity" in sensor_data:
            assert isinstance(sensor_data["humidity"], float)
        if "iaq" in sensor_data:
            assert isinstance(sensor_data["iaq"], float)
        if "tvoc" in sensor_data:
            assert isinstance(sensor_data["tvoc"], float)


@pytest.mark.asyncio
async def test_client_list_uses_local_fixture_payload(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure the captured client list payload can drive the main poll path."""

    payload = load_fixture("client_list.json")
    session = MockSession([MockClientResponse(200, payload)])

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=session,
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.async_dispatcher_send"
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_fetch_ap_environment",
        new=AsyncMock(return_value={}),
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_update_ap_devices",
        new=AsyncMock(return_value=None),
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_5")
        coordinator._last_version_fetch = datetime.now()
        data = await coordinator._async_update_data()

    assert isinstance(data, dict)
    assert data["wlc_status"]["online_status"] == "Online"


@pytest.mark.asyncio
async def test_wlc_status_uses_local_fixture_payload(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure the captured controller software version payload parses."""

    payload = load_fixture("software_version.json")
    session = MockSession([MockClientResponse(200, payload)])

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=session,
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_6")
        await coordinator.fetch_wlc_status()

    status = coordinator.data.get("wlc_status", {})
    assert isinstance(status, dict)
    assert status.get("software_version")
    assert status.get("software_version_raw")


@pytest.mark.asyncio
async def test_client_detail_uses_local_fixture_payloads(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure captured per-client detailed telemetry payloads can be parsed."""

    fixtures = [
        load_fixture("client_common_oper_data.json"),
        load_fixture("client_dot11_oper_data.json"),
        load_fixture("client_speed.json"),
        load_fixture("client_roaming_history.json"),
        load_fixture("client_dc_info.json"),
        load_fixture("client_dot11_oper_data.json"),
    ]

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_7")

    coordinator._get = AsyncMock(
        side_effect=[(200, fixture, None) for fixture in fixtures]
    )

    attributes = await coordinator.fetch_attributes("aa:bb:cc:dd:ee:ff")

    assert isinstance(attributes, dict)
    assert coordinator._get.call_count >= 5
