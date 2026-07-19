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
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import UpdateFailed
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.coordinator import (
    INITIAL_ENRICH_DELAY_SECONDS,
    CiscoWLCUpdateCoordinator,
    _has_client_detail,
    _has_client_name,
    _is_meaningful,
)
from custom_components.cisco_9800_wlc.const import CONF_DETAILED_MACS, DOMAIN

FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "cisco_9800_wlc"
AP_MAC = "34:5d:a8:0a:2e:40"
AIR_QUALITY_LAST_UPDATE = "2026-07-19T09:12:49.248687+00:00"


def load_fixture(name: str) -> dict:
    """Load a sanitized Cisco WLC RESTCONF fixture."""

    path = FIXTURE_DIR / name
    if not path.exists():
        pytest.skip(f"Local Cisco WLC fixture is not present: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _temperature_payload(entries: list[dict] | None = None) -> dict:
    return {
        "Cisco-IOS-XE-wireless-access-point-oper:ap-temp": entries or []
    }


def test_cached_client_detail_detection() -> None:
    """Only meaningful enriched fields should mark cached clients as enriched."""

    assert _has_client_detail({"IP Address": "192.0.2.10"}) is False
    assert _has_client_detail({"device-name": "Kitchen iPhone"}) is True
    assert _is_meaningful("Unknown Device") is False
    assert _is_meaningful("Un-Classified Device") is True
    assert _has_client_detail({"device-name": "Unknown Device", "ssid": ""}) is False
    assert _has_client_detail({"device-name": "unknown", "ssid": ""}) is False
    assert _has_client_detail({"ssid": "Home"}) is True


def test_any_non_placeholder_device_name_is_real_client_name() -> None:
    """Only Cisco's explicit name placeholders should keep identity refreshes open."""

    assert _has_client_name({"device-name": "APPLE, INC."}) is True
    assert _has_client_name({"device-name": "Un-Classified Device"}) is True
    assert _has_client_name({"device-name": "Unknown"}) is False
    assert _has_client_name({"device-name": "Unknown Device"}) is False
    assert _has_client_name({"device-name": "blackey-iphone"}) is True


def test_identity_placeholder_observations_stop_after_initial_plus_five_retries(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Repeated Cisco Unknown Device names should stop identity retries."""

    mac = "94:89:78:89:36:11"
    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            "entry_identity_observations",
        )

    for _ in range(5):
        coordinator._record_identity_name_observation(mac, "Unknown Device")
    assert mac not in coordinator._identity_enrich_exhausted

    coordinator._record_identity_name_observation(mac, "Unknown Device")

    assert mac in coordinator._identity_enrich_exhausted


def test_identity_non_placeholder_name_observation_clears_retries(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Any non-placeholder Cisco device-name should be treated as final."""

    mac = "80:b9:89:7b:62:2d"
    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            "entry_identity_vendor_observations",
        )

    coordinator._identity_enrich_exhausted.add(mac)
    coordinator._identity_name_observations[mac] = [True, True]

    coordinator._record_identity_name_observation(
        mac,
        {
            "device-name": "APPLE, INC.",
            "device-os": "iPhone16,2",
            "day-zero-dc": "APPLE, INC.",
        },
    )

    assert mac not in coordinator._identity_enrich_exhausted
    assert mac not in coordinator._identity_name_observations


def _air_quality_payload(entries: list[dict] | None = None) -> dict:
    return {
        "Cisco-IOS-XE-wireless-access-point-oper:ap-air-quality": entries or []
    }


def _air_quality_entry(**values) -> dict:
    return {
        "ap-mac": AP_MAC,
        "last-update": AIR_QUALITY_LAST_UPDATE,
        **values,
    }


async def _fetch_air_quality(
    hass: HomeAssistant,
    coordinator_config: dict,
    entries: list[dict] | None,
) -> dict[str, dict]:
    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            "entry_air_quality",
        )

    coordinator._get = AsyncMock(
        side_effect=[
            (200, _temperature_payload(), None),
            (200, _air_quality_payload(entries), None),
        ]
    )

    return await coordinator._async_fetch_ap_environment()


class MockClientResponse:
    def __init__(self, status: int = 200, payload: dict | None = None) -> None:
        self.status = status
        self._payload = payload or {}
        self.charset = "utf-8"

    async def __aenter__(self) -> "MockClientResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def text(self) -> str:
        return json.dumps(self._payload)

    async def read(self) -> bytes:
        return json.dumps(self._payload).encode(self.charset)

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
                "ipv6-binding": {
                    "ip-key": [
                        {"ip-addr": "2001:db8::10"},
                        {"ip-addr": "2001:db8::11"},
                    ],
                },
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
    client_data = coordinator.data["aa:bb:cc:dd:ee:ff"]
    assert client_data["IP Address"] == "192.0.2.10"
    assert client_data["IPv4 Address"] == "192.0.2.10"
    assert client_data["IPv6 Address"] == "2001:db8::10"
    assert client_data["IPv6 Addresses"] == ["2001:db8::10", "2001:db8::11"]
    assert client_data["Connected to Controller"] == "wlc.example.com"
    mock_dispatch.assert_called_once()
    args = mock_dispatch.call_args[0]
    assert args[0] == hass
    assert args[1] == "cisco_9800_wlc_new_clients"
    assert "aa:bb:cc:dd:ee:ff" in args[3]


@pytest.mark.asyncio
async def test_enabled_tracker_does_not_trigger_recurring_detail_without_manual_selection(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Enabled presence trackers should not imply recurring detailed polling."""

    mac = "aa:bb:cc:dd:ee:ff"
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_presence_only",
        data=coordinator_config,
        options={},
        unique_id="wlc.example.com",
    )
    entry.add_to_hass(hass)
    er.async_get(hass).async_get_or_create(
        "device_tracker",
        DOMAIN,
        f"wlc.example.com_{mac}",
        suggested_object_id="client_presence_only",
        config_entry=entry,
    )

    response_payload = {
        "Cisco-IOS-XE-wireless-client-oper:sisf-db-mac": [
            {"mac-addr": mac}
        ]
    }
    mock_fetch = AsyncMock(return_value={"device-name": "Should Not Fetch"})

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([MockClientResponse(200, response_payload)]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_fetch_ap_environment",
        new=AsyncMock(return_value={}),
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_update_ap_devices",
        new=AsyncMock(return_value=None),
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_schedule_enrich_with_delay",
    ) as mock_schedule, patch.object(
        CiscoWLCUpdateCoordinator,
        "fetch_attributes",
        mock_fetch,
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            entry.entry_id,
            options={},
        )
        coordinator._last_version_fetch = datetime.now()
        data = await coordinator._async_update_data()

    mock_fetch.assert_not_called()
    mock_schedule.assert_called_once_with({mac}, INITIAL_ENRICH_DELAY_SECONDS)
    assert data[mac]["connected"] is True


@pytest.mark.asyncio
async def test_manual_detailed_selection_triggers_detail_polling(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Only MACs selected in detailed_macs should receive detailed polling."""

    mac = "aa:bb:cc:dd:ee:ff"
    response_payload = {
        "Cisco-IOS-XE-wireless-client-oper:sisf-db-mac": [
            {"mac-addr": mac}
        ]
    }
    mock_fetch = AsyncMock(return_value={"device-name": "Phone"})

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([MockClientResponse(200, response_payload)]),
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
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "fetch_attributes",
        mock_fetch,
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            "entry_detailed",
            options={CONF_DETAILED_MACS: [mac]},
        )
        coordinator._last_version_fetch = datetime.now()
        data = await coordinator._async_update_data()

    mock_fetch.assert_called_once_with(mac)
    assert data[mac]["device-name"] == "Phone"


@pytest.mark.asyncio
async def test_new_unselected_client_schedules_one_shot_enrichment_for_name(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Unselected clients should get one-shot enrichment for naming."""

    mac = "aa:bb:cc:dd:ee:ff"
    response_payload = {
        "Cisco-IOS-XE-wireless-client-oper:sisf-db-mac": [
            {"mac-addr": mac}
        ]
    }

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([MockClientResponse(200, response_payload)]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.async_dispatcher_send"
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_schedule_enrich_with_delay",
    ) as mock_schedule, patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_fetch_ap_environment",
        new=AsyncMock(return_value={}),
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_update_ap_devices",
        new=AsyncMock(return_value=None),
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            "entry_presence_new",
            options={CONF_DETAILED_MACS: []},
        )
        coordinator._last_version_fetch = datetime.now()
        data = await coordinator._async_update_data()

    mock_schedule.assert_called_once_with({mac}, INITIAL_ENRICH_DELAY_SECONDS)
    assert data[mac]["connected"] is True


@pytest.mark.asyncio
async def test_placeholder_client_name_schedules_one_shot_refresh(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Cached placeholder names should be refreshed without recurring detail polling."""

    mac = "94:89:78:89:36:11"
    response_payload = {
        "Cisco-IOS-XE-wireless-client-oper:sisf-db-mac": [
            {"mac-addr": mac}
        ]
    }

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([MockClientResponse(200, response_payload)]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_schedule_enrich_with_delay",
    ) as mock_schedule, patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_fetch_ap_environment",
        new=AsyncMock(return_value={}),
    ), patch.object(
        CiscoWLCUpdateCoordinator,
        "_async_update_ap_devices",
        new=AsyncMock(return_value=None),
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            "entry_placeholder_name",
            options={CONF_DETAILED_MACS: []},
        )
        coordinator.data = {
            mac: {
                "device-name": "Unknown Device",
                "ssid": "Home",
            }
        }
        coordinator._initial_enriched.add(mac)
        coordinator._announced_new_clients.add(mac)
        coordinator._last_version_fetch = datetime.now()

        data = await coordinator._async_update_data()

    mock_schedule.assert_called_once_with({mac}, INITIAL_ENRICH_DELAY_SECONDS)
    assert data[mac]["device-name"] == "Unknown Device"
    assert data[mac]["connected"] is True


def test_client_connection_attributes_prefers_non_link_local_ipv6(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure multi-address IPv6 bindings keep all addresses and prefer usable primary."""

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_ipv6")

    attrs = coordinator._client_connection_attributes(
        {
            "mac-addr": "aa:bb:cc:dd:ee:ff",
            "ipv6-binding": [
                {"ip-key": {"zone-id": 2147483658, "ip-addr": "fe80::1"}},
                {"ip-key": {"zone-id": 0, "ip-addr": "fd03:4856:c67c:42ad::10"}},
                {"ip-key": {"zone-id": 0}},
                {"ip-key": {"zone-id": 0, "ip-addr": "fd03:4856:c67c:42ad::11"}},
            ],
        }
    )

    assert attrs["IP Address"] == "fd03:4856:c67c:42ad::10"
    assert attrs["IPv4 Address"] is None
    assert attrs["IPv6 Address"] == "fd03:4856:c67c:42ad::10"
    assert attrs["IPv6 Addresses"] == [
        "fe80::1",
        "fd03:4856:c67c:42ad::10",
        "fd03:4856:c67c:42ad::11",
    ]
    assert attrs["Connected to Controller"] == "wlc.example.com"


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
async def test_ap_air_quality_full_payload_keeps_all_values(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure full AP air-quality payloads parse every supported numeric field."""

    payload = _air_quality_entry(
        iaq="2.24",
        tvoc="0.41",
        etoh="0.22",
        **{f"rmox-{index}": str(float(index + 1)) for index in range(13)},
    )

    sensors = await _fetch_air_quality(hass, coordinator_config, [payload])
    sensor_data = sensors[AP_MAC]

    assert sensor_data["iaq"] == 2.24
    assert sensor_data["tvoc"] == 0.41
    assert sensor_data["etoh"] == 0.22
    for index in range(13):
        assert sensor_data[f"rmox-{index}"] == float(index + 1)
    assert sensor_data["air_quality_last_update"] == AIR_QUALITY_LAST_UPDATE


@pytest.mark.asyncio
async def test_ap_air_quality_partial_iaq_without_tvoc(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure IAQ-only air-quality payloads do not invent missing values."""

    sensors = await _fetch_air_quality(
        hass,
        coordinator_config,
        [_air_quality_entry(iaq="1.25")],
    )

    sensor_data = sensors[AP_MAC]
    assert sensor_data["iaq"] == 1.25
    assert "tvoc" not in sensor_data
    assert "etoh" not in sensor_data


@pytest.mark.asyncio
async def test_ap_air_quality_partial_tvoc_without_etoh(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure TVOC-only air-quality payloads do not require EtOH."""

    sensors = await _fetch_air_quality(
        hass,
        coordinator_config,
        [_air_quality_entry(tvoc="0.41")],
    )

    sensor_data = sensors[AP_MAC]
    assert sensor_data["tvoc"] == 0.41
    assert "iaq" not in sensor_data
    assert "etoh" not in sensor_data


@pytest.mark.asyncio
async def test_ap_air_quality_numeric_zero_remains_valid(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure zero strings are parsed as real zero values, not missing data."""

    sensors = await _fetch_air_quality(
        hass,
        coordinator_config,
        [
            _air_quality_entry(
                iaq="0",
                tvoc="0.0",
                etoh=0,
                **{f"rmox-{index}": "0" for index in range(13)},
            )
        ],
    )

    sensor_data = sensors[AP_MAC]
    assert sensor_data["iaq"] == 0.0
    assert sensor_data["tvoc"] == 0.0
    assert sensor_data["etoh"] == 0.0
    for index in range(13):
        assert sensor_data[f"rmox-{index}"] == 0.0


@pytest.mark.asyncio
async def test_ap_air_quality_decimal_strings_convert_to_float(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure decimal strings are safely converted to floats."""

    sensors = await _fetch_air_quality(
        hass,
        coordinator_config,
        [
            _air_quality_entry(
                iaq="3.64",
                tvoc="1.98",
                etoh="1.05",
                **{"rmox-4": "1108295.13"},
            )
        ],
    )

    sensor_data = sensors[AP_MAC]
    assert sensor_data["iaq"] == 3.64
    assert sensor_data["tvoc"] == 1.98
    assert sensor_data["etoh"] == 1.05
    assert sensor_data["rmox-4"] == 1108295.13


@pytest.mark.asyncio
async def test_ap_air_quality_invalid_numeric_strings_are_missing(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure invalid numeric values are omitted instead of coerced to zero."""

    sensors = await _fetch_air_quality(
        hass,
        coordinator_config,
        [
            _air_quality_entry(
                iaq="",
                tvoc="not-a-number",
                etoh="NaN",
                **{
                    "rmox-0": "inf",
                    "rmox-1": " ",
                },
            )
        ],
    )

    sensor_data = sensors[AP_MAC]
    for key in ("iaq", "tvoc", "etoh", "rmox-0", "rmox-1"):
        assert key not in sensor_data


@pytest.mark.asyncio
async def test_ap_without_air_quality_record_has_no_air_quality_data(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Ensure absent AP air-quality records do not create sensor records."""

    sensors = await _fetch_air_quality(hass, coordinator_config, [])

    assert sensors == {}


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


@pytest.mark.asyncio
async def test_client_detail_keeps_six_previous_roams(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Roaming history should expose most recent plus six previous roams."""

    roaming_entries = [
        {
            "ap-name": f"AP-{index}",
            "ms-assoc-time": f"2026-04-25T12:{7 - index:02d}:00+00:00",
        }
        for index in range(8)
    ]
    fixtures = [
        {"Cisco-IOS-XE-wireless-client-oper:common-oper-data": [{"ap-name": "AP-0"}]},
        {
            "Cisco-IOS-XE-wireless-client-oper:dot11-oper-data": [
                {"current-channel": 6, "vap-ssid": "Home"}
            ]
        },
        {"Cisco-IOS-XE-wireless-client-oper:speed": 100},
        {
            "Cisco-IOS-XE-wireless-client-oper:mobility-history": {
                "entry": roaming_entries
            }
        },
        {"Cisco-IOS-XE-wireless-client-oper:dc-info": [{"device-name": "Phone"}]},
    ]

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_roams")

    coordinator._get = AsyncMock(
        side_effect=[(200, fixture, None) for fixture in fixtures]
    )

    attributes = await coordinator.fetch_attributes("aa:bb:cc:dd:ee:ff")

    assert attributes["most_recent_roam"].startswith("AP-0 at ")
    assert attributes["previous_roam_1"].startswith("AP-1 at ")
    assert attributes["previous_roam_6"].startswith("AP-6 at ")
    assert "previous_roam_7" not in attributes
    assert len(attributes["roaming_history"]) == 7
    assert attributes["roaming_history"][0].startswith("AP-0 at ")
    assert attributes["roaming_history"][6].startswith("AP-6 at ")


@pytest.mark.asyncio
async def test_fetch_attributes_refreshes_placeholder_device_name(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """A cached Unknown Device name should not suppress dc-info refreshes."""

    mac = "94:89:78:89:36:11"
    fixtures = [
        {"Cisco-IOS-XE-wireless-client-oper:common-oper-data": [{"ap-name": "AP-1"}]},
        {
            "Cisco-IOS-XE-wireless-client-oper:dot11-oper-data": [
                {"current-channel": 11, "vap-ssid": "Home"}
            ]
        },
        {"Cisco-IOS-XE-wireless-client-oper:speed": 100},
        {
            "Cisco-IOS-XE-wireless-client-oper:mobility-history": {
                "entry": []
            }
        },
        {
            "Cisco-IOS-XE-wireless-client-oper:dc-info": [
                {
                    "device-name": "Kitchen Tablet",
                    "device-type": "Tablet",
                    "device-os": "Android",
                    "protocol-map": (
                        "protocol-map-oui protocol-map-dhcp protocol-map-http"
                    ),
                    "confidence-level": 10,
                    "classified-time": "2026-07-19T17:10:00+00:00",
                    "day-zero-dc": "APPLE, INC.",
                    "device-vendor": "Apple",
                    "device-protocol": "DHCP",
                    "device-sub-version": "26.5",
                }
            ]
        },
    ]

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, coordinator_config, "entry_name")

    coordinator.data = {
        mac: {
            "device-name": "Unknown Device",
            "device-type": "Tablet",
            "device-os": "Android",
        }
    }
    coordinator._get = AsyncMock(
        side_effect=[(200, fixture, None) for fixture in fixtures]
    )

    attributes = await coordinator.fetch_attributes(mac)

    assert attributes["device-name"] == "Kitchen Tablet"
    assert (
        attributes["protocol-map"]
        == "protocol-map-oui protocol-map-dhcp protocol-map-http"
    )
    assert attributes["confidence-level"] == 10
    assert attributes["classified-time"] == "2026-07-19T17:10:00+00:00"
    assert attributes["day-zero-dc"] == "APPLE, INC."
    assert attributes["device-vendor"] == "Apple"
    assert attributes["device-protocol"] == "DHCP"
    assert attributes["device-sub-version"] == "26.5"
    assert coordinator.data[mac]["device-name"] == "Kitchen Tablet"
    assert any("dc-info=" in call.args[0] for call in coordinator._get.await_args_list)


@pytest.mark.asyncio
async def test_fetch_attributes_keeps_non_placeholder_device_name_as_final(
    hass: HomeAssistant, coordinator_config: dict
) -> None:
    """Any cached non-placeholder device-name should suppress dc-info refreshes."""

    mac = "80:b9:89:7b:62:2d"
    fixtures = [
        {"Cisco-IOS-XE-wireless-client-oper:common-oper-data": [{"ap-name": "AP-1"}]},
        {
            "Cisco-IOS-XE-wireless-client-oper:dot11-oper-data": [
                {"current-channel": 11, "vap-ssid": "Home"}
            ]
        },
        {"Cisco-IOS-XE-wireless-client-oper:speed": 100},
        {
            "Cisco-IOS-XE-wireless-client-oper:mobility-history": {
                "entry": []
            }
        },
    ]

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.async_get_clientsession",
        return_value=MockSession([]),
    ), patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(
            hass,
            coordinator_config,
            "entry_vendor_name",
        )

    coordinator.data = {
        mac: {
            "device-name": "APPLE, INC.",
            "device-type": "Apple-Device",
            "device-os": "iPhone16,2",
            "day-zero-dc": "APPLE, INC.",
        }
    }
    coordinator._get = AsyncMock(
        side_effect=[(200, fixture, None) for fixture in fixtures]
    )

    attributes = await coordinator.fetch_attributes(mac)

    assert "device-name" not in attributes
    assert coordinator.data[mac]["device-name"] == "APPLE, INC."
    assert not any(
        "dc-info=" in call.args[0] for call in coordinator._get.await_args_list
    )
