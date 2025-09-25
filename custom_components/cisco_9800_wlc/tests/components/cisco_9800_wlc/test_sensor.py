"""Tests for Cisco WLC sensors."""
from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.const import DOMAIN
from custom_components.cisco_9800_wlc.sensor import CiscoWLCVersionSensor


async def test_version_sensor_native_value(hass) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_2",
        data={
            CONF_HOST: "wlc.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
    )

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, entry.data, entry.entry_id, entry.options)

    coordinator.data = {
        "wlc_status": {
            "software_version": "17.15.4",
            "software_version_raw": "17.15.4a",
        }
    }

    sensor = CiscoWLCVersionSensor(coordinator, entry)

    assert sensor.unique_id == "entry_2_software_version"
    assert sensor.entity_description.translation_key == "software_version"
    assert sensor.native_value == "17.15.4"
