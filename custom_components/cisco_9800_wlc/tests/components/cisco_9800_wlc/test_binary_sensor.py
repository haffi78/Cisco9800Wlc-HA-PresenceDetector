"""Tests for the Cisco WLC binary sensor."""
from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.binary_sensor import (
    CiscoWLCStatusBinarySensor,
)
from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.const import DOMAIN


async def test_status_binary_sensor_is_on(hass) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_1",
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

    coordinator.data = {"wlc_status": {"online_status": "Online"}}

    sensor = CiscoWLCStatusBinarySensor(coordinator, entry)

    assert sensor.unique_id == "entry_1_controller_status"
    assert sensor.entity_description.translation_key == "controller_status"
    assert sensor.is_on
