"""Tests for the Cisco WLC options flow."""
from __future__ import annotations

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResultType
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc import config_flow
from custom_components.cisco_9800_wlc.const import (
    CONF_DETAILED_MACS,
    CONF_IGNORE_SSL,
    CONF_SCAN_INTERVAL,
    DOMAIN,
)


class DummyCoordinator:
    def __init__(self) -> None:
        self.data = {
            "aa:bb:cc:dd:ee:ff": {"device-name": "Phone"},
            "bb:cc:dd:ee:ff:00": {"device-type": "Tablet"},
        }

    def get_registered_macs(self) -> set[str]:
        return {"aa:bb:cc:dd:ee:ff", "bb:cc:dd:ee:ff:00"}


async def test_options_flow_updates_detailed_macs(hass) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_1",
        data={
            CONF_HOST: "wlc.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
            CONF_IGNORE_SSL: False,
        },
        options={
            "enable_new_entities": False,
            CONF_DETAILED_MACS: ["aa:bb:cc:dd:ee:ff"],
            CONF_SCAN_INTERVAL: 120,
        },
        unique_id="wlc.example.com",
    )
    entry.add_to_hass(hass)
    entry.runtime_data = DummyCoordinator()

    init_result = await hass.config_entries.options.async_init(entry.entry_id)
    assert init_result["type"] is FlowResultType.FORM
    assert init_result["step_id"] == "init"

    result = await hass.config_entries.options.async_configure(
        init_result["flow_id"],
        {
            "enable_new_entities": True,
            CONF_SCAN_INTERVAL: 3,
            CONF_DETAILED_MACS: {
                "aa:bb:cc:dd:ee:ff": True,
                "bb:cc:dd:ee:ff:00": False,
            },
        },
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    options = result["data"]
    assert options["enable_new_entities"] is True
    assert options[CONF_DETAILED_MACS] == ["aa:bb:cc:dd:ee:ff"]
    assert options[CONF_SCAN_INTERVAL] == 5  # clamped to minimum
