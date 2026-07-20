"""Tests for Cisco WLC AP button entities."""
from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.button import (
    CiscoWLCAPLEDFlashButton,
    CiscoWLCAPLEDSimpleButton,
    _ap_button_unique_id_migrations,
)
from custom_components.cisco_9800_wlc.const import DOMAIN
from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator

AP_MAC = "34:5d:a8:0a:2e:40"


def _config_entry(entry_id: str, host: str) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        entry_id=entry_id,
        data={
            CONF_HOST: host,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
    )


def _coordinator(hass, entry: MockConfigEntry) -> CiscoWLCUpdateCoordinator:
    with patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        return CiscoWLCUpdateCoordinator(hass, entry.data, entry.entry_id, entry.options)


async def test_ap_led_button_identity_is_scoped_for_multiple_wlc_hosts(hass) -> None:
    entry_a = _config_entry("entry_a", "wlc-a.example.com")
    entry_b = _config_entry("entry_b", "wlc-b.example.com")
    coordinator_a = _coordinator(hass, entry_a)
    coordinator_b = _coordinator(hass, entry_b)
    coordinator_a.data = {
        "ap_devices": {AP_MAC: {"name": "Lab AP", "ip_address": "192.0.2.10"}}
    }
    coordinator_b.data = {
        "ap_devices": {AP_MAC: {"name": "Lab AP", "ip_address": "192.0.2.11"}}
    }

    button_a = CiscoWLCAPLEDSimpleButton(coordinator_a, entry_a, AP_MAC, True)
    button_b = CiscoWLCAPLEDSimpleButton(coordinator_b, entry_b, AP_MAC, True)
    flash_button = CiscoWLCAPLEDFlashButton(
        coordinator_a,
        entry_a,
        AP_MAC,
        enable_flash=True,
        duration=60,
    )

    assert button_a.unique_id == f"wlc-a.example.com_ap_{AP_MAC}_led_on"
    assert button_b.unique_id == f"wlc-b.example.com_ap_{AP_MAC}_led_on"
    assert button_a.unique_id != button_b.unique_id
    assert flash_button.unique_id == (
        f"wlc-a.example.com_ap_{AP_MAC}_led_flash_start"
    )
    assert button_a.device_info["identifiers"] == {
        (DOMAIN, f"wlc-a.example.com_ap_{AP_MAC}")
    }
    assert button_b.device_info["identifiers"] == {
        (DOMAIN, f"wlc-b.example.com_ap_{AP_MAC}")
    }
    assert button_a.device_info["via_device"] == (DOMAIN, "entry_a")
    assert button_b.device_info["via_device"] == (DOMAIN, "entry_b")
    assert button_a.device_info["serial_number"] == AP_MAC
    assert button_b.device_info["serial_number"] == AP_MAC
    assert "connections" not in button_a.device_info
    assert "connections" not in button_b.device_info


async def test_ap_button_legacy_unique_id_migration_map(hass) -> None:
    entry = _config_entry("entry_a", "wlc-a.example.com")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {"ap_devices": {AP_MAC: {"name": "Lab AP"}}}

    migrations = _ap_button_unique_id_migrations(coordinator)

    assert migrations[f"{AP_MAC}_led_on"] == (
        f"wlc-a.example.com_ap_{AP_MAC}_led_on"
    )
    assert migrations[f"{AP_MAC}_led_off"] == (
        f"wlc-a.example.com_ap_{AP_MAC}_led_off"
    )
    assert migrations[f"{AP_MAC}_led_flash_start"] == (
        f"wlc-a.example.com_ap_{AP_MAC}_led_flash_start"
    )
    assert migrations[f"{AP_MAC}_led_flash_stop"] == (
        f"wlc-a.example.com_ap_{AP_MAC}_led_flash_stop"
    )
