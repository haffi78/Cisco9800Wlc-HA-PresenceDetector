"""Tests for Cisco WLC registry cleanup helpers."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import device_registry as dr
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.const import DOMAIN
from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.registry import (
    async_cleanup_legacy_empty_ap_devices,
)

AP_MAC = "34:5d:a8:0a:2e:40"


def _config_entry() -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_ap",
        data={
            CONF_HOST: "wlc.example.com",
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


async def test_cleanup_removes_empty_legacy_ap_device(hass) -> None:
    entry = _config_entry()
    coordinator = _coordinator(hass, entry)
    coordinator.data = {"ap_devices": {AP_MAC: {"name": "Lab AP"}}}
    legacy_device = SimpleNamespace(
        id="legacy",
        config_entry_id=entry.entry_id,
        config_entries={entry.entry_id},
        identifiers={(DOMAIN, f"ap-{AP_MAC}")},
        connections={(dr.CONNECTION_NETWORK_MAC, AP_MAC)},
    )
    scoped_device = SimpleNamespace(
        id="scoped",
        config_entry_id=entry.entry_id,
        config_entries={entry.entry_id},
        identifiers={(DOMAIN, f"wlc.example.com_ap_{AP_MAC}")},
        connections=set(),
    )
    removed: list[str] = []
    device_registry = SimpleNamespace(
        devices={"legacy": legacy_device, "scoped": scoped_device},
        async_remove_device=removed.append,
    )
    entity_registry = SimpleNamespace(entities={})

    with (
        patch(
            "custom_components.cisco_9800_wlc.registry.dr.async_get",
            return_value=device_registry,
        ),
        patch(
            "custom_components.cisco_9800_wlc.registry.er.async_get",
            return_value=entity_registry,
        ),
    ):
        await async_cleanup_legacy_empty_ap_devices(hass, coordinator, entry)

    assert removed == ["legacy"]


async def test_cleanup_keeps_legacy_ap_device_with_entities(hass) -> None:
    entry = _config_entry()
    coordinator = _coordinator(hass, entry)
    coordinator.data = {"ap_devices": {AP_MAC: {"name": "Lab AP"}}}
    legacy_device = SimpleNamespace(
        id="legacy",
        config_entry_id=entry.entry_id,
        config_entries={entry.entry_id},
        identifiers={(DOMAIN, f"ap-{AP_MAC}")},
        connections={(dr.CONNECTION_NETWORK_MAC, AP_MAC)},
    )
    scoped_device = SimpleNamespace(
        id="scoped",
        config_entry_id=entry.entry_id,
        config_entries={entry.entry_id},
        identifiers={(DOMAIN, f"wlc.example.com_ap_{AP_MAC}")},
        connections=set(),
    )
    removed: list[str] = []
    device_registry = SimpleNamespace(
        devices={"legacy": legacy_device, "scoped": scoped_device},
        async_remove_device=removed.append,
    )
    entity_registry = SimpleNamespace(
        entities={"sensor.ap_clients": SimpleNamespace(device_id="legacy")}
    )

    with (
        patch(
            "custom_components.cisco_9800_wlc.registry.dr.async_get",
            return_value=device_registry,
        ),
        patch(
            "custom_components.cisco_9800_wlc.registry.er.async_get",
            return_value=entity_registry,
        ),
    ):
        await async_cleanup_legacy_empty_ap_devices(hass, coordinator, entry)

    assert removed == []
