"""Tests for Cisco WLC registry cleanup helpers."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import device_registry as dr
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.const import DOMAIN
from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.registry import (
    _device_belongs_to_entry,
    async_get_device_by_identifier,
    async_cleanup_legacy_empty_ap_devices,
    async_register_controller_device,
    controller_device_link,
)

AP_MAC = "34:5d:a8:0a:2e:40"


class ModernDevice(SimpleNamespace):
    """Fail if cleanup touches the deprecated ownership property."""

    @property
    def config_entries(self):
        raise AssertionError("Deprecated config_entries was read")


class DeviceCollection(list):
    """Model the new collection, rejecting its deprecated mapping shim."""

    def values(self):
        raise AssertionError("Deprecated devices.values() was called")


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
    legacy_device = ModernDevice(
        id="legacy",
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, f"ap-{AP_MAC}")},
        connections={(dr.CONNECTION_NETWORK_MAC, AP_MAC)},
    )
    scoped_device = ModernDevice(
        id="scoped",
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, f"wlc.example.com_ap_{AP_MAC}")},
        connections=set(),
    )
    removed: list[str] = []
    device_registry = SimpleNamespace(
        devices=DeviceCollection([legacy_device, scoped_device]),
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


@pytest.mark.parametrize("owner", ["entry_ap", "other_entry", None])
def test_modern_device_ownership_never_reads_config_entries(owner) -> None:
    entry = _config_entry()
    device = ModernDevice(config_entry_id=owner)
    assert _device_belongs_to_entry(device, entry) == (owner == entry.entry_id)


def test_older_device_ownership_uses_config_entries() -> None:
    entry = _config_entry()
    assert _device_belongs_to_entry(
        SimpleNamespace(config_entries={entry.entry_id}), entry
    )
    assert not _device_belongs_to_entry(
        SimpleNamespace(config_entries={"other_entry"}), entry
    )


def test_device_lookup_is_scoped_to_entry() -> None:
    identifier = (DOMAIN, "client")
    device = ModernDevice(id="client_device", config_entry_id="entry_ap")
    registry = SimpleNamespace(
        async_get_device_by_identifier=Mock(return_value=device),
        async_get_device=Mock(side_effect=AssertionError("Deprecated lookup called")),
    )
    assert async_get_device_by_identifier(registry, identifier, "entry_ap") is device
    registry.async_get_device_by_identifier.assert_called_once_with(identifier, "entry_ap")
    registry.async_get_device.assert_not_called()


def test_older_device_lookup() -> None:
    identifier = (DOMAIN, "client")
    device = SimpleNamespace(id="client_device")
    registry = SimpleNamespace(async_get_device=Mock(return_value=device))
    assert async_get_device_by_identifier(registry, identifier, "entry_ap") is device
    registry.async_get_device.assert_called_once_with(identifiers={identifier})


def test_modern_controller_link_uses_registered_id() -> None:
    coordinator = SimpleNamespace(entry_id="entry_ap", controller_device_id="controller")
    with patch.object(dr, "async_get_device_id_by_identifier", new=object(), create=True):
        assert controller_device_link(coordinator) == {"via_device_id": "controller"}
        coordinator.controller_device_id = None
        assert controller_device_link(coordinator) == {}


def test_older_controller_link(monkeypatch) -> None:
    monkeypatch.delattr(dr, "async_get_device_id_by_identifier", raising=False)
    coordinator = SimpleNamespace(entry_id="entry_ap", controller_device_id="controller")
    assert controller_device_link(coordinator) == {"via_device": (DOMAIN, "entry_ap")}


async def test_controller_registered_before_platform_devices(hass) -> None:
    entry = _config_entry()
    entry.add_to_hass(hass)
    coordinator = _coordinator(hass, entry)
    async_register_controller_device(hass, coordinator)
    device = dr.async_get(hass).async_get(coordinator.controller_device_id)
    assert device is not None
    assert device.identifiers == {(DOMAIN, entry.entry_id)}
    assert _device_belongs_to_entry(device, entry)
    assert device.name == "Cisco 9800 WLC"
    # Reloads must reuse the controller identity.
    device_id = coordinator.controller_device_id
    async_register_controller_device(hass, coordinator)
    assert coordinator.controller_device_id == device_id


async def test_cleanup_with_home_assistant_registry(hass, caplog) -> None:
    entry = _config_entry()
    entry.add_to_hass(hass)
    other_entry = MockConfigEntry(domain=DOMAIN, entry_id="other_entry")
    other_entry.add_to_hass(hass)
    coordinator = _coordinator(hass, entry)
    coordinator.data = {"ap_devices": {AP_MAC: {"name": "Lab AP"}}}
    registry = dr.async_get(hass)
    legacy_identifier = (DOMAIN, f"ap-{AP_MAC}")
    legacy_device = registry.async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={legacy_identifier}
    )
    other_device = registry.async_get_or_create(
        config_entry_id=other_entry.entry_id,
        identifiers={(DOMAIN, "other_legacy_ap")},
        connections={(dr.CONNECTION_NETWORK_MAC, AP_MAC)},
    )
    scoped_device = registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, f"wlc.example.com_ap_{AP_MAC}")},
    )
    caplog.clear()

    await async_cleanup_legacy_empty_ap_devices(hass, coordinator, entry)

    assert registry.async_get(legacy_device.id) is None
    assert registry.async_get(scoped_device.id) is not None
    assert registry.async_get(other_device.id) is not None
    assert "deprecated" not in caplog.text.lower()


async def test_setup_registers_controller_before_forwarding_platforms(hass) -> None:
    from custom_components.cisco_9800_wlc import async_setup_entry

    entry = _config_entry()
    entry.add_to_hass(hass)

    async def check_controller(config_entry, platforms):
        coordinator = config_entry.runtime_data
        assert coordinator.controller_device_id is not None
        device = dr.async_get(hass).async_get(coordinator.controller_device_id)
        assert device is not None
        assert device.identifiers == {(DOMAIN, entry.entry_id)}

    with (
        patch.object(CiscoWLCUpdateCoordinator, "_start_enrich_worker"),
        patch.object(CiscoWLCUpdateCoordinator, "async_load_cached_status", new_callable=AsyncMock),
        patch.object(CiscoWLCUpdateCoordinator, "async_load_cached_clients", new_callable=AsyncMock),
        patch.object(CiscoWLCUpdateCoordinator, "async_config_entry_first_refresh", new_callable=AsyncMock),
        patch.object(hass.config_entries, "async_forward_entry_setups", side_effect=check_controller),
    ):
        assert await async_setup_entry(hass, entry)
