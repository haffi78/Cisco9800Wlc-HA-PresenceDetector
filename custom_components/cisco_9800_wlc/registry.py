"""Home Assistant registry helpers for Cisco 9800 WLC entities."""
from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN
from .coordinator import CiscoWLCUpdateCoordinator
from .utils import build_ap_device_identifier, build_https_url

_LOGGER = logging.getLogger(__name__)


def async_register_controller_device(
    hass: HomeAssistant, coordinator: CiscoWLCUpdateCoordinator
) -> None:
    """Create the controller before platforms register devices linked to it."""

    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=coordinator.entry_id,
        identifiers={(DOMAIN, coordinator.entry_id)},
        name="Cisco 9800 WLC",
        manufacturer="Cisco",
        model="9800 Series Wireless Controller",
        configuration_url=build_https_url(coordinator.host),
    )
    coordinator.controller_device_id = device.id


def controller_device_link(coordinator: CiscoWLCUpdateCoordinator) -> dict[str, Any]:
    """Return parent-device metadata supported by the installed HA version."""

    if hasattr(dr, "async_get_device_id_by_identifier"):
        if coordinator.controller_device_id is None:
            return {}
        return {"via_device_id": coordinator.controller_device_id}
    # Older HA releases do not support via_device_id yet.
    return {"via_device": (DOMAIN, coordinator.entry_id)}


def async_get_device_by_identifier(
    device_registry: dr.DeviceRegistry,
    identifier: tuple[str, str],
    entry_id: str,
) -> Any:
    """Look up a device within its config entry, with support for older HA."""

    if lookup := getattr(device_registry, "async_get_device_by_identifier", None):
        return lookup(identifier, entry_id)
    return device_registry.async_get_device(identifiers={identifier})


def _registered_devices(device_registry: Any) -> Iterable[Any]:
    """Iterate modern device collections or older registry mappings."""

    devices = device_registry.devices
    if isinstance(devices, Mapping):
        return devices.values()
    return devices


def _ap_macs_from_coordinator(coordinator: CiscoWLCUpdateCoordinator) -> set[str]:
    """Return AP MACs currently known by the coordinator."""

    data = coordinator.data if isinstance(coordinator.data, dict) else {}
    macs: set[str] = set()
    for key in ("ap_devices", "ap_sensors"):
        records = data.get(key) if isinstance(data, dict) else {}
        if not isinstance(records, dict):
            continue
        macs.update(str(mac).lower() for mac in records if isinstance(mac, str))
    return macs


def _device_belongs_to_entry(device: Any, entry: ConfigEntry) -> bool:
    """Return whether a device registry entry belongs to the config entry."""

    if hasattr(device, "config_entry_id"):
        return device.config_entry_id == entry.entry_id
    # Only read the old multi-entry property when the new field is absent.
    return entry.entry_id in device.config_entries


def _device_has_entity(entity_registry: Any, device_id: str) -> bool:
    """Return whether any entity registry entry still points at the device."""

    return any(
        getattr(entity_entry, "device_id", None) == device_id
        for entity_entry in entity_registry.entities.values()
    )


def _has_scoped_ap_device(
    device_registry: Any,
    entry: ConfigEntry,
    scoped_identifier: tuple[str, str],
) -> bool:
    """Return whether the scoped AP device exists for this config entry."""

    return any(
        _device_belongs_to_entry(device, entry)
        and scoped_identifier in getattr(device, "identifiers", set())
        for device in _registered_devices(device_registry)
    )


async def async_cleanup_legacy_empty_ap_devices(
    hass: HomeAssistant,
    coordinator: CiscoWLCUpdateCoordinator,
    entry: ConfigEntry,
) -> None:
    """Remove empty legacy AP devices left behind by scoped AP identity migration."""

    await asyncio.sleep(0)
    await asyncio.sleep(0)

    ap_macs = _ap_macs_from_coordinator(coordinator)
    if not ap_macs:
        return

    device_registry = dr.async_get(hass)
    entity_registry = er.async_get(hass)
    remove_device = getattr(device_registry, "async_remove_device", None)
    if not callable(remove_device):
        return

    for mac in ap_macs:
        legacy_identifier = (DOMAIN, f"ap-{mac}")
        legacy_connection = (dr.CONNECTION_NETWORK_MAC, mac)
        scoped_identifier = (DOMAIN, build_ap_device_identifier(coordinator.host, mac))

        if not _has_scoped_ap_device(device_registry, entry, scoped_identifier):
            continue

        for device in list(_registered_devices(device_registry)):
            if not _device_belongs_to_entry(device, entry):
                continue
            identifiers = getattr(device, "identifiers", set())
            connections = getattr(device, "connections", set())
            if (
                legacy_identifier not in identifiers
                and legacy_connection not in connections
            ):
                continue
            if scoped_identifier in identifiers:
                continue
            if _device_has_entity(entity_registry, device.id):
                continue

            remove_device(device.id)
            _LOGGER.debug(
                "Removed empty legacy AP device %s for WLC entry %s",
                device.id,
                entry.entry_id,
            )
