"""Sensor for Cisco 9800 WLC software version."""
from __future__ import annotations

import logging
from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo, EntityCategory

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class CiscoWLCVersionSensor(CoordinatorEntity, SensorEntity):
    """Shows the WLC software version."""

    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, config_entry):
        super().__init__(coordinator)
        self.config_entry = config_entry
        self._attr_name = "Cisco 9800 WLC Software Version"
        self._attr_unique_id = f"{DOMAIN}_software_version"

    @property
    def native_value(self):
        status = self.coordinator.data.get("wlc_status", {}) if isinstance(self.coordinator.data, dict) else {}
        return status.get("software_version", "n/a")

    @property
    def available(self) -> bool:
        # Keep available to present last-known version; shows "n/a" if unknown
        return True

    @property
    def device_info(self) -> DeviceInfo:
        status = self.coordinator.data.get("wlc_status", {}) if isinstance(self.coordinator.data, dict) else {}
        sw_raw = status.get("software_version_raw") or status.get("software_version", "n/a")
        return DeviceInfo(
            identifiers={(DOMAIN, self.config_entry.entry_id)},
            name="Cisco 9800 WLC",
            manufacturer="Cisco",
            model="9800 Series Wireless Controller",
            sw_version=sw_raw,
            configuration_url=f"https://{self.config_entry.data['host']}",
        )


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN].get(entry.entry_id)
    if not coordinator:
        _LOGGER.error("Failed to find WLC coordinator for entry %s. Aborting sensor setup.", entry.entry_id)
        return

    async_add_entities([CiscoWLCVersionSensor(coordinator, entry)])
