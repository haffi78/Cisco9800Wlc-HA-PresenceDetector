"""Binary sensor for Cisco 9800 WLC controller status."""
from __future__ import annotations

import logging
from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorDeviceClass
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo
from datetime import timedelta

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class CiscoWLCStatusBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Represents the online/offline connectivity of the Cisco WLC."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_should_poll = False

    def __init__(self, coordinator, config_entry):
        super().__init__(coordinator)
        self.config_entry = config_entry
        self._attr_name = "Cisco 9800 WLC"
        self._attr_unique_id = f"{DOMAIN}_controller_status"

    @property
    def is_on(self) -> bool:
        status = self.coordinator.data.get("wlc_status", {}) if isinstance(self.coordinator.data, dict) else {}
        return str(status.get("online_status", "Offline")).lower() == "online"

    @property
    def available(self) -> bool:
        # Always available; show connectivity via is_on
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
        _LOGGER.error("Failed to find WLC coordinator for entry %s. Aborting binary_sensor setup.", entry.entry_id)
        return

    # Fetch initial status and try a client refresh so connectivity is accurate ASAP
    await coordinator.fetch_wlc_status()
    await coordinator.async_request_refresh()

    async_add_entities([CiscoWLCStatusBinarySensor(coordinator, entry)])
