"""Binary sensor for Cisco 9800 WLC controller status."""
from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import cast

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CiscoWLCUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


@dataclass
class CiscoWLCBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes a Cisco WLC binary sensor."""


BINARY_SENSOR_DESCRIPTION = CiscoWLCBinarySensorEntityDescription(
    key="controller_status",
    translation_key="controller_status",
    device_class=BinarySensorDeviceClass.CONNECTIVITY,
)


class CiscoWLCStatusBinarySensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], BinarySensorEntity
):
    """Represents the online/offline connectivity of the Cisco WLC."""

    entity_description = BINARY_SENSOR_DESCRIPTION
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CiscoWLCUpdateCoordinator, config_entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_controller_status"
        self._attr_name = None

    @property
    def is_on(self) -> bool:
        status = (
            self.coordinator.data.get("wlc_status", {})
            if isinstance(self.coordinator.data, dict)
            else {}
        )
        return str(status.get("online_status", "offline")).lower() == "online"

    @property
    def available(self) -> bool:
        return bool(self.coordinator.last_update_success)

    @property
    def device_info(self) -> DeviceInfo:
        status = (
            self.coordinator.data.get("wlc_status", {})
            if isinstance(self.coordinator.data, dict)
            else {}
        )
        sw_raw = status.get("software_version_raw") or status.get(
            "software_version", "n/a"
        )
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name="Cisco 9800 WLC",
            manufacturer="Cisco",
            model="9800 Series Wireless Controller",
            sw_version=sw_raw,
            configuration_url=f"https://{self._entry.data['host']}",
        )


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:
    coordinator = cast(CiscoWLCUpdateCoordinator | None, entry.runtime_data)
    if not coordinator:
        _LOGGER.error(
            "Failed to find WLC coordinator for entry %s. Aborting binary_sensor setup.",
            entry.entry_id,
        )
        return

    await coordinator.fetch_wlc_status()
    await coordinator.async_request_refresh()

    async_add_entities([CiscoWLCStatusBinarySensor(coordinator, entry)])
