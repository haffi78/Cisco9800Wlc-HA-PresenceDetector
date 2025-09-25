"""Sensor for Cisco 9800 WLC software version."""
from __future__ import annotations

from dataclasses import dataclass
import logging

from typing import cast

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CiscoWLCUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


@dataclass
class CiscoWLCSensorEntityDescription(SensorEntityDescription):
    """Describes a Cisco WLC sensor."""


VERSION_DESCRIPTION = CiscoWLCSensorEntityDescription(
    key="software_version",
    translation_key="software_version",
    entity_category=EntityCategory.DIAGNOSTIC,
)


class CiscoWLCVersionSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Shows the WLC software version."""

    entity_description = VERSION_DESCRIPTION
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CiscoWLCUpdateCoordinator, config_entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._attr_unique_id = f"{config_entry.entry_id}_{self.entity_description.key}"

    @property
    def native_value(self) -> str:
        status = (
            self.coordinator.data.get("wlc_status", {})
            if isinstance(self.coordinator.data, dict)
            else {}
        )
        return status.get("software_version", "n/a")

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
            "Failed to find WLC coordinator for entry %s. Aborting sensor setup.",
            entry.entry_id,
        )
        return

    async_add_entities([CiscoWLCVersionSensor(coordinator, entry)])
