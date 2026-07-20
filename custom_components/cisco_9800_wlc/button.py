"""Button entities for Cisco 9800 WLC access-point LED controls."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.button import DOMAIN as BUTTON_DOMAIN, ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CiscoWLCUpdateCoordinator
from .registry import async_cleanup_legacy_empty_ap_devices
from .utils import build_ap_device_identifier, build_ap_unique_id, build_https_url

_LOGGER = logging.getLogger(__name__)

DEFAULT_FLASH_DURATION = 60


def _ap_button_unique_id_migrations(
    coordinator: CiscoWLCUpdateCoordinator,
) -> dict[str, str]:
    """Return legacy AP button unique IDs mapped to WLC-scoped IDs."""

    data = coordinator.data if isinstance(coordinator.data, dict) else {}
    devices = data.get("ap_devices") if isinstance(data, dict) else {}
    if not isinstance(devices, dict):
        return {}

    migrations: dict[str, str] = {}
    for mac, info in devices.items():
        if not isinstance(mac, str) or not isinstance(info, dict):
            continue
        for key in ("led_on", "led_off", "led_flash_start", "led_flash_stop"):
            migrations[f"{mac}_{key}".lower()] = build_ap_unique_id(
                coordinator.host,
                mac,
                key,
            )
    return migrations


def _async_migrate_ap_button_unique_ids(
    hass: HomeAssistant,
    coordinator: CiscoWLCUpdateCoordinator,
    entry: ConfigEntry,
) -> None:
    """Move legacy MAC-only AP button unique IDs to WLC-scoped unique IDs."""

    migrations = _ap_button_unique_id_migrations(coordinator)
    if not migrations:
        return

    entity_registry = er.async_get(hass)
    for entity_entry in list(entity_registry.entities.values()):
        if (
            entity_entry.platform != DOMAIN
            or entity_entry.config_entry_id != entry.entry_id
            or not entity_entry.entity_id.startswith(f"{BUTTON_DOMAIN}.")
            or not entity_entry.unique_id
        ):
            continue
        uid = entity_entry.unique_id.lower()
        scoped_uid = migrations.get(uid)
        if not scoped_uid or uid == scoped_uid:
            continue
        if entity_registry.async_get_entity_id(BUTTON_DOMAIN, DOMAIN, scoped_uid):
            continue
        entity_registry.async_update_entity(
            entity_entry.entity_id,
            new_unique_id=scoped_uid,
        )


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: CiscoWLCUpdateCoordinator | None = entry.runtime_data
    if not coordinator:
        _LOGGER.error(
            "Failed to find WLC coordinator for entry %s. Aborting button setup.",
            entry.entry_id,
        )
        return

    _async_migrate_ap_button_unique_ids(hass, coordinator, entry)

    known: set[str] = set()

    def _schedule_legacy_ap_cleanup() -> None:
        hass.async_create_task(
            async_cleanup_legacy_empty_ap_devices(hass, coordinator, entry)
        )

    def _async_add_ap_buttons() -> None:
        data = coordinator.data if isinstance(coordinator.data, dict) else {}
        devices = data.get("ap_devices") if isinstance(data, dict) else {}
        if not isinstance(devices, dict):
            return

        new_entities: list[ButtonEntity] = []

        for mac, info in devices.items():
            if not isinstance(info, dict):
                continue

            for description, factory in (
                ("led_on", lambda: CiscoWLCAPLEDSimpleButton(coordinator, entry, mac, True)),
                ("led_off", lambda: CiscoWLCAPLEDSimpleButton(coordinator, entry, mac, False)),
                (
                    "led_flash_start",
                    lambda: CiscoWLCAPLEDFlashButton(
                        coordinator,
                        entry,
                        mac,
                        enable_flash=True,
                        duration=DEFAULT_FLASH_DURATION,
                    ),
                ),
                (
                    "led_flash_stop",
                    lambda: CiscoWLCAPLEDFlashButton(
                        coordinator,
                        entry,
                        mac,
                        enable_flash=False,
                        duration=None,
                    ),
                ),
            ):
                unique_id = build_ap_unique_id(coordinator.host, mac, description)
                if unique_id in known:
                    continue
                entity = factory()
                new_entities.append(entity)
                known.add(unique_id)

        if new_entities:
            async_add_entities(new_entities)
        _schedule_legacy_ap_cleanup()

    _async_add_ap_buttons()
    coordinator.async_add_listener(_async_add_ap_buttons)


class _BaseAPButton(CoordinatorEntity[CiscoWLCUpdateCoordinator], ButtonEntity):
    """Common helpers for AP button entities."""

    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: CiscoWLCUpdateCoordinator, entry: ConfigEntry, ap_mac: str) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._ap_mac = ap_mac

    def _ap_record(self) -> dict[str, Any]:
        data = self.coordinator.data if isinstance(self.coordinator.data, dict) else {}
        devices = data.get("ap_devices") if isinstance(data, dict) else {}
        if not isinstance(devices, dict):
            return {}
        record = devices.get(self._ap_mac)
        return record if isinstance(record, dict) else {}

    @property
    def device_info(self) -> DeviceInfo:
        record = self._ap_record()
        config_url = None
        ip_address = record.get("ip_address")
        if isinstance(ip_address, str) and ip_address:
            config_url = build_https_url(ip_address)
        friendly_name = record.get("name") or f"AP {self._ap_mac.upper()}"
        return DeviceInfo(
            identifiers={
                (
                    DOMAIN,
                    build_ap_device_identifier(self.coordinator.host, self._ap_mac),
                )
            },
            name=friendly_name,
            manufacturer="Cisco",
            model=record.get("model"),
            serial_number=record.get("serial_number") or self._ap_mac,
            suggested_area=record.get("location"),
            configuration_url=config_url,
            via_device=(DOMAIN, self._entry.entry_id),
        )


class CiscoWLCAPLEDSimpleButton(_BaseAPButton):
    """Button that sets the steady LED state."""

    def __init__(self, coordinator: CiscoWLCUpdateCoordinator, entry: ConfigEntry, ap_mac: str, turn_on: bool) -> None:
        super().__init__(coordinator, entry, ap_mac)
        action = "On" if turn_on else "Off"
        self._attr_name = f"AP LED {action}"
        self._attr_unique_id = build_ap_unique_id(
            coordinator.host,
            ap_mac,
            f"led_{action.lower()}",
        )
        self._turn_on = turn_on

    async def async_press(self) -> None:
        record = self._ap_record()
        await self.coordinator.async_set_ap_led_state(
            ap_mac=self._ap_mac,
            ap_name=record.get("name"),
            enabled=self._turn_on,
        )


class CiscoWLCAPLEDFlashButton(_BaseAPButton):
    """Button that starts or stops LED flashing."""

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        entry: ConfigEntry,
        ap_mac: str,
        *,
        enable_flash: bool,
        duration: int | None,
    ) -> None:
        super().__init__(coordinator, entry, ap_mac)
        self._enable_flash = enable_flash
        self._duration = duration
        action = "Start" if enable_flash else "Stop"
        self._attr_name = f"AP LED Flash {action}"
        self._attr_unique_id = build_ap_unique_id(
            coordinator.host,
            ap_mac,
            f"led_flash_{action.lower()}",
        )

    async def async_press(self) -> None:
        record = self._ap_record()
        await self.coordinator.async_set_ap_led_flash(
            ap_mac=self._ap_mac,
            ap_name=record.get("name"),
            enabled=self._enable_flash,
            duration=self._duration,
        )
