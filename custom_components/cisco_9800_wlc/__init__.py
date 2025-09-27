from __future__ import annotations

import logging
from typing import cast

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .coordinator import CiscoWLCOperationError, CiscoWLCUpdateCoordinator
from .const import (
    ATTR_AP_MAC,
    ATTR_AP_NAME,
    ATTR_DURATION,
    ATTR_ENABLED,
    ATTR_ENTRY_ID,
    DOMAIN,
    SERVICE_SET_LED_FLASH,
    SERVICE_SET_LED_STATE,
)

PLATFORMS = [Platform.DEVICE_TRACKER, Platform.BINARY_SENSOR, Platform.SENSOR, Platform.BUTTON]
_LOGGER = logging.getLogger(__name__)

LED_STATE_SERVICE_SCHEMA = vol.All(
    cv.has_at_least_one_key(ATTR_AP_MAC, ATTR_AP_NAME),
    vol.Schema(
        {
            vol.Optional(ATTR_ENTRY_ID): cv.string,
            vol.Optional(ATTR_AP_MAC): cv.string,
            vol.Optional(ATTR_AP_NAME): cv.string,
            vol.Required(ATTR_ENABLED): cv.boolean,
        },
        extra=vol.PREVENT_EXTRA,
    ),
)

LED_FLASH_SERVICE_SCHEMA = vol.All(
    cv.has_at_least_one_key(ATTR_AP_MAC, ATTR_AP_NAME),
    vol.Schema(
        {
            vol.Optional(ATTR_ENTRY_ID): cv.string,
            vol.Optional(ATTR_AP_MAC): cv.string,
            vol.Optional(ATTR_AP_NAME): cv.string,
            vol.Required(ATTR_ENABLED): cv.boolean,
            vol.Optional(ATTR_DURATION): vol.All(vol.Coerce(int), vol.Range(min=0, max=3600)),
        },
        extra=vol.PREVENT_EXTRA,
    ),
)


def _get_coordinator_for_service(
    hass: HomeAssistant, entry_id: str | None
) -> CiscoWLCUpdateCoordinator:
    """Resolve the coordinator to use for a service call."""

    domain_data = hass.data.setdefault(DOMAIN, {})
    coordinators: dict[str, CiscoWLCUpdateCoordinator] = domain_data.get("coordinators", {})

    if not coordinators:
        raise HomeAssistantError("No Cisco 9800 WLC coordinators are available")

    if entry_id:
        coordinator = coordinators.get(entry_id)
        if not coordinator:
            raise HomeAssistantError(f"Cisco 9800 WLC entry_id {entry_id} not found")
        return coordinator

    if len(coordinators) == 1:
        return next(iter(coordinators.values()))

    raise HomeAssistantError(
        "Multiple Cisco 9800 WLC controllers configured; supply entry_id to target a specific one"
    )


def _register_services(hass: HomeAssistant) -> None:
    """Register Home Assistant services for the integration."""

    async def async_handle_set_led_state(call: ServiceCall) -> None:
        coordinator = _get_coordinator_for_service(hass, call.data.get(ATTR_ENTRY_ID))
        try:
            await coordinator.async_set_ap_led_state(
                ap_mac=call.data.get(ATTR_AP_MAC),
                ap_name=call.data.get(ATTR_AP_NAME),
                enabled=call.data[ATTR_ENABLED],
            )
        except CiscoWLCOperationError as err:
            raise HomeAssistantError(str(err)) from err

    async def async_handle_set_led_flash(call: ServiceCall) -> None:
        coordinator = _get_coordinator_for_service(hass, call.data.get(ATTR_ENTRY_ID))
        try:
            await coordinator.async_set_ap_led_flash(
                ap_mac=call.data.get(ATTR_AP_MAC),
                ap_name=call.data.get(ATTR_AP_NAME),
                enabled=call.data[ATTR_ENABLED],
                duration=call.data.get(ATTR_DURATION),
            )
        except CiscoWLCOperationError as err:
            raise HomeAssistantError(str(err)) from err

    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_LED_STATE,
        async_handle_set_led_state,
        schema=LED_STATE_SERVICE_SCHEMA,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_LED_FLASH,
        async_handle_set_led_flash,
        schema=LED_FLASH_SERVICE_SCHEMA,
    )


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle config option updates by reloading the entry."""

    _LOGGER.debug("Options updated for entry %s; reloading", entry.entry_id)
    await hass.config_entries.async_reload(entry.entry_id)

def setup(hass: HomeAssistant, config: dict) -> bool:
    _LOGGER.info("Setting up Cisco 9800 WLC integration (legacy setup)")
    hass.data.setdefault(
        DOMAIN,
        {"tracked_macs": {}, "coordinators": {}, "services_registered": False},
    )
    return True

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data.setdefault("tracked_macs", {})
    domain_data.setdefault("coordinators", {})
    domain_data.setdefault("services_registered", False)
    _LOGGER.info("Asynchronous setup of Cisco 9800 WLC integration")
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.info("Setting up Cisco 9800 WLC entry %s", entry.entry_id)

    # Ensure DOMAIN storage exists
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data.setdefault("tracked_macs", {})
    coordinators: dict[str, CiscoWLCUpdateCoordinator] = domain_data.setdefault("coordinators", {})

    # Create the coordinator
    coordinator = CiscoWLCUpdateCoordinator(
        hass,
        entry.data,
        entry.entry_id,
        entry.options,
    )

    # Load any cached client attributes before first refresh
    await coordinator.async_load_cached_status()
    await coordinator.async_load_cached_clients()

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    # Store runtime data on the entry for platform access
    entry.runtime_data = coordinator
    coordinators[entry.entry_id] = coordinator

    if not domain_data.get("services_registered"):
        _register_services(hass)
        domain_data["services_registered"] = True

    # Watch for options updates
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    # Forward the setup to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.info("Unloading Cisco 9800 WLC entry %s", entry.entry_id)
    coordinator = cast(CiscoWLCUpdateCoordinator | None, entry.runtime_data)
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        if isinstance(coordinator, CiscoWLCUpdateCoordinator):
            await coordinator.async_shutdown()
        tracked = hass.data[DOMAIN].get("tracked_macs")
        if isinstance(tracked, dict):
            tracked.pop(entry.entry_id, None)
        coordinators = hass.data[DOMAIN].get("coordinators", {})
        if isinstance(coordinators, dict):
            coordinators.pop(entry.entry_id, None)
            if not coordinators and hass.data[DOMAIN].get("services_registered"):
                hass.services.async_remove(DOMAIN, SERVICE_SET_LED_STATE)
                hass.services.async_remove(DOMAIN, SERVICE_SET_LED_FLASH)
                hass.data[DOMAIN]["services_registered"] = False
        entry.runtime_data = None
    return unloaded
