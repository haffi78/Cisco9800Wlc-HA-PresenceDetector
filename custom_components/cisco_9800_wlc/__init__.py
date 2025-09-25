from __future__ import annotations
import logging
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from .coordinator import CiscoWLCUpdateCoordinator
from .const import DOMAIN
from . import system_health
PLATFORMS = [Platform.DEVICE_TRACKER, Platform.BINARY_SENSOR, Platform.SENSOR]
_LOGGER = logging.getLogger(__name__)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle config option updates by reloading the entry."""

    _LOGGER.debug("Options updated for entry %s; reloading", entry.entry_id)
    await hass.config_entries.async_reload(entry.entry_id)

def setup(hass: HomeAssistant, config: dict) -> bool:
    _LOGGER.info("Setting up Cisco 9800 WLC integration (legacy setup)")
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    domain_data = hass.data.setdefault(DOMAIN, {})
    _LOGGER.info("Asynchronous setup of Cisco 9800 WLC integration")
    await system_health.async_register(hass)
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.info("Setting up Cisco 9800 WLC entry %s", entry.entry_id)

    # Ensure DOMAIN storage exists
    hass.data.setdefault(DOMAIN, {})

    # Create the coordinator
    coordinator = CiscoWLCUpdateCoordinator(
        hass,
        entry.data,
        entry.entry_id,
        entry.options,
    )

    # Load any cached client attributes before first refresh
    await coordinator.async_load_cached_clients()

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    # Store the coordinator in Home Assistant's data
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Watch for options updates
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    # Forward the setup to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.info("Unloading Cisco 9800 WLC entry %s", entry.entry_id)
    coordinator: CiscoWLCUpdateCoordinator | None = hass.data[DOMAIN].get(entry.entry_id)
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        if isinstance(coordinator, CiscoWLCUpdateCoordinator):
            await coordinator.async_shutdown()
        tracked = hass.data[DOMAIN].get("tracked_macs")
        if isinstance(tracked, dict):
            tracked.pop(entry.entry_id, None)
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
