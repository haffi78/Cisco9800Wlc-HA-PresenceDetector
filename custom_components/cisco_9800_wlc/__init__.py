from __future__ import annotations
import logging
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform

DOMAIN = "cisco_9800_wlc"
PLATFORMS = [Platform.DEVICE_TRACKER]
_LOGGER = logging.getLogger(__name__)

def setup(hass: HomeAssistant, config: dict) -> bool:
    _LOGGER.info("Setting up Cisco 9800 WLC integration")
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    _LOGGER.info("Asynchronous setup of Cisco 9800 WLC integration")
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.info("Setting up Cisco 9800 WLC entry")
    hass.data.setdefault(DOMAIN, {})
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.info("Unloading Cisco 9800 WLC entry")
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)