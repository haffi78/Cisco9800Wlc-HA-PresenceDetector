"""System health support for the Cisco 9800 WLC integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components import system_health
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import CiscoWLCUpdateCoordinator


async def async_register(hass: HomeAssistant) -> None:
    """Register the system health info callback for this integration."""

    system_health.async_register_info(hass, DOMAIN, async_info)


async def async_info(hass: HomeAssistant, config_entry: ConfigEntry | None = None) -> dict[str, Any]:
    """Return diagnostic information for system health."""

    domain_data = hass.data.get(DOMAIN, {})

    coordinator: CiscoWLCUpdateCoordinator | None = None
    if config_entry is not None:
        maybe = domain_data.get(config_entry.entry_id)
        if isinstance(maybe, CiscoWLCUpdateCoordinator):
            coordinator = maybe

    if coordinator is None:
        for value in domain_data.values():
            if isinstance(value, CiscoWLCUpdateCoordinator):
                coordinator = value
                break

    coordinators = [value for value in domain_data.values() if isinstance(value, CiscoWLCUpdateCoordinator)]
    info: dict[str, Any] = {"config_entries": len(coordinators)}

    if coordinator is None:
        info.update({
            "status": "not_initialized",
        })
        return info

    options = getattr(coordinator, "_options", {})
    last_success = getattr(coordinator, "last_update_success_time", None)
    enrich_pending = getattr(coordinator, "_enrich_pending", set()) or []

    info.update(
        {
            "host": getattr(coordinator, "host", "unknown"),
            "polling_disabled": bool(options.get("disable_polling", False)),
            "last_update_success": getattr(coordinator, "last_update_success", None),
            "last_update_success_time": last_success.isoformat() if last_success else None,
            "queued_enrichments": len(enrich_pending),
        }
    )

    return info
