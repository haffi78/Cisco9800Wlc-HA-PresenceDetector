"""System health support for the Cisco 9800 WLC integration."""
from __future__ import annotations

from typing import Any, cast

from homeassistant.components import system_health
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import CiscoWLCUpdateCoordinator


def async_register(
    hass: HomeAssistant,
    registration: system_health.SystemHealthRegistration | None = None,
) -> None:
    """Register the system health info callback for this integration."""

    if registration is not None:
        registration.async_register_info(async_info)
    else:
        # Fallback for older Home Assistant cores that still expect manual registration
        system_health.async_register_info(hass, DOMAIN, async_info)


async def async_info(hass: HomeAssistant, config_entry: ConfigEntry | None = None) -> dict[str, Any]:
    """Return diagnostic information for system health."""

    coordinator: CiscoWLCUpdateCoordinator | None = None
    if config_entry is not None:
        coordinator = cast(
            CiscoWLCUpdateCoordinator | None,
            getattr(config_entry, "runtime_data", None),
        )

    if coordinator is None:
        for entry in hass.config_entries.async_entries(DOMAIN):
            maybe = cast(
                CiscoWLCUpdateCoordinator | None,
                getattr(entry, "runtime_data", None),
            )
            if isinstance(maybe, CiscoWLCUpdateCoordinator):
                coordinator = maybe
                break

    coordinators = [
        entry
        for entry in hass.config_entries.async_entries(DOMAIN)
        if isinstance(getattr(entry, "runtime_data", None), CiscoWLCUpdateCoordinator)
    ]
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
