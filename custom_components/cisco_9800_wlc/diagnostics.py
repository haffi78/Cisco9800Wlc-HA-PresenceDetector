"""Diagnostics support for the Cisco 9800 WLC integration."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from .const import DOMAIN, CONF_DETAILED_MACS
from .coordinator import CiscoWLCUpdateCoordinator

TO_REDACT = {
    CONF_USERNAME,
    CONF_PASSWORD,
    "username",
    "attributes_updated",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""

    coordinator = cast(CiscoWLCUpdateCoordinator | None, entry.runtime_data)
    if coordinator is None:
        return {"controller": {"status": "not_loaded"}}
    coordinator_data = coordinator.data if isinstance(coordinator.data, dict) else {}

    clients: dict[str, Any] = {}
    for mac, attrs in coordinator_data.items():
        if mac == "wlc_status" or not isinstance(attrs, Mapping):
            continue
        clients[mac] = dict(attrs)

    payload: dict[str, Any] = {
        "controller": {
            "host": coordinator.host,
            "polling_disabled": coordinator._polling_disabled(),
            "scan_interval_seconds": (
                coordinator.update_interval.total_seconds()
                if coordinator.update_interval
                else None
            ),
        },
        "entry": {
            "title": entry.title,
            "data": dict(entry.data),
            "options": dict(entry.options),
            "detailed_macs": entry.options.get(CONF_DETAILED_MACS, []),
        },
        "wlc_status": coordinator_data.get("wlc_status", {}),
        "client_count": len(clients),
        "clients": clients,
    }

    return async_redact_data(payload, TO_REDACT)
