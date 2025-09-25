from __future__ import annotations

import logging
import re
import aiohttp
import voluptuous as vol
from typing import Any, Mapping

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import entity_registry as er, config_validation as cv, selector
from .const import DOMAIN, CONF_IGNORE_SSL, CONF_DETAILED_MACS, CONF_SCAN_INTERVAL
from .coordinator import DEFAULT_SCAN_INTERVAL, CiscoWLCUpdateCoordinator

MAC_REGEX_COLON = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
MAC_REGEX_HYPHEN = re.compile(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$")
MAC_REGEX_CISCO = re.compile(r"^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): selector.TextSelector(),
        vol.Required(CONF_USERNAME): selector.TextSelector(),
        vol.Required(CONF_PASSWORD): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
        ),
        vol.Optional(CONF_IGNORE_SSL, default=False): selector.BooleanSelector(),
        vol.Optional("enable_new_entities", default=False): selector.BooleanSelector(),
    }
)


class CiscoWLConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cisco 9800 WLC."""

    VERSION = 1

    async def async_step_user(self, user_input: Mapping[str, Any] | None = None) -> FlowResult:
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            # Abort if this controller is already configured
            for existing_entry in self._async_current_entries():
                if existing_entry.data.get(CONF_HOST) == user_input[CONF_HOST]:
                    return self.async_abort(reason="already_configured")

            session = async_get_clientsession(
                self.hass,
                verify_ssl=not user_input.get(CONF_IGNORE_SSL, False),
            )
            url = f"https://{user_input[CONF_HOST]}/restconf/data"
            auth = aiohttp.BasicAuth(user_input[CONF_USERNAME], user_input[CONF_PASSWORD])
            headers = {"Accept": "application/yang-data+json"}

            try:
                async with session.get(url, auth=auth, headers=headers) as response:
                    _LOGGER.debug("WLC API Response Code: %s", response.status)

                    if response.status == 401:
                        errors["base"] = "invalid_auth"
                    elif response.status != 200:
                        errors["base"] = "cannot_connect"
                    else:
                        return self.async_create_entry(
                            title=user_input[CONF_HOST],
                            data=user_input,
                            options={
                                "enable_new_entities": user_input.get("enable_new_entities", False),
                                CONF_DETAILED_MACS: [],
                            },
                        )

            except aiohttp.ClientConnectorCertificateError:
                _LOGGER.error("SSL Certificate Verification Failed. Try enabling 'Ignore Self-Signed SSL'.")
                errors["base"] = "ssl_error"
            except aiohttp.ClientError as e:
                _LOGGER.error("Client error connecting to Cisco 9800 WLC: %s", e)
                errors["base"] = "cannot_connect"
            except Exception as e:
                _LOGGER.error("Unexpected error: %s", e)
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=DATA_SCHEMA,
            errors=errors,
            description_placeholders={
                "setup_hint": "Make sure RESTCONF is enabled on your WLC before proceeding.",
                "connection_hint": "Enter the connection details to your Cisco 9800 WLC.",
                "new_entities_hint": "Entities are disabled by default to avoid creating trackers automatically.",
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> CiscoWLCOptionsFlow:
        """Return the options flow to configure existing entries."""
        return CiscoWLCOptionsFlow(config_entry)


def normalize_mac(mac: str) -> str | None:
    """Normalize MAC strings to colon format for consistent storage."""
    candidate = (mac or "").strip().lower()
    if MAC_REGEX_COLON.match(candidate):
        return candidate
    if MAC_REGEX_HYPHEN.match(candidate):
        return candidate.replace("-", ":")
    if MAC_REGEX_CISCO.match(candidate):
        flattened = candidate.replace(".", "")
        return ":".join(flattened[i:i + 2] for i in range(0, 12, 2))
    return None


def _build_mac_options(
    hass: HomeAssistant,
    coordinator: CiscoWLCUpdateCoordinator | None,
    existing: list[str],
) -> dict[str, str]:
    """Construct selectable MAC options with friendly labels for the options flow."""
    macs: set[str] = set()
    for mac in existing:
        normalized = normalize_mac(mac)
        if normalized:
            macs.add(normalized)

    if coordinator and hasattr(coordinator, "get_registered_macs"):
        try:
            macs.update(coordinator.get_registered_macs())
        except Exception:  # pragma: no cover - defensive logging handled elsewhere
            _LOGGER.debug("Failed to read registered MACs from coordinator", exc_info=True)

    coordinator_data = getattr(coordinator, "data", {}) if coordinator else {}
    if isinstance(coordinator_data, dict):
        for mac in coordinator_data.keys():
            if mac == "wlc_status":
                continue
            normalized = normalize_mac(mac)
            if normalized:
                macs.add(normalized)

    # Fallback to entity registry to ensure all configured entities appear
    entity_registry = er.async_get(hass)
    for entry in entity_registry.entities.values():
        if entry.platform != DOMAIN or not entry.unique_id:
            continue
        normalized = normalize_mac(entry.unique_id)
        if normalized:
            macs.add(normalized)

    options: dict[str, str] = {}
    for mac in sorted(macs):
        label = mac
        details = coordinator_data.get(mac) if isinstance(coordinator_data, dict) else None
        if isinstance(details, dict):
            friendly = (
                details.get("device-name")
                or details.get("device-type")
                or details.get("device-os")
                or details.get("ssid")
            )
            if isinstance(friendly, str) and friendly.strip():
                label = f"{friendly.strip()} ({mac})"
        options[mac] = label
    return options


class CiscoWLCOptionsFlow(config_entries.OptionsFlow):
    """Handle the options flow for Cisco 9800 WLC."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(self, user_input: Mapping[str, Any] | None = None) -> FlowResult:
        """Present and process the options form."""
        current_enable_new = self._config_entry.options.get("enable_new_entities", False)
        stored_detailed: list[str] = self._config_entry.options.get(CONF_DETAILED_MACS, []) or []
        current_detailed = [mac for mac in (normalize_mac(m) for m in stored_detailed) if mac]
        current_interval = int(self._config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL.total_seconds()))

        coordinator = self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)
        mac_choices = _build_mac_options(self.hass, coordinator, current_detailed)

        if user_input is not None:
            detailed_selected = user_input.get(CONF_DETAILED_MACS, [])
            if isinstance(detailed_selected, dict):
                detailed_selected = [key for key, selected in detailed_selected.items() if selected]
            elif not isinstance(detailed_selected, list):
                detailed_selected = current_detailed

            normalized_selected = {
                normalized
                for mac in detailed_selected
                if (normalized := normalize_mac(mac))
            }

            try:
                interval_value = int(user_input.get(CONF_SCAN_INTERVAL, current_interval))
            except (ValueError, TypeError):
                interval_value = current_interval

            new_options = {
                "enable_new_entities": user_input.get("enable_new_entities", current_enable_new),
                CONF_DETAILED_MACS: sorted(normalized_selected),
                CONF_SCAN_INTERVAL: max(5, interval_value),
            }
            return self.async_create_entry(title="", data=new_options)

        if mac_choices:
            schema = vol.Schema(
                {
                    vol.Optional("enable_new_entities", default=current_enable_new): selector.BooleanSelector(),
                    vol.Optional(CONF_SCAN_INTERVAL, default=current_interval): vol.All(vol.Coerce(int), vol.Range(min=5, max=3600)),
                    vol.Optional(CONF_DETAILED_MACS, default=current_detailed): cv.multi_select(mac_choices),
                }
            )
        else:
            schema = vol.Schema(
                {
                    vol.Optional("enable_new_entities", default=current_enable_new): selector.BooleanSelector(),
                    vol.Optional(CONF_SCAN_INTERVAL, default=current_interval): vol.All(vol.Coerce(int), vol.Range(min=5, max=3600)),
                }
            )

        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            description_placeholders={
                "enable_new_entities_label": "Disable new Entities"
            },
        )
