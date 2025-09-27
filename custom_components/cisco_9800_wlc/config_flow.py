from __future__ import annotations

import asyncio
import logging
import re
import aiohttp
import voluptuous as vol
from typing import Any, Mapping, cast

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import entity_registry as er, config_validation as cv, selector
from homeassistant.helpers.translation import async_get_translations
from .const import (
    DOMAIN,
    CONF_IGNORE_SSL,
    CONF_DETAILED_MACS,
    CONF_SCAN_INTERVAL,
    CONF_AP_DETAIL_INTERVAL,
    DEFAULT_AP_DETAIL_INTERVAL,
)
from .coordinator import DEFAULT_SCAN_INTERVAL, CiscoWLCUpdateCoordinator

MAC_REGEX_COLON = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
MAC_REGEX_HYPHEN = re.compile(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$")
MAC_REGEX_CISCO = re.compile(r"^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")

_LOGGER = logging.getLogger(__name__)


class CiscoWLCFlowError(Exception):
    """Base exception for config flow validation."""


class CannotConnect(CiscoWLCFlowError):
    """Raised when the controller cannot be reached."""


class InvalidAuth(CiscoWLCFlowError):
    """Raised when authentication fails."""


class SSLError(CiscoWLCFlowError):
    """Raised when certificate validation fails."""


class UnknownError(CiscoWLCFlowError):
    """Raised for unexpected failures."""

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

    def __init__(self) -> None:
        self._pending_reauth_entry_id: str | None = None
        self._pending_reauth_entry: ConfigEntry | None = None
        self._reauth_defaults: dict[str, Any] = {}

    async def _async_validate_credentials(
        self,
        *,
        host: str,
        username: str,
        password: str,
        ignore_ssl: bool,
    ) -> None:
        """Validate that the provided credentials can reach the controller."""

        session = async_get_clientsession(
            self.hass,
            verify_ssl=not ignore_ssl,
        )
        url = f"https://{host}/restconf/data"
        auth = aiohttp.BasicAuth(username, password)
        headers = {"Accept": "application/yang-data+json"}

        try:
            async with session.get(url, auth=auth, headers=headers) as response:
                _LOGGER.debug("WLC API Response Code: %s", response.status)
                if response.status == 401:
                    raise InvalidAuth
                if response.status != 200:
                    raise CannotConnect
        except aiohttp.ClientConnectorCertificateError as err:
            raise SSLError from err
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            raise CannotConnect from err
        except Exception as err:  # pragma: no cover - defensive guard
            raise UnknownError from err

    async def async_step_user(
        self, user_input: Mapping[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            ignore_ssl = user_input.get(CONF_IGNORE_SSL, False)
            try:
                await self._async_validate_credentials(
                    host=user_input[CONF_HOST],
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    ignore_ssl=ignore_ssl,
                )
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except SSLError:
                errors["base"] = "ssl_error"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except UnknownError:
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(user_input[CONF_HOST])
                self._abort_if_unique_id_configured()

                data = {
                    CONF_HOST: user_input[CONF_HOST],
                    CONF_USERNAME: user_input[CONF_USERNAME],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                    CONF_IGNORE_SSL: ignore_ssl,
                }
                options = {
                    "enable_new_entities": user_input.get("enable_new_entities", False),
                    CONF_DETAILED_MACS: [],
                }
                return self.async_create_entry(
                    title=user_input[CONF_HOST],
                    data=data,
                    options=options,
                )

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

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> FlowResult:
        """Start a reauthentication flow when credentials become invalid."""

        self._pending_reauth_entry_id = self.context.get("entry_id")
        if self._pending_reauth_entry_id:
            self._pending_reauth_entry = self.hass.config_entries.async_get_entry(
                self._pending_reauth_entry_id
            )
        else:
            self._pending_reauth_entry = None

        host = entry_data.get(CONF_HOST, "")
        self._reauth_defaults = {
            CONF_HOST: host,
            CONF_USERNAME: entry_data.get(CONF_USERNAME, ""),
            CONF_IGNORE_SSL: entry_data.get(CONF_IGNORE_SSL, False),
        }

        self.context["title_placeholders"] = {"host": host}
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: Mapping[str, Any] | None = None
    ) -> FlowResult:
        """Ask the user for new credentials during reauthentication."""

        errors: dict[str, str] = {}
        defaults = self._reauth_defaults
        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_USERNAME,
                    default=defaults.get(CONF_USERNAME, ""),
                ): selector.TextSelector(),
                vol.Required(CONF_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
                vol.Optional(
                    CONF_IGNORE_SSL,
                    default=defaults.get(CONF_IGNORE_SSL, False),
                ): selector.BooleanSelector(),
            }
        )

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]
            ignore_ssl = user_input.get(CONF_IGNORE_SSL, defaults.get(CONF_IGNORE_SSL, False))
            host = defaults.get(CONF_HOST, "")

            try:
                await self._async_validate_credentials(
                    host=host,
                    username=username,
                    password=password,
                    ignore_ssl=ignore_ssl,
                )
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except SSLError:
                errors["base"] = "ssl_error"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except UnknownError:
                errors["base"] = "unknown"
            else:
                entry = self._pending_reauth_entry
                if entry is None and self._pending_reauth_entry_id:
                    entry = self.hass.config_entries.async_get_entry(
                        self._pending_reauth_entry_id
                    )
                if entry is None:
                    return self.async_abort(reason="unknown")

                data_updates = {
                    CONF_USERNAME: username,
                    CONF_PASSWORD: password,
                    CONF_IGNORE_SSL: ignore_ssl,
                }
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates=data_updates,
                    reason="reauth_successful",
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=data_schema,
            errors=errors,
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
        self._option_labels: dict[str, str] | None = None

    async def _async_get_option_labels(self) -> dict[str, str]:
        """Return localized labels for options form fields."""

        if self._option_labels is not None:
            return self._option_labels

        defaults = {
            "enable_new_entities": "Disable newly discovered devices by default",
            "scan_interval": "Polling interval (seconds)",
            "ap_detail_interval": "AP metadata refresh interval (seconds)",
            "detailed_macs": "Clients to poll for detailed telemetry",
        }

        try:
            translations = await async_get_translations(
                self.hass,
                self.hass.config.language,
                "options",
                {DOMAIN},
            )
        except Exception:  # pragma: no cover - defensive
            translations = {}

        labels: dict[str, str] = {}
        for key, fallback in defaults.items():
            translation_key = f"component.{DOMAIN}.options.step.init.data.{key}"
            label = translations.get(translation_key, fallback)
            if not isinstance(label, str) or not label.strip():
                label = fallback
            labels[key] = label

        self._option_labels = labels
        return labels

    async def async_step_init(
        self, user_input: Mapping[str, Any] | None = None
    ) -> FlowResult:
        """Present and process the options form."""
        current_enable_new = self._config_entry.options.get("enable_new_entities", False)
        stored_detailed: list[str] = self._config_entry.options.get(CONF_DETAILED_MACS, []) or []
        current_detailed = [mac for mac in (normalize_mac(m) for m in stored_detailed) if mac]
        current_interval = int(
            self._config_entry.options.get(
                CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL.total_seconds()
            )
        )
        current_ap_interval = int(
            self._config_entry.options.get(
                CONF_AP_DETAIL_INTERVAL, DEFAULT_AP_DETAIL_INTERVAL
            )
        )

        coordinator = cast(
            CiscoWLCUpdateCoordinator | None,
            getattr(self._config_entry, "runtime_data", None),
        )
        mac_choices = _build_mac_options(self.hass, coordinator, current_detailed)

        labels = await self._async_get_option_labels()
        label_enable_new = labels["enable_new_entities"]
        label_scan_interval = labels["scan_interval"]
        label_ap_detail = labels["ap_detail_interval"]
        label_detailed_macs = labels["detailed_macs"]

        if user_input is not None:
            def _input_value(raw_key: str, label: str, default: Any) -> Any:
                if isinstance(user_input, Mapping):
                    if label in user_input:
                        return user_input[label]
                    if raw_key in user_input:
                        return user_input[raw_key]
                return default

            detailed_selected = _input_value(CONF_DETAILED_MACS, label_detailed_macs, [])
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
                interval_value = int(_input_value(CONF_SCAN_INTERVAL, label_scan_interval, current_interval))
            except (ValueError, TypeError):
                interval_value = current_interval

            try:
                ap_interval_value = int(
                    _input_value(CONF_AP_DETAIL_INTERVAL, label_ap_detail, current_ap_interval)
                )
            except (ValueError, TypeError):
                ap_interval_value = current_ap_interval

            new_options = {
                "enable_new_entities": bool(
                    _input_value("enable_new_entities", label_enable_new, current_enable_new)
                ),
                CONF_DETAILED_MACS: sorted(normalized_selected),
                CONF_SCAN_INTERVAL: max(5, interval_value),
                CONF_AP_DETAIL_INTERVAL: max(60, ap_interval_value),
            }
            return self.async_create_entry(title="", data=new_options)

        fields: dict[Any, Any] = {
            vol.Optional(label_enable_new, default=current_enable_new): selector.BooleanSelector(),
            vol.Optional(label_scan_interval, default=current_interval): vol.All(
                vol.Coerce(int), vol.Range(min=5, max=3600)
            ),
            vol.Optional(label_ap_detail, default=current_ap_interval): vol.All(
                vol.Coerce(int), vol.Range(min=60, max=86400)
            ),
        }

        if mac_choices:
            fields[vol.Optional(label_detailed_macs, default=current_detailed)] = cv.multi_select(
                mac_choices
            )

        schema = vol.Schema(fields)

        return self.async_show_form(
            step_id="init",
            data_schema=schema,
        )
