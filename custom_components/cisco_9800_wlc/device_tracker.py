"""Device tracker for Cisco 9800 WLC integration."""
from __future__ import annotations

import logging
from typing import Any, Iterable, cast

from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.components.device_tracker.const import SourceType

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, SIGNAL_NEW_CLIENTS
from .coordinator import CiscoWLCUpdateCoordinator, parse_to_local_datetime

_LOGGER = logging.getLogger(__name__)

# -------------------------
#  Tracked Client Entity
# Lets remeber that WLC has a idle timeout so clients will report in even when disconnected for the idle time. default 6 mins.
# -------------------------
class CiscoWLCClient(CoordinatorEntity[CiscoWLCUpdateCoordinator], ScannerEntity):
    """Represents a tracked client device connected to the Cisco WLC."""

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        mac: str,
        data: dict[str, Any] | None,
        enable_by_default: bool,
    ) -> None:
        """Initialize the WLC tracked client."""
      #  _LOGGER.debug(" Initialize the WLC tracked client.")
        super().__init__(coordinator)
        self.coordinator = coordinator
        self.mac = mac
        self.data = data or self.coordinator.data.get(self.mac, {})
        self._attr_should_poll = False  #  Polling is not needed
        self._enable_by_default = enable_by_default  #  Store user preference
        self._attr_name = self._current_friendly_name()


    @property
    def source_type(self) -> SourceType:
        """Indicate this is a router-based tracker."""
        return SourceType.ROUTER

    @property
    def available(self) -> bool:
        """Return if coordinator has delivered a successful update recently."""

        return bool(self.coordinator.last_update_success)

    @property
    def unique_id(self) -> str:
        """Return a unique ID for the device."""
        return self.mac  #  Uses MAC as-is, which was working before

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return whether the entity is enabled by default."""
        return self._enable_by_default  #  Use user setting from config entry

    @property
    def name(self) -> str:
        """Return a friendly, stable name with MAC suffix.

        Preference order:
        1) Device Name (e.g., a hostname like "blackeys-phone")
        2) Device Type (e.g., model)
        3) Device OS
        Else fallback to the MAC address.
        Always append last 2 MAC bytes for disambiguation: " Name ee:ff".
        """
        return self._current_friendly_name()

    @property
    def is_connected(self) -> bool:
        """Return True if the client is still connected."""
        if not isinstance(self.coordinator.data, dict):
            return False
        client = self.coordinator.data.get(self.mac)
        if isinstance(client, dict):
            if "connected" in client:
                return bool(client["connected"])
            # Fallback for legacy data without the new flag
            return True
        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes about the connected client."""
      

        # Retrieve stored attributes from the coordinator
        attributes = self.coordinator.data.get(self.mac, {})

        default_attributes = {
            "SSID": None,
            "Access Point Name": None,
            "Username": None,
            "Current Channel": None,
            "Roaming": None,
            "Connection Speed Mbps": None,
            "Device Name": None,
            "Device Type": None,
            "Device OS": None,
            "Most Recent Roam": None, 
            "Previous Roam 2": None,   
            "Previous Roam 1": None,   
            "Previous Roam 3": None, 
            "IP Address": None,
            "WifiStandard": None,
            "Last Seen": None,
            "Attributes Updated": None,


            
        }

        # Mapping HA attribute keys to API attribute names
        attribute_key_mapping = {
            "SSID": "ssid",
            "Access Point Name": "ap-name",
            "IP Address": "IP Address",
            "Connection Speed Mbps": "speed",
            "Current Channel": "current-channel",
            "Roaming": "auth-key-mgmt",
            "Device Name": "device-name",
            "Device Type": "device-type",
            "Device OS": "device-os",
            "Most Recent Roam": "most_recent_roam",  
            "Previous Roam 1": "previous_roam_1",    
            "Previous Roam 2": "previous_roam_2",    
            "Previous Roam 3": "previous_roam_3",   
            "WifiStandard": "WifiStandard",
            "Username": "username",
            "Last Seen": "last_seen",
            "Attributes Updated": "attributes_updated",
        }

        merged_attributes: dict[str, Any] = {}

        for ha_key, api_key in attribute_key_mapping.items():
            if api_key in attributes and attributes[api_key] is not None:
                merged_attributes[ha_key] = attributes[api_key]
            else:
                merged_attributes[ha_key] = default_attributes.get(ha_key, None)

        for time_key in ("Last Seen", "Attributes Updated"):
            value = merged_attributes.get(time_key)
            if value:
                formatted = _format_timestamp(value)
                if formatted:
                    merged_attributes[time_key] = formatted

        return merged_attributes

    def _base_name(self) -> str:
        """Return the best friendly name without the MAC suffix."""

        attributes = (
            self.coordinator.data.get(self.mac, {})
            if isinstance(self.coordinator.data, dict)
            else {}
        )
        name_candidate = (
            attributes.get("device-name")
            or attributes.get("device-type")
            or attributes.get("device-os")
        )
        if isinstance(name_candidate, str) and name_candidate.strip():
            return name_candidate.strip()
        return self.mac

    def _mac_suffix(self) -> str:
        parts = self.mac.split(":")
        if len(parts) >= 2:
            return f"{parts[-2]}:{parts[-1]}"
        return self.mac[-5:]

    def _current_friendly_name(self) -> str:
        base = self._base_name()
        suffix = self._mac_suffix()
        if base == self.mac:
            return f"Client {suffix}"
        return f"{base} {suffix}"

    def _device_registry_label(self) -> str:
        base = self._base_name()
        if base == self.mac:
            return f"Client {self._mac_suffix()}"
        return base

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry information for this tracked client."""
        return DeviceInfo(
            connections={(dr.CONNECTION_NETWORK_MAC, self.mac)},
            name=self._device_registry_label(),
        )

    async def _async_update_device_registry_name(self) -> None:
        desired_name = self._device_registry_label()
        device_registry = dr.async_get(self.hass)
        device = device_registry.async_get_device(connections={(dr.CONNECTION_NETWORK_MAC, self.mac)})
        if device and device.name != desired_name:
            device_registry.async_update_device(device.id, name=desired_name)

    def _handle_coordinator_update(self) -> None:
        self._attr_name = self._current_friendly_name()
        super()._handle_coordinator_update()
        self.hass.async_create_task(self._async_update_device_registry_name())
# -------------------------
#  Async Setup Entry
# -------------------------

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Cisco 9800 WLC device tracker from a config entry."""
    _LOGGER.info("Setting up Cisco 9800 WLC device tracker platform")

    domain_data = hass.data.setdefault(DOMAIN, {})
    coordinator = cast(CiscoWLCUpdateCoordinator | None, entry.runtime_data)
    if coordinator is None:
        _LOGGER.error(" Failed to find WLC coordinator for entry %s. Aborting setup.", entry.entry_id)
        return
    coordinator = cast(CiscoWLCUpdateCoordinator, coordinator)

    if entry.options.get("disable_polling", False):
        _LOGGER.info("Polling is disabled in options; manual refresh only")
        coordinator.update_interval = None  # Disable automatic updates
    else:
        # Respect the coordinator's configured interval (set in coordinator.py)
        _LOGGER.debug("Polling is enabled; using coordinator interval: %s", coordinator.update_interval)

    # Track which MACs have entities already added
    tracked_entries = domain_data.setdefault("tracked_macs", {})
    tracked_entries = cast(dict[str, set[str]], tracked_entries)
    tracked_macs = set()
    tracked_entries[entry.entry_id] = tracked_macs
    enable_new_entities = entry.options.get("enable_new_entities", False)
    
    # Controller status is now provided via binary_sensor platform

    # Fetch initial list of clients from WLC
    _LOGGER.debug("Fetching initial client list from WLC")
    await coordinator.async_request_refresh()
    all_active_clients: set[str] = set()
    for key in coordinator.data.keys():
        if not isinstance(key, str):
            continue
        if key == "wlc_status":
            continue
        if coordinator._normalize_mac(key) is None:
            continue
        all_active_clients.add(key)

    #  **Step 1: Retrieve all known devices from Home Assistant**
    entity_registry = er.async_get(hass)
    known_clients: set[str] = set()

    for entity_entry in list(entity_registry.entities.values()):
        if (
            entity_entry.entity_id.startswith("device_tracker.")
            and entity_entry.platform == DOMAIN
            and entity_entry.unique_id
        ):
            # Re-bind orphaned entities (e.g., after config entry re-create) to this entry
            if entity_entry.config_entry_id != entry.entry_id:
                entity_registry.async_update_entity(
                    entity_entry.entity_id,
                    config_entry_id=entry.entry_id,
                )

            uid = entity_entry.unique_id.lower()
            normalized_uid = coordinator._normalize_mac(uid)
            if not normalized_uid:
                _LOGGER.debug("Skipping invalid MAC unique_id %s", uid)
                continue
            known_clients.add(uid)
            known_clients.add(normalized_uid)

    _LOGGER.info(
        "Initial registration: %d active from WLC, %d total to register",
        len(all_active_clients),
        len(known_clients | all_active_clients),
    )

    # **Step 2: Merge Known Clients & Active Clients**
    all_clients = known_clients | all_active_clients  # Union of both sets

    # **Step 3: Register All Clients in Home Assistant**
    clients_to_add: list[CiscoWLCClient] = []
    for mac in all_clients:
        if coordinator._normalize_mac(mac) is None:
            continue
        if mac not in tracked_macs:
            clients_to_add.append(CiscoWLCClient(coordinator, mac, coordinator.data.get(mac, {}), enable_new_entities))
            tracked_macs.add(mac)

    if clients_to_add:
        _LOGGER.debug("Registering %d device trackers in Home Assistant", len(clients_to_add))
        async_add_entities(clients_to_add)
    else:
        _LOGGER.debug("No client entities were added (possibly already registered)")

    _LOGGER.info("Cisco 9800 WLC device tracker setup completed")

    # Listen for new clients discovered by the coordinator and add entities dynamically
    def handle_new_clients(
        coord: CiscoWLCUpdateCoordinator,
        new_macs: Iterable[str],
    ) -> None:
        if coord is not coordinator:
            return
        new_entities: list[CiscoWLCClient] = []
        for mac in new_macs:
            if coordinator._normalize_mac(mac) is None:
                continue
            if mac in tracked_macs:
                continue
            new_entities.append(
                CiscoWLCClient(
                    coordinator,
                    mac,
                    coordinator.data.get(mac, {}),
                    enable_new_entities,
                )
            )
            tracked_macs.add(mac)
        if new_entities:
            _LOGGER.debug("Adding %d newly discovered client(s)", len(new_entities))
            hass.add_job(async_add_entities, new_entities)

    unsubscribe = async_dispatcher_connect(hass, SIGNAL_NEW_CLIENTS, handle_new_clients)
    entry.async_on_unload(unsubscribe)


def _format_timestamp(value: Any) -> str | None:
    """Normalize timestamp strings to 24-hour local format."""

    if isinstance(value, str):
        parsed = parse_to_local_datetime(value)
        if parsed:
            tz_label = parsed.tzname() or "local"
            return f"{parsed.strftime('%Y-%m-%d %H:%M:%S')} ({tz_label})"
    return value if isinstance(value, str) else None
