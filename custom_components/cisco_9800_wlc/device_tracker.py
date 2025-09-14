"""Device tracker for Cisco 9800 WLC integration."""
from __future__ import annotations
import logging
from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.components.device_tracker.const import SourceType
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers import entity_registry as er
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from datetime import timedelta
from .const import DOMAIN, SIGNAL_NEW_CLIENTS
from homeassistant.helpers import device_registry as dr

_LOGGER = logging.getLogger(__name__)

# -------------------------
#  Tracked Client Entity
# Lets remeber that WLC has a idle timeout so clients will report in even when disconnected for the idle time. default 6 mins.
# -------------------------
class CiscoWLCClient(CoordinatorEntity, ScannerEntity):
    """Represents a tracked client device connected to the Cisco WLC."""

    def __init__(self, coordinator, mac, data, enable_by_default):
        """Initialize the WLC tracked client."""
      #  _LOGGER.debug(" Initialize the WLC tracked client.")
        super().__init__(coordinator)
        self.coordinator = coordinator
        self.mac = mac  
        self.data = self.coordinator.data.get(self.mac, {})
        self._attr_should_poll = False  #  Polling is not needed
        self._enable_by_default = enable_by_default  #  Store user preference
      

    @property
    def source_type(self):
        """Indicate this is a router-based tracker."""
        return SourceType.ROUTER

    @property
    def unique_id(self):
        """Return a unique ID for the device."""
        return self.mac  #  Uses MAC as-is, which was working before

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return whether the entity is enabled by default."""
        return self._enable_by_default  #  Use user setting from config entry

    @property
    def name(self):
        """Return a human-readable name, appending last 4 MAC hex digits.

        Example: "APPLE, INC." + "44:f3" -> "APPLE, INC.44:f3".
        """
        attributes = self.extra_state_attributes
        base_name = attributes.get("Device Name")
        # Compute suffix from last two bytes of MAC
        parts = self.mac.split(":")
        mac_suffix = f"{parts[-2]}:{parts[-1]}" if len(parts) >= 2 else self.mac[-5:]

        if base_name and isinstance(base_name, str) and base_name.strip():
            return f"{base_name}{mac_suffix}"
        # Fallback to MAC if no name available
        return self.mac

    @property
    def is_connected(self) -> bool:
        """Return True if the client is still connected."""
        return isinstance(self.coordinator.data, dict) and self.mac in self.coordinator.data

    @property
    def extra_state_attributes(self):
        """Return additional attributes about the connected client."""
      

        # Retrieve stored attributes from the coordinator
        attributes = self.coordinator.data.get(self.mac, {})

        default_attributes = {
            "SSID": None,
            "Access Point Name": None,
            "Username": None,
            "Current Channel": None,
            "Fast Roaming": None,
            "Connection Speed Mps": None,
            "Device Name": None,
            "Device Type": None,
            "Device OS": None,
            "Most Recent Roam": None, 
            "Previous Roam 2": None,   
            "Previous Roam 1": None,   
            "Previous Roam 3": None, 
            "IP Address": None,
            "WifiStandard": None,
            "Last Updated Time": None 
            

            
        }

        # Mapping HA attribute keys to API attribute names
        attribute_key_mapping = {
            "SSID": "ssid",
            "Access Point Name": "ap-name",
            "IP Address": "IP Address",
            "Connection Speed Mps": "speed",
            "Current Channel": "current-channel",
            "Fast Roaming": "auth-key-mgmt",
            "Device Name": "device-name",
            "Device Type": "device-type",
            "Device OS": "device-os",
            "Most Recent Roam": "most_recent_roam",  
            "Previous Roam 1": "previous_roam_1",    
            "Previous Roam 2": "previous_roam_2",    
            "Previous Roam 3": "previous_roam_3",   
            "WifiStandard": "WifiStandard",
            "Username": "username",
            "Last Updated Time": "last_updated_time"
        }

        merged_attributes = {}

        for ha_key, api_key in attribute_key_mapping.items():
            if api_key in attributes and attributes[api_key] is not None:
                merged_attributes[ha_key] = attributes[api_key]
            else:
                merged_attributes[ha_key] = default_attributes.get(ha_key, None)

        
        return merged_attributes
            
    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry information for this tracked client."""
        return DeviceInfo(
            connections={(dr.CONNECTION_NETWORK_MAC, self.mac)},
            name=self.name,
        )

# -------------------------
#  Async Setup Entry
# -------------------------

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Cisco 9800 WLC device tracker from a config entry."""
    _LOGGER.info("Setting up Cisco 9800 WLC device tracker platform")

    coordinator = hass.data[DOMAIN].get(entry.entry_id)
    if entry.options.get("disable_polling", False):
        _LOGGER.info("Polling is disabled in options; manual refresh only")
        coordinator.update_interval = None  # Disable automatic updates
    else:
        _LOGGER.debug("Polling is enabled; setting update interval")
        coordinator.update_interval = timedelta(seconds=120)  # Keep existing interval
    
    if not coordinator:
        _LOGGER.error(" Failed to find WLC coordinator for entry %s. Aborting setup.", entry.entry_id)
        return
    
    # Track which MACs have entities already added
    tracked_macs = hass.data[DOMAIN].setdefault("tracked_macs", set())
    enable_new_entities = entry.options.get("enable_new_entities", False)
    
    # Controller status is now provided via binary_sensor platform

    # Fetch initial list of clients from WLC
    _LOGGER.debug("Fetching initial client list from WLC")
    await coordinator.async_request_refresh()
    all_active_clients = {k for k in coordinator.data.keys() if k != "wlc_status"}

    #  **Step 1: Retrieve all known devices from Home Assistant**
    entity_registry = er.async_get(hass)
    known_clients = set()

    for entity_entry in entity_registry.entities.values():
        if (
            getattr(entity_entry, "domain", None) == "device_tracker"
            and entity_entry.platform == DOMAIN
            and entity_entry.unique_id
        ):
            known_clients.add(entity_entry.unique_id.lower())

    _LOGGER.debug("Home Assistant knows %d devices", len(known_clients))
    _LOGGER.info(
        "Initial registration: %d active from WLC, %d total to register",
        len(all_active_clients), len(known_clients | all_active_clients),
    )

    # **Step 2: Merge Known Clients & Active Clients**
    all_clients = known_clients | all_active_clients  # Union of both sets

    # **Step 3: Register All Clients in Home Assistant**
    clients_to_add = []
    for mac in all_clients:
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
    def handle_new_clients(coord, new_macs):
        if coord is not coordinator:
            return
        new_entities = []
        for mac in new_macs:
            if mac in tracked_macs:
                continue
            new_entities.append(CiscoWLCClient(coordinator, mac, coordinator.data.get(mac, {}), enable_new_entities))
            tracked_macs.add(mac)
        if new_entities:
            _LOGGER.debug("Adding %d newly discovered client(s)", len(new_entities))
            async_add_entities(new_entities)

    unsubscribe = async_dispatcher_connect(hass, SIGNAL_NEW_CLIENTS, handle_new_clients)
    entry.async_on_unload(unsubscribe)
