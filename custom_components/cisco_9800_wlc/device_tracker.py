"""Device tracker for Cisco 9800 WLC integration."""
from __future__ import annotations
import logging
import asyncio
from homeassistant.components.device_tracker import ScannerEntity
from typing import Callable, Dict
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import device_registry as dr
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from datetime import datetime, timedelta
from .const import  DEFAULT_TRACK_NEW ,DOMAIN  

_LOGGER = logging.getLogger(__name__)

# -------------------------
#  WLC Controller Status Entity
# -------------------------
class CiscoWLCStatus(CoordinatorEntity):
    """Represents the online/offline status of the Cisco WLC."""

    def __init__(self, coordinator, config_entry, wlc_online_status, wlc_software_version):
        """Initialize the WLC status entity."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{DOMAIN}_controller_status"
        self._attr_name = "Cisco 9800 WLC"
        self._attr_should_poll = False  
        self.config_entry = config_entry

        #  Store received data from the coordinator
        self._attr_online_status = wlc_online_status
        self._attr_sw_version = wlc_software_version
        #  Store reference for updates
        coordinator.hass.data[DOMAIN]["wlc_status_entity"] = self
      

    @property
    def available(self) -> bool:
        """Return True if the WLC itself is online."""
        return self._attr_online_status.lower() == "online"  #  Now returns True or False correctly
    
    @property
    def state(self):
        """Return the state of the WLC as Online/Offline."""
        return "Online" if self._attr_online_status.lower() == "online" else "Offline"

    @property
    def available(self) -> bool:
        """Return True if the WLC itself is online."""
        return self._attr_online_status.lower() == "online"  #  Ensures boolean return

    @property
    def sw_version(self) -> str:
        """Return the latest software version stored in the entity."""
        return self._attr_sw_version

    @property
    def device_info(self) -> DeviceInfo:
        """Return Home Assistant device information for WLC."""
        return DeviceInfo(
            identifiers={(DOMAIN, self.config_entry.entry_id)},
            name="Cisco 9800 WLC",
            manufacturer="Cisco",
            model="9800 Series Wireless Controller",
            sw_version=self._attr_sw_version,  #  Fetch from stored attribute
            configuration_url=f"https://{self.config_entry.data['host']}",
        )

    async def async_update(self):
        """Ensure software version and online status are updated from the latest data."""
        

        #  Request fresh data from coordinator
        await self.coordinator.async_request_refresh()

        #  Extract updated data
        self._attr_sw_version = self.coordinator.data.get("software_version", "Unknown")
        self._attr_online_status = self.coordinator.data.get("online_status", "Unknown")

        #  Log updated values
        _LOGGER.info(f"🚀 [WLC ENTITY] Updated SW Version: {self._attr_sw_version}")
        _LOGGER.info(f"🚀 [WLC ENTITY] Updated Online Status: {self._attr_online_status}")

        #  Refresh UI
        self.async_write_ha_state()


    
# -------------------------
#  Tracked Client Entity
# Lets remeber that WLC has a idle timeout so clients will report in even when disconnected for the idle time. default 6 mins.
# -------------------------
class CiscoWLCClient(ScannerEntity, CoordinatorEntity):
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
        return "router"

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
        """Return the device name from extra_state_attributes, otherwise the MAC address."""
        attributes = self.extra_state_attributes  # Ensure we're getting the latest attributes
        return attributes.get("Device Name", self.mac)  #  Now correctly retrieves the name

    @property
    def is_connected(self) -> bool:
        """Return True if the client is still connected."""
        return self.mac in self.coordinator.data

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
            
    async def async_update(self):
        """Fetch the latest list of connected clients and update state."""

        _LOGGER.debug(f"Tracker - Checking entity {self.entity_id} (MAC: {self.mac})")

        #  Handle "Unavailable" State Before Fetching Data
        current_state = self.hass.states.get(self.entity_id)
        if current_state and current_state.state == "unavailable":
            _LOGGER.info(f" Restoring entity {self.entity_id} from 'unavailable' to 'away'")
            self.hass.states.async_set(self.entity_id, "away")

        # Refresh coordinator data
        await self.coordinator.async_request_refresh()

        client_data = self.coordinator.data.get(self.mac)

        if client_data:
            #  If the MAC is detected, mark as home
            self._attr_is_connected = True
            self._attr_state = "home"
        else:
            #  If MAC is missing, mark as away
            self._attr_is_connected = False
            self._attr_state = "away"

        self.async_write_ha_state()

# -------------------------
#  Async Setup Entry
# -------------------------

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Cisco 9800 WLC device tracker from a config entry."""
    _LOGGER.info(" Starting setup for Cisco 9800 WLC integration.")

    coordinator = hass.data[DOMAIN].get(entry.entry_id)
    if entry.options.get("disable_polling", False):
        _LOGGER.info("Polling is disabled in system options. Using manual refresh only.")
        coordinator.update_interval = None  # Disable automatic updates
    else:
        _LOGGER.info("Polling is enabled. Setting update interval.")
        coordinator.update_interval = timedelta(seconds=120)  # Keep existing interval
    
    if not coordinator:
        _LOGGER.error(" Failed to find WLC coordinator for entry %s. Aborting setup.", entry.entry_id)
        return
    
    hass.data[DOMAIN]["async_add_entities"] = async_add_entities
    coordinator.async_add_entities = async_add_entities
    enable_new_entities = entry.options.get("enable_new_entities", False)
    
    await coordinator.fetch_wlc_status()

    wlc_status_entity = CiscoWLCStatus(
        coordinator,
        entry,
        wlc_online_status=coordinator.data.get("wlc_status", {}).get("online_status", "Offline"),
        wlc_software_version=coordinator.data.get("wlc_status", {}).get("software_version", "n/a")
    )

    async_add_entities([wlc_status_entity])  # ✅ First, add entity so `hass` is assigned
    hass.data[DOMAIN]["wlc_status_entity"] = wlc_status_entity

    # ✅ Wait for Home Assistant to fully assign `hass`
    async def finalize_wlc_status():
        await asyncio.sleep(0)  # Yield control to Home Assistant
        if wlc_status_entity.hass is not None:
            wlc_status_entity.async_write_ha_state()
        else:
            _LOGGER.warning("WLC Status entity `hass` is still None. Skipping state update.")

    hass.async_create_task(finalize_wlc_status())  # ✅ Run async task instead
   
    if wlc_status_entity._attr_online_status != "Online":
        _LOGGER.error(" WLC is offline! Aborting client setup but keeping status entity.")
        return

    _LOGGER.info(" WLC is online! Proceeding with client setup.")

    # Fetch initial list of clients from WLC
    _LOGGER.info(" Fetching initial client list from WLC...")
    await coordinator._async_firstrun()
    all_active_clients = set(coordinator.data.keys())

    #  **Step 1: Retrieve all known devices from Home Assistant**
    entity_registry = er.async_get(hass)
    known_clients = set()

    for entity_entry in entity_registry.entities.values():
        if (
            entity_entry.platform == DOMAIN
            and entity_entry.entity_id.startswith("device_tracker.cisco_9800_wlc_")
            and entity_entry.disabled_by is None
        ):
            known_clients.add(entity_entry.unique_id.lower())

    _LOGGER.info(f" Home Assistant knows {len(known_clients)} devices.")
    _LOGGER.info(f" WLC currently sees {len(all_active_clients)} devices.")

    # **Step 2: Merge Known Clients & Active Clients**
    all_clients = known_clients | all_active_clients  # Union of both sets

    # **Step 3: Register All Clients in Home Assistant**
    clients_to_add = [
        CiscoWLCClient(coordinator, mac, coordinator.data.get(mac, {}), enable_new_entities)
        for mac in all_clients
    ]

    if clients_to_add:
        _LOGGER.info(f"Registering {len(clients_to_add)} device trackers in Home Assistant.")
        async_add_entities(clients_to_add)
    else:
        _LOGGER.warning(" No client entities were added. Check if WLC data retrieval is working.")

    # **Step 4: Handle "RESTORED" entities stuck as 'unavailable'**
    restored_entities = []
    for entity_entry in entity_registry.entities.values():
        if (
            entity_entry.platform == DOMAIN
            and entity_entry.entity_id.startswith("device_tracker.cisco_9800_wlc_")
            and entity_entry.disabled_by is None
        ):
            current_state = hass.states.get(entity_entry.entity_id)

            #  If device is "restored" but missing from the API, re-register it
            if entity_entry.entity_id not in coordinator.data:
                hass.states.async_set(entity_entry.entity_id, "away")
                restored_entities.append(entity_entry.entity_id)

    if restored_entities:
        _LOGGER.info(f"🚀 Manually refreshing {len(restored_entities)} restored entities to sync attributes.")
        hass.async_create_task(coordinator.async_request_refresh())  #  Ensure attributes update

    _LOGGER.info("Cisco 9800 WLC setup completed successfully!")