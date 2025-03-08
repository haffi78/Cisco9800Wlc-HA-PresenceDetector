"""Device tracker for Cisco 9800 WLC integration."""
from __future__ import annotations
import logging
from homeassistant.components.device_tracker import ScannerEntity
from typing import Callable, Dict
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import device_registry as dr
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
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
        """Return the device name if available, otherwise the MAC address."""
        return self.data.get("device_name") or self.mac  #  Optimized fallback

    @property
    def is_connected(self) -> bool:
        """Return True if the client is still connected and has valid attributes."""
        return bool(self.coordinator.data.get(self.mac))  #  More robust check

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
            "Latest Roam": None,
            "1st-roam": None,
            "2nd-roam": None,
            "3rd-roam": None,
            "IP Address": None,
            "WifiStandard": None,

            
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
            "Latest Roam": "latest-roam",
            "1st-roam": "1st-roam",
            "2nd-roam": "2nd-roam",
            "3rd-roam": "3rd-roam",
            "WifiStandard": "WifiStandard",
            "Username": "username",
        }

        merged_attributes = {}

        for ha_key, api_key in attribute_key_mapping.items():
            if api_key in attributes and attributes[api_key] is not None:
                merged_attributes[ha_key] = attributes[api_key]
            else:
                merged_attributes[ha_key] = default_attributes.get(ha_key, None)

        
        return merged_attributes
            
    async def async_update(self):
        """Fetch the latest list of connected clients."""
    # _LOGGER.debug(" CiscoWLCClient - 9800 Fetching connected client data")
        # Ask coordinator to refresh ALL clients
        await self.coordinator.async_request_refresh()
    
        # Ensure HA updates UI
        self.async_write_ha_state()

# -------------------------
#  Async Setup Entry
# -------------------------

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Cisco 9800 WLC device tracker from a config entry."""
    _LOGGER.info(" Starting setup for Cisco 9800 WLC integration.")

    #  Get the WLC data coordinator
    coordinator = hass.data[DOMAIN].get(entry.entry_id)
    
    if not coordinator:
        _LOGGER.error(" Failed to find WLC coordinator for entry %s. Aborting setup.", entry.entry_id)
        return  #  Stop setup if the coordinator is missing
    enable_new_entities = entry.options.get("enable_new_entities", False)
    await coordinator.fetch_wlc_status()  #  Get WLC online status + firmware version
    
    #  Step 2:  Create WLC status entity **before fetching clients
        
    wlc_status_entity = CiscoWLCStatus(
    coordinator,
    entry,
    wlc_online_status=coordinator.data.get("wlc_status", {}).get("online_status", "Offline"),
    wlc_software_version=coordinator.data.get("wlc_status", {}).get("software_version", "n/a")
)
    


    async_add_entities([wlc_status_entity])  #  Register WLC status entity
    
    #  Store reference for future updates
    hass.data[DOMAIN]["wlc_status_entity"] = wlc_status_entity 
    wlc_status_entity.async_write_ha_state() #  Ensure HA UI reflects WLC status immediately
   
    #  Step 3: Check if WLC is online before proceeding   
    if wlc_status_entity._attr_online_status != "Online":
        _LOGGER.error(" WLC is offline! Aborting client setup but keeping status entity.")
        return  #  Stop client setup but keep WLC status visible in HA

    _LOGGER.info(" WLC is online! Proceeding with client setup.")

    #  Step 4: Fetch **all** clients (before tracking specific ones)
    _LOGGER.info(" Fetching initial client list from WLC...")
    await coordinator._async_update_data()  #  Retrieve all connected clients

    # Get the list of all clients detected by the WLC
    all_clients = list(coordinator.data.keys())

    if not all_clients:
        _LOGGER.warning(" No clients found on the WLC. Device tracker might not work properly.")

    #  Step 5: Register **all** clients in Home Assistant
    clients = [
    CiscoWLCClient(coordinator, mac, coordinator.data.get(mac, {}), enable_new_entities)
    for mac in all_clients  # 🔥 Add all discovered clients
]

    if clients:
        _LOGGER.info(f" Registering {len(clients)} client trackers in Home Assistant.")
        async_add_entities(clients)  #  Add all clients as HA entities
    else:
        _LOGGER.warning(" No client entities were added. Check if WLC data retrieval is working.")

    _LOGGER.info(" Cisco 9800 WLC setup completed successfully!")