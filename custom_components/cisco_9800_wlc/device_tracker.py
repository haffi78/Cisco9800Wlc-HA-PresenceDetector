from __future__ import annotations  # Allows forward references in type hints, improving readability for modern Python
import logging  # For logging debug/info/error messages throughout the script
import json  # To parse JSON responses from the RESTCONF API
from datetime import timedelta  # Used for representing scan intervals as time durations
import voluptuous as vol  # Validation library to enforce config schema in Home Assistant
import requests  # Core library for making HTTP requests to the Cisco RESTCONF API
from requests.auth import HTTPBasicAuth  # Provides basic authentication for API requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # To suppress SSL warnings
import time
import aiohttp  # 🟢 Import aiohttp at the top
import asyncio 

# Suppress SSL warnings since self-signed certificates are common in network devices
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Home Assistant imports for integrating with its device tracker component
from homeassistant.components.device_tracker import (
    PLATFORM_SCHEMA as DEVICE_TRACKER_PLATFORM_SCHEMA,  # Base schema for device tracker platforms
    DeviceScanner,  # Abstract base class for implementing custom device scanners
)
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_VERIFY_SSL  # Standard config keys
from homeassistant.core import HomeAssistant  # Represents the HA instance
from homeassistant.helpers import config_validation as cv  # Helpers for validating config entries
from homeassistant.helpers.typing import ConfigType  # Type alias for configuration dictionaries

from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.helpers.event import async_track_time_interval

SCAN_INTERVAL = timedelta(seconds=60)  # Explicitly set scan interval ( Home assistant polls every 10 sec and this seams to be ignored ?? I implemented cache to fix)

# Set up a logger specific to this module for consistent logging
_LOGGER = logging.getLogger(__name__)

# Define default constants for RESTCONF endpoints and scanner behavior
DEFAULT_SCAN_INTERVAL = 60  # Default polling interval in seconds (30s is reasonable for network devices)
DEFAULT_VERIFY_SSL = False  # Default to skipping SSL verification (common for internal network devices)
DEFAULT_AP_OPER = "/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data"  # Endpoint for AP operational data
DEFAULT_WLAN_CONFIG = "/Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-data"  # Endpoint for WLAN configuration
DEFAULT_RRM_OPER = "/Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data"  # Endpoint for radio resource management data
DEFAULT_CLIENT_OPER = "/Cisco-IOS-XE-wireless-client-oper:client-oper-data"  # Endpoint for client operational data

# Custom validator to flexibly handle scan_interval as either an int (seconds) or a time period string
def scan_interval_validator(value):
    if isinstance(value, int):  # If user provides an integer (e.g., 30)
        return timedelta(seconds=value)  # Convert to timedelta for consistency
    return cv.time_period(value)  # Otherwise, parse as a time period (e.g., "00:00:30")

# Extend the base device tracker schema with Cisco 9800-specific config options
PLATFORM_SCHEMA = DEVICE_TRACKER_PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,  # Must provide WLC hostname or IP
    vol.Required(CONF_USERNAME): cv.string,  # RESTCONF API username (required for auth)
    vol.Required(CONF_PASSWORD): cv.string,  # RESTCONF API password (required for auth)
    vol.Optional("scan_interval", default=DEFAULT_SCAN_INTERVAL): scan_interval_validator,  # Polling frequency
    vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): cv.boolean,  # Toggle SSL verification
    # Optional overrides for RESTCONF endpoints (useful for custom firmware or setups)
    vol.Optional("base_url"): cv.string,  # Base URL for RESTCONF API (e.g., "https://host/restconf/data")
    vol.Optional("ap_oper", default=DEFAULT_AP_OPER): cv.string,  # AP data endpoint
    vol.Optional("wlan_config", default=DEFAULT_WLAN_CONFIG): cv.string,  # WLAN config endpoint
    vol.Optional("rrm_oper", default=DEFAULT_RRM_OPER): cv.string,  # RRM data endpoint
    vol.Optional("client_oper", default=DEFAULT_CLIENT_OPER): cv.string,  # Client data endpoint
})

###############################################################################
# BEGIN RESTCONF API FUNCTIONS (Merged from getClientInfo.py and getApInfo.py)
###############################################################################

# Global variables to hold API credentials and endpoints; set by the scanner later
API_USER = None  # RESTCONF username
API_PASSWORD = None  # RESTCONF password
BASE_URL = None  # Base URL for API calls (e.g., "https://192.168.1.1/restconf/data")
CLIENT_OPER = None  # Client operational data endpoint
AP_OPER = None  # AP operational data endpoint
WLAN_CONFIG = None  # WLAN configuration endpoint

# Helper to ensure API config is initialized before making requests
def _check_api_config():
    # Raise an exception if any required global variable is unset
    if not API_USER or not API_PASSWORD or not BASE_URL or not CLIENT_OPER or not AP_OPER or not WLAN_CONFIG:
        raise Exception("Missing RESTCONF API configuration variables")

# Fetch common client operational data (e.g., MAC addresses, connection status)
async def get_common_oper_data():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/common-oper-data"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()  # 🟢 Non-blocking async call

# Fetch 802.11-specific client data (e.g., signal strength, channel)
async def get_dot11_oper_data():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/dot11-oper-data"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()

# Fetch mobility history data (e.g., association time, roaming details)
async def get_mobility_history():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/mm-if-client-history"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()


# Fetch client traffic statistics (e.g., bytes sent/received)
async def get_traffic_stats():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/traffic-stats"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()

# Fetch SISF (Security Information and Event Management) MAC database info
async def get_sisf_db_mac():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/sisf-db-mac"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()

# Fetch device classifier info (e.g., device type or category)
async def get_dc_info():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/dc-info"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()

# Fetch list of access points with name-MAC mappings
async def get_ap_list():
    _check_api_config()
    url = BASE_URL + AP_OPER + "/ap-name-mac-map"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()

# Fetch WLAN configuration details (e.g., SSIDs, security settings)
async def get_wlan_list():
    _check_api_config()
    url = BASE_URL + WLAN_CONFIG + "/wlan-cfg-entries/wlan-cfg-entry"
    headers = {"Accept": "application/yang-data+json"}

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(API_USER, API_PASSWORD)) as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            return await response.json()

# Retrieve AP details (name and MAC) by AP name
async def get_ap_info_by_ap_name(ap_name):
    _check_api_config()
    ap_list = await get_ap_list()  # 🟢 Await the async function
    ap_mac = "nomac"

    for item in ap_list.get("Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map", []):
        if ap_name == item.get("wtp-name"):
            ap_mac = item.get("wtp-mac")
            break

    return {"ap_name": ap_name, "ap_mac": ap_mac}

###############################################################################
# END RESTCONF API FUNCTIONS
###############################################################################

###############################################################################
# BEGIN DEVICE SCANNER IMPLEMENTATION
###############################################################################

# Factory function to initialize and return the scanner (required by Home Assistant)
async def async_get_scanner(hass: HomeAssistant, config: ConfigType) -> Cisco9800DeviceScanner | None:
    """Set up the Cisco 9800 WLC Device Tracker using RESTCONF."""
    config = config["device_tracker"]  # Extract device_tracker section from config
    scanner = Cisco9800DeviceScanner(config)  # Create scanner instance
    await scanner.async_setup_scanner()  # ✅ Properly await scanner setup
    
    if not scanner.available:  # Verify connectivity
        _LOGGER.error("Unable to connect to Cisco 9800 WLC via RESTCONF API")
        return None  # Return None if connection fails
    return scanner  # Return working scanner
# Global cache for device data (shared across all threads)
GLOBAL_DEVICE_CACHE = {}  # Stores {MAC: client_data}
GLOBAL_LAST_UPDATE = 0  # Tracks the last time the cache was updated
GLOBAL_CACHE_LOCK = asyncio.Lock()  # Prevents race conditions

# Custom device scanner class for Cisco 9800 WLC
class Cisco9800DeviceScanner(DeviceScanner):
    """Scanner for devices connected to a Cisco 9800 WLC via RESTCONF."""

    def __init__(self, config: ConfigType) -> None:
        """Initialize the scanner with configuration parameters."""
        # Store required config values
        self.last_results = {}  # 🟢 Store cached device data
        self.last_update = 0  # 🟢 Track the last time data was fetched
        self.host = config[CONF_HOST]  # WLC host address
        self.username = config[CONF_USERNAME]  # API username
        self.password = config[CONF_PASSWORD]  # API password
        self.verify_ssl = config[CONF_VERIFY_SSL]  # SSL verification flag
        self.scan_interval = config.get("scan_interval", DEFAULT_SCAN_INTERVAL)
        if isinstance(self.scan_interval, timedelta):
            self.scan_interval = self.scan_interval.total_seconds()
        else:
            self.scan_interval = float(self.scan_interval)  # 🟢 Ensure it's always a float



        # Set base URL, defaulting to standard RESTCONF path if not provided
        self.base_url = config.get("base_url", f"https://{self.host}/restconf/data")
        # Assign RESTCONF endpoints, falling back to defaults
        self.ap_oper = config.get("ap_oper", DEFAULT_AP_OPER)
        self.wlan_config = config.get("wlan_config", DEFAULT_WLAN_CONFIG)
        self.rrm_oper = config.get("rrm_oper", DEFAULT_RRM_OPER)
        self.client_oper = config.get("client_oper", DEFAULT_CLIENT_OPER)

        # Configure global variables for API functions (not ideal, but functional)
        global API_USER, API_PASSWORD, BASE_URL, CLIENT_OPER, AP_OPER, WLAN_CONFIG
        API_USER = self.username
        API_PASSWORD = self.password
        BASE_URL = self.base_url
        CLIENT_OPER = self.client_oper
        AP_OPER = self.ap_oper
        WLAN_CONFIG = self.wlan_config

        self.last_results: dict[str, dict] = {}  # Dictionary to store MAC -> client data mappings
        self.available = False  # Default to False before connection check
       
            

    @property
    def should_poll(self) -> bool:
        """Tell Home Assistant to use our internal scan logic instead of polling every 10s."""
        return False  # 🟢 This stops HA from forcing updates every 10 seconds.


    def _should_update(self) -> bool:
        """Check if cache is older than scan_interval (converted to seconds)."""
        return (time.time() - self.last_update) >= self.scan_interval


    async def _test_connection(self) -> bool:
        """Test connectivity by attempting to fetch client data."""
        try:
            data = await get_common_oper_data()
            _LOGGER.info("Connected to Cisco 9800 WLC via RESTCONF API")
            return True  # ✅ Must return True if successful
        except Exception as e:
             _LOGGER.error("Connection test failed: %s", e)
             return False  # ✅ Must return False if an error occurs
    
    async def async_setup_scanner(self):
         """Set up the scanner asynchronously."""
         self.available = await self._test_connection()


    async def _update_info(self) -> None:
        """Fetch new data only if the global cache is stale."""
        global GLOBAL_DEVICE_CACHE, GLOBAL_LAST_UPDATE

        if not self._should_update():
            return  # 🟢 Skip API call if cache is still valid

        async with GLOBAL_CACHE_LOCK:  # 🟢 Prevent multiple threads from updating at the same time
            try:
                _LOGGER.info("Fetching new client data from WLC...")
                data = await get_common_oper_data()  # Fetch all clients **once**
                new_results = {}

                # Process each client entry in the response
                for client in data.get("Cisco-IOS-XE-wireless-client-oper:common-oper-data", []):
                    mac = client.get("client-mac", "").lower()  # Normalize MAC
                    if mac:
                        new_results[mac] = client  # Store in cache
                
                # 🟢 Update global cache
                GLOBAL_DEVICE_CACHE = new_results
                GLOBAL_LAST_UPDATE = time.time()

                _LOGGER.info(f"Updated cache with {len(new_results)} devices.")

            except Exception as e:
                _LOGGER.error("Error updating client data: %s", e)

    async def async_scan_devices(self) -> list[str]:
        """Return a list of connected device MAC addresses, using cached data."""
        await self._update_info()  # 🟢 Now async
        return list(self.last_results.keys())

    def get_extra_attributes(self, device: str) -> dict:
        """Return extra attributes for a device using the global cache."""
        global GLOBAL_DEVICE_CACHE  # Ensure we use the shared cache

        # 🟢 Check if device exists in the cached data
        if device not in GLOBAL_DEVICE_CACHE:
            _LOGGER.warning("Device %s not found in cached data", device)
            return {}  # Return empty dict if device is missing

        client_info = GLOBAL_DEVICE_CACHE.get(device, {})

        # 🟢 Extract necessary attributes, preserving commented-out code
        return {
            "Access Point Name": client_info.get("ap-name"),
            # "Client State": client_info.get("co-state"),
            "Username": client_info.get("username"),
            # "dot11-state": client_info.get("dot11-state"),
            "SSID": client_info.get("vap-ssid"),
            "Current Channel": client_info.get("current-channel"),
            "Connection Speed": client_info.get("speed"),
            "IP Address": client_info.get("ip-address"),
            "Device Type": client_info.get("device-type"),
            "Device OS": client_info.get("device-os"),
            "Device Name": client_info.get("device-name"),
        }


    async def _async_get_extra_attributes(self, device: str) -> dict:
        """Actual async method to fetch additional client data."""
        try:
            # Fetch data from different sections
            common_data = await get_common_oper_data() or {}
            dot11_data = await get_dot11_oper_data() or {}
            # mobility_data = await get_mobility_history() or {}
            traffic_data = await get_traffic_stats() or {}
            sisf_data = await get_sisf_db_mac() or {}
            dc_info_data = await get_dc_info() or {}
            ap_data = await get_ap_list() or {}

            ap_mapping = {}
            if "Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map" in ap_data:
                ap_mapping = {
                    ap.get("wtp-mac", "").lower(): ap.get("wtp-name", "Unknown AP")
                    for ap in ap_data["Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map"]
                }

            # Extract clients from each section
            common_clients = common_data.get("Cisco-IOS-XE-wireless-client-oper:common-oper-data", [])
            dot11_clients = dot11_data.get("Cisco-IOS-XE-wireless-client-oper:dot11-oper-data", [])
            # mobility_clients = mobility_data.get("Cisco-IOS-XE-wireless-client-oper:mm-if-client-history", [])
            traffic_clients = traffic_data.get("Cisco-IOS-XE-wireless-client-oper:traffic-stats", [])
            sisf_clients = sisf_data.get("Cisco-IOS-XE-wireless-client-oper:sisf-db-mac", [])  # 🟢
            dc_clients = dc_info_data.get("Cisco-IOS-XE-wireless-client-oper:dc-info", [])  # 🔵

            # Find matching client in common-oper-data
            client_info = next((client for client in common_clients if client.get("client-mac", "").lower() == device), {})

            # Find matching client in dot11-oper-data
            dot11_info = next((client for client in dot11_clients if client.get("ms-mac-address", "").lower() == device), {})
            
            # Find matching client in mobility history
            # mobility_info = next((client for client in mobility_clients if client.get("client-mac", "").lower() == device), {})
            sisf_info = next((client for client in sisf_clients if client.get("mac-addr", "").lower() == device), {})

            # Find matching client in dot11-oper-data
            traffic_info = next((client for client in traffic_clients if client.get("ms-mac-address", "").lower() == device), {})

            ipv4_address = None
            ipv4_bindings = sisf_info.get("ipv4-binding", [])
            if isinstance(ipv4_bindings, dict):
                ipv4_bindings = [ipv4_bindings]  # Convert single dict to list

            # Extract the first IP address found
            if ipv4_bindings:
                ipv4_address = ipv4_bindings[0].get("ip-key", {}).get("ip-addr")

            # 🔵 Find matching client in dc-info (Device Classification)
            dc_info = next((client for client in dc_clients if client.get("client-mac", "").lower() == device), {})

            # Extract MAC addresses from dot11k-neighbor-list
            raw_neighbors = dot11_info.get("dot11k-neighbor-list", {}).get("dot11k-neighbor", [])

            # Normalize to always be a list
            neighbor_macs = raw_neighbors if isinstance(raw_neighbors, list) else [raw_neighbors]

            # Convert MACs to AP Names using ap_mapping
            neighbor_ap_names = [ap_mapping.get(mac.lower(), mac) for mac in neighbor_macs]

            # **Keep only the parent mobility-history section**
            # mobility_history = mobility_info.get("mobility-history", {})

            # Return filtered data
            return {
                "Access Point Name": client_info.get("ap-name"),
                #"Client State": client_info.get("co-state"),
                "Username": client_info.get("username"),
                #"dot11-state": dot11_info.get("dot11-state"),
                "SSID": dot11_info.get("vap-ssid"),
                "Current Channel": dot11_info.get("current-channel"),
                "dot11k-neighbor-list": neighbor_ap_names,  # List of neighboring APs
                "ms-wifi": dot11_info.get("ms-wifi"),  # WiFi security details
                "Connection Speed": traffic_info.get("speed"),
                "IP Address": ipv4_address,
                "Device Type": dc_info.get("device-type"),
                "Device OS": dc_info.get("device-os"),
                "Device Name": dc_info.get("device-name"),
            }

        except Exception as e:
            _LOGGER.error("Error fetching extra attributes: %s", e)

        return {}  # Return empty dict if not found

    def get_device_name(self, device: str) -> str:
            """Return a name for the device; here, just the MAC address."""
            # Note: Could potentially use client data (e.g., hostname) if available
            return device  # MAC serves as the identifier

###############################################################################
# END DEVICE SCANNER IMPLEMENTATION
###############################################################################