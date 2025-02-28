from __future__ import annotations  # Allows forward references in type hints, improving readability for modern Python
import logging  # For logging debug/info/error messages throughout the script
import json  # To parse JSON responses from the RESTCONF API
from datetime import timedelta  # Used for representing scan intervals as time durations
import voluptuous as vol  # Validation library to enforce config schema in Home Assistant
import requests  # Core library for making HTTP requests to the Cisco RESTCONF API
from requests.auth import HTTPBasicAuth  # Provides basic authentication for API requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # To suppress SSL warnings

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

# Set up a logger specific to this module for consistent logging
_LOGGER = logging.getLogger(__name__)

# Define default constants for RESTCONF endpoints and scanner behavior
DEFAULT_SCAN_INTERVAL = 30  # Default polling interval in seconds (30s is reasonable for network devices)
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
def get_common_oper_data():
    _check_api_config()  # Validate config
    url = BASE_URL + CLIENT_OPER + "/common-oper-data"  # Build full endpoint URL
    headers = {"Accept": "application/yang-data+json"}  # Request YANG-structured JSON
    response = requests.get(url, headers=headers, verify=False,  # Skip SSL check
                            auth=HTTPBasicAuth(API_USER, API_PASSWORD))  # Authenticate
    return json.loads(response.text)  # Return parsed JSON data

# Fetch 802.11-specific client data (e.g., signal strength, channel)
def get_dot11_oper_data():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/dot11-oper-data"
    headers = {"Accept": "application/yang-data+json"}
    response = requests.get(url, headers=headers, verify=False,
                            auth=HTTPBasicAuth(API_USER, API_PASSWORD))
    return json.loads(response.text)

# Fetch client traffic statistics (e.g., bytes sent/received)
def get_traffic_stats():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/traffic-stats"
    headers = {"Accept": "application/yang-data+json"}
    response = requests.get(url, headers=headers, verify=False,
                            auth=HTTPBasicAuth(API_USER, API_PASSWORD))
    return json.loads(response.text)

# Fetch SISF (Security Information and Event Management) MAC database info
def get_sisf_db_mac():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/sisf-db-mac"
    headers = {"Accept": "application/yang-data+json"}
    response = requests.get(url, headers=headers, verify=False,
                            auth=HTTPBasicAuth(API_USER, API_PASSWORD))
    return json.loads(response.text)

# Fetch device classifier info (e.g., device type or category)
def get_dc_info():
    _check_api_config()
    url = BASE_URL + CLIENT_OPER + "/dc-info"
    headers = {"Accept": "application/yang-data+json"}
    response = requests.get(url, headers=headers, verify=False,
                            auth=HTTPBasicAuth(API_USER, API_PASSWORD))
    return json.loads(response.text)

# Fetch list of access points with name-MAC mappings
def get_ap_list():
    _check_api_config()
    url = BASE_URL + AP_OPER + "/ap-name-mac-map"
    headers = {"Accept": "application/yang-data+json"}
    response = requests.get(url, headers=headers, verify=False,
                            auth=HTTPBasicAuth(API_USER, API_PASSWORD))
    return json.loads(response.text)

# Fetch WLAN configuration details (e.g., SSIDs, security settings)
def get_wlan_list():
    _check_api_config()
    url = BASE_URL + WLAN_CONFIG + "/wlan-cfg-entries/wlan-cfg-entry"
    headers = {"Accept": "application/yang-data+json"}
    response = requests.get(url, headers=headers, verify=False,
                            auth=HTTPBasicAuth(API_USER, API_PASSWORD))
    return json.loads(response.text)

# Retrieve AP details (name and MAC) by AP name
def get_ap_info_by_ap_name(ap_name):
    _check_api_config()
    ap_list = get_ap_list()  # Get full AP list
    ap_mac = "nomac"  # Fallback MAC if no match is found
    # Iterate through AP list to find matching name
    for item in ap_list.get("Cisco-IOS-XE-wireless-access-point-oper:ap-name-mac-map", []):
        if ap_name == item.get("wtp-name"):  # Check for name match
            ap_mac = item.get("wtp-mac")  # Extract MAC if found
            break
    return {"ap_name": ap_name, "ap_mac": ap_mac}  # Return AP info

###############################################################################
# END RESTCONF API FUNCTIONS
###############################################################################

###############################################################################
# BEGIN DEVICE SCANNER IMPLEMENTATION
###############################################################################

# Factory function to initialize and return the scanner (required by Home Assistant)
def get_scanner(hass: HomeAssistant, config: ConfigType) -> Cisco9800DeviceScanner | None:
    """Set up the Cisco 9800 WLC Device Tracker using RESTCONF."""
    config = config["device_tracker"]  # Extract device_tracker section from config
    scanner = Cisco9800DeviceScanner(config)  # Create scanner instance
    if not scanner.available:  # Verify connectivity
        _LOGGER.error("Unable to connect to Cisco 9800 WLC via RESTCONF API")
        return None  # Return None if connection fails
    return scanner  # Return working scanner

# Custom device scanner class for Cisco 9800 WLC
class Cisco9800DeviceScanner(DeviceScanner):
    """Scanner for devices connected to a Cisco 9800 WLC via RESTCONF."""

    def __init__(self, config: ConfigType) -> None:
        """Initialize the scanner with configuration parameters."""
        # Store required config values
        self.host = config[CONF_HOST]  # WLC host address
        self.username = config[CONF_USERNAME]  # API username
        self.password = config[CONF_PASSWORD]  # API password
        self.scan_interval = config["scan_interval"]  # Polling interval (timedelta)
        self.verify_ssl = config[CONF_VERIFY_SSL]  # SSL verification flag

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
        self.available = self._test_connection()  # Check if WLC is reachable on init

    def _test_connection(self) -> bool:
        """Test connectivity by attempting to fetch client data."""
        try:
            data = get_common_oper_data()  # Simple connectivity test using client data endpoint
            _LOGGER.info("Connected to Cisco 9800 WLC via RESTCONF API")
            return True
        except Exception as e:  # Broad exception catch for initial testing
            _LOGGER.error("Connection test failed: %s", e)
            return False

    def _update_info(self) -> None:
        """Fetch and store the latest client data from the WLC."""
        try:
            data = get_common_oper_data()  # Retrieve client operational data
            new_results = {}
            # Process each client entry in the response
            for client in data.get("Cisco-IOS-XE-wireless-client-oper:common-oper-data", []):
                mac = client.get("client-mac", "").lower()  # Normalize MAC to lowercase
                if mac:  # Only store if MAC exists
                    new_results[mac] = client  # Map MAC to full client data
            self.last_results = new_results  # Update stored results
            _LOGGER.debug("Updated client data: %s", self.last_results)
        except Exception as e:
            _LOGGER.error("Error updating client data: %s", e)

    def scan_devices(self) -> list[str]:
        """Scan for connected devices and return their MAC addresses."""
        self._update_info()  # Refresh data before returning
        return list(self.last_results.keys())  # Return list of detected MACs

    def get_extra_attributes(self, device: str) -> dict:
        """Return additional client data for a specific device."""
        return self.last_results.get(device, {})  # Return client data or empty dict if not found

    def get_device_name(self, device: str) -> str:
        """Return a name for the device; here, just the MAC address."""
        # Note: Could potentially use client data (e.g., hostname) if available
        return device  # MAC serves as the identifier

###############################################################################
# END DEVICE SCANNER IMPLEMENTATION
###############################################################################