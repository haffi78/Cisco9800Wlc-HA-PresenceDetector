"""coordinator.py"""
import json
import logging
import aiohttp
import asyncio
import locale
import re
from urllib.parse import quote
import xml.etree.ElementTree as ET
from datetime import timedelta
from datetime import datetime
from .const import DEFAULT_TRACK_NEW ,DOMAIN  
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_VERIFY_SSL
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler


_LOGGER = logging.getLogger(__name__)
SCAN_INTERVAL = timedelta(seconds=120)

PER_CLIENT_URLS = {
    "common": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data={mac}",
    "dot11": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data={mac}",
    "device": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info={mac}",
    "speed": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats={mac}/speed",
    "roaming_history": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/mm-if-client-history={mac}/mobility-history",
}

def format_roaming_time(timestamp):
    """
    Convert ISO 8601 timestamp to 'HH:MM:SS - DD Month' format.
    
    Example:
    - Input: "2025-03-12T22:04:19+00:00"
    - Output: "22:04:19 - 12 March"
    """
    try:
        #  Convert to datetime object
        dt = datetime.fromisoformat(timestamp)

        #  Set locale for month name translation (adjust based on language)
        locale.setlocale(locale.LC_TIME, "en_US.UTF-8")  # Change as needed ("sv_SE.UTF-8" for Swedish)

        #  Format: "22:04:19 - 12 March"
        return dt.strftime("%H:%M:%S - %d %B")

    except ValueError:
        return timestamp

class CiscoWLCUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator to manage Cisco 9800 WLC API polling."""

    def __init__(self, hass: HomeAssistant, config: dict):
        super().__init__(
            hass, _LOGGER, name=DOMAIN, update_interval=SCAN_INTERVAL
        )
        self.hass = hass
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self.verify_ssl = not config.get(CONF_VERIFY_SSL, False)

        self.api_url = f"https://{self.host}/restconf/data"
        self.data = {}
        self.session = async_get_clientsession(hass, verify_ssl=self.verify_ssl)
        self.api_semaphore = asyncio.Semaphore(5)  # Limit concurrent API requests to 5

        #  Store authentication **once** in `self.auth`
        self.auth = aiohttp.BasicAuth(self.username, self.password)

        hass.loop.create_task(self.delayed_first_scan())
############################################################################################################

    async def async_fetch_initial_status(self):
        """Fetch the WLC status immediately after setup."""
  
        await self.fetch_wlc_status()  # Manually trigger it at setup


############################################################################################################


    async def delayed_first_scan(self):
        """Wait a short time after startup, then run the first full scan."""
    
        await asyncio.sleep(2)  # Wait 10 seconds after HA starts
        await self._async_update_data()  # Now do the first full scan
   

############################################################################################################

    async def _async_update_data(self):
        """Fetch all connected clients from Cisco WLC but only update tracked entities."""

        try:
            url = f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac"
            headers = {"Accept": "application/yang-data+json"}

            async with self.session.get(url, headers=headers, auth=self.auth) as response:
                response_text = await response.text()

                if response.status == 409:  # API Overload (Too many sessions)
                    _LOGGER.warning("WLC API Overload (Too many sessions). Skipping this update cycle.")
                    return self.coordinator.data  #  Return existing data to avoid overwriting

                if response.status != 200:
                    _LOGGER.error(f"HTTP {response.status}: Error fetching client list - {response_text}")
                    raise UpdateFailed(f"HTTP {response.status}: {response_text}")

                try:
                    data = await response.json()
                except Exception as json_err:
                    _LOGGER.error(f"JSON Parsing Error: {json_err} - Response: {response_text}")
                    raise UpdateFailed("JSON Parsing Error")

            #  Get the list of currently active clients (only those in the WLC response)
            clients = data.get("Cisco-IOS-XE-wireless-client-oper:sisf-db-mac", [])
            if not isinstance(clients, list):
                _LOGGER.error(f"Unexpected response format from WLC: {data}")
                raise UpdateFailed("Unexpected response format from WLC")

            #  Get currently tracked MACs (from HA)
            tracked_macs = self.get_tracked_macs()

            #  Extract MACs seen in the latest WLC scan
            active_macs = {client.get("mac-addr", "").lower() for client in clients if client.get("mac-addr")}

            #  Find MACs that are both tracked and currently active
            tracked_and_active_macs = tracked_macs & active_macs  # Intersection of both sets

            #  Prepare updated client data (ALL active MACs get at least their IP)
            client_data = {}

            for client in clients:
                mac = client.get("mac-addr", "").lower()
                if not mac:
                    continue  # Skip invalid MACs

                # Extract and store IPv4 address
                ip_entry = client.get("ipv4-binding", {}).get("ip-key", {})
                ipv4_address = ip_entry.get("ip-addr", "N/A")

                #  Store ALL active MACs with basic data
                client_data[mac] = {"IP Address": ipv4_address}

            #  Fetch attributes only for tracked & active MACs
            tasks = [self.fetch_attributes(mac) for mac in tracked_and_active_macs]

            attribute_results = []
            for i in range(0, len(tasks), 5):  # Process in batches of 5
                batch = tasks[i:i+5]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)  # Await and store results
                attribute_results.extend(batch_results)
                await asyncio.sleep(0.1)  # Add small delay after each batch

            #  Merge attributes into the final client_data (only for tracked MACs)
            for mac, attributes in zip(tracked_and_active_macs, attribute_results):
                if isinstance(attributes, dict) and attributes:
                    for key, value in attributes.items():
                        if value not in [None, ""]:  # ✅ Only update non-empty values
                            client_data[mac][key] = value
                elif isinstance(attributes, Exception):
                    _LOGGER.error(f"Error fetching attributes for {mac}: {attributes}")
                else:
                    _LOGGER.warning(f"Skipping empty attributes for {mac}")

            #  Log final processed data before sending to HA
            # _LOGGER.debug(f"Final Processed Client Data (All Active MACs Sent to HA, Extra for Tracked): {client_data}")

            #  Send ALL active MACs (basic data for all, enriched for tracked)
            self.async_set_updated_data(client_data)  # Ensure HA gets updates!

            return client_data

        except UpdateFailed as update_err:
            _LOGGER.error(f"UpdateFailed Error: {update_err}")
            raise

        except Exception as err:
            _LOGGER.warning(f"Unexpected error fetching WLC data: {str(err)}")
            raise UpdateFailed(f"Unexpected error: {str(err)}")

############################################################################################################

    async def fetch_wlc_status(self):
        """Fetch the WLC online status and software version using the existing connection."""

        

        async with self.api_semaphore:
            status_url = f"{self.api_url}/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-system-data/software-version"
            headers = {"Accept": "application/yang-data+json"}

            if not self.session or self.session.closed:
                _LOGGER.error(" [DEBUG] No active session. Cannot fetch WLC status.")
                return

            try:
               
                 async with self.session.get(status_url, headers=headers, auth=self.auth, timeout=3) as response:
                    
                    if response.status != 200:
                        response_text = await response.text()
                        _LOGGER.error(f" [DEBUG] HTTP {response.status}: Error fetching WLC status - {response_text}")
                        return

                    data = await response.json()
                    software_version = data.get("Cisco-IOS-XE-device-hardware-oper:software-version", "N/A").strip()

                    #  Store WLC status separately in `coordinator.data`
                    self.data["wlc_status"] = {
                        "software_version": software_version,
                        "online_status": "Online" if software_version != "N/A" else "Offline",
                    }

                    #  Notify Home Assistant to refresh entities
                    self.async_set_updated_data(self.data)  

                    #  Force the WLC Status entity to refresh in HA UI
                    wlc_status_entity = self.hass.data[DOMAIN].get("wlc_status_entity")
                    if wlc_status_entity:
                        
                        wlc_status_entity.async_write_ha_state()
                    

            except asyncio.TimeoutError:
                _LOGGER.error(" [DEBUG] API request timed out!")

            except Exception as e:
                _LOGGER.error(f" [DEBUG] Unexpected error fetching WLC status: {e}")

############################################################################################################

    def get_tracked_macs(self):
        """Retrieve a set of valid MAC addresses that Home Assistant is actively tracking 
        and belong to this integration's domain.
        """
        # Regex patterns for different MAC address formats
        MAC_REGEX_COLON = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")  # 00:1A:2B:3C:4D:5E
        MAC_REGEX_HYPHEN = re.compile(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$")  # 12-34-56-78-9A-BC
        MAC_REGEX_CISCO = re.compile(r"^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")  # 001a.23d4.3aa2

        def normalize_mac(mac: str) -> str | None:
            """Convert MAC addresses into a standard colon-separated format."""
            mac = mac.lower().strip()  # Convert to lowercase & remove spaces

            if MAC_REGEX_COLON.match(mac):
                return mac  # Already in correct format
            
            if MAC_REGEX_HYPHEN.match(mac):
                return mac.replace("-", ":")  # Convert hyphens to colons
            
            if MAC_REGEX_CISCO.match(mac):
                # Convert from Cisco format (001a.23d4.3aa2) to colon-separated
                return ":".join(mac.replace(".", "").upper()[i:i+2] for i in range(0, 12, 2))

            return None  # Invalid format

        entity_registry = er.async_get(self.hass)  # Get entity registry
        tracked_macs = set()

        for entity_id, entity in entity_registry.entities.items():
            if (
                entity_id.startswith("device_tracker.")  # Ensure it's a device tracker
                and not entity.disabled  # Ensure it's enabled
                and entity.platform == DOMAIN  # Ensure it belongs to this integration's domain
                and entity.unique_id  # Ensure it has a unique ID
            ):
                normalized_mac = normalize_mac(entity.unique_id)
                if normalized_mac:
                    tracked_macs.add(normalized_mac)
               
            _LOGGER.debug(f"This is the tracked macs {tracked_macs}")
        return tracked_macs
############################################################################################################

    async def fetch_attributes(self, mac):
        """Fetch multiple attributes for a tracked MAC address from Cisco WLC, handling API limits."""

        async with self.api_semaphore:  # Prevents API flooding (Max concurrent requests)
            encoded_mac = quote(mac, safe="")  # Properly encode the MAC address
            attributes = {}
            attributes["last_updated_time"] = datetime.now().strftime("%H:%M:%S")
            #  Check if `dc-info` has already been fetched for this MAC
            has_dc_info = all(
                attributes.get(attr) not in [None, "", "Unknown", "N/A"]
                for attr in ["device-name", "device-type", "device-os"]
            )
            
            #  Define API calls (fetch everything except `dc-info` if already known)
            url_mapping = {
                "common": f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data={encoded_mac}",
                "dot11": f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data={encoded_mac}",
                "speed": f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats={encoded_mac}/speed",
                "roaming_history": f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/mm-if-client-history={encoded_mac}/mobility-history",
            }

            #  Only fetch `dc-info` if it hasn’t been retrieved before
            if not has_dc_info:
                url_mapping["device"] = f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info={encoded_mac}"

            headers = {"Accept": "application/yang-data+json"}
           

            await asyncio.sleep(0.1)  #  Small delay to avoid API rate limits

            #  Fetch API data asynchronously
            tasks = {key: self.session.get(url, headers=headers, auth=self.auth) for key, url in url_mapping.items()}
            responses = await asyncio.gather(*tasks.values(), return_exceptions=True)

            is_wireless = False  # Default assumption

            #  Process API responses
            for (key, response) in zip(tasks.keys(), responses):
                if isinstance(response, Exception):
                    _LOGGER.error(f"fetch_attributes: Request failed for {key} ({mac}): {response}")
                    continue

                try:
                    response_text = await response.text()

                    if response.status == 409:  # API Overload
                        _LOGGER.warning(f"WLC API Overload (Too many sessions): Skipping {mac}.")
                        return self.data.get(mac, {})  #  Keep existing data, avoid overwriting

                    if response.status == 404:
                        continue
                    elif response.status != 200:
                        continue

                    data = await response.json()
                    root_key = list(data.keys())[0]
                    items = data[root_key]

                    if isinstance(items, list) and len(items) > 0:
                        items = items[0]  #  Extract first item from list

                    if key == "speed" and isinstance(items, int):
                        attributes["speed"] = items
                        
                        continue  #  Speed is just an integer, no further processing needed

                    if not isinstance(items, dict):
                        continue

                    #  Process `common` attributes (Determining if WiFi or wired)
                    if key == "common":
                        attributes["ap-name"] = items.get("ap-name", "Wired Connection" if "ap-name" not in items else items["ap-name"])
                        attributes["username"] = items.get("username", None)
                        is_wireless = bool(attributes["ap-name"])  #  True if AP name exists
                        

                    #  Process `dot11` attributes
                    elif key == "dot11":
                        attributes["current-channel"] = items.get("current-channel", None if is_wireless else None)
                        attributes["auth-key-mgmt"] = items.get("ms-wifi", {}).get("auth-key-mgmt", None)
                        attributes["ssid"] = items.get("vap-ssid", None)
                        attributes["WifiStandard"] = items.get("ewlc-ms-phy-type", "Unknown")

                    #  Process `dc-info` (Only fetched if missing in `self.data`)
                    elif key == "device":
                        attributes["device-name"] = items.get("device-name", None)
                        attributes["device-type"] = items.get("device-type", None)
                        attributes["device-os"] = items.get("device-os", None)

                    #  Process `roaming_history`
                    elif key == "roaming_history":
                        mobility_entries = items.get("entry", [])

                        if isinstance(mobility_entries, list):
                            #  Ensure entries are sorted correctly (most recent first)
                            mobility_entries.sort(key=lambda x: x.get("ms-assoc-time", 0), reverse=True)

                            formatted_roaming = []
                            for entry in mobility_entries:
                                ap_name = entry.get("ap-name", "Unknown AP")
                                raw_time = entry.get("ms-assoc-time", "")

                                #  Use the helper function to format the time
                                formatted_time = format_roaming_time(raw_time)

                                formatted_roaming.append(f"Roamed: {ap_name} at {formatted_time}")

                            #  Assign formatted timestamps
                            if formatted_roaming:
                                attributes["most_recent_roam"] = formatted_roaming[0] if len(formatted_roaming) > 0 else None
                                attributes["previous_roam_1"] = formatted_roaming[1] if len(formatted_roaming) > 1 else None
                                attributes["previous_roam_2"] = formatted_roaming[2] if len(formatted_roaming) > 2 else None
                                attributes["previous_roam_3"] = formatted_roaming[3] if len(formatted_roaming) > 3 else None

                except Exception as err:
                    _LOGGER.error(f"Error processing {key} attributes for MAC {mac}: {err}")
            
            #  **Persist the fetched attributes in `self.data` to keep across update cycles**
            self.data[mac] = attributes

            return attributes