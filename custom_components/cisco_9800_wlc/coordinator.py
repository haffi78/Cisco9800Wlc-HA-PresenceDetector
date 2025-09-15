"""coordinator.py"""
import json
import logging
import aiohttp
import asyncio
import re
from urllib.parse import quote
from datetime import timedelta
from datetime import datetime
from .const import DOMAIN, CONF_IGNORE_SSL, SIGNAL_NEW_CLIENTS
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.storage import Store

_LOGGER = logging.getLogger(__name__)
SCAN_INTERVAL = timedelta(seconds=120)
DEBUG_LOG_PAYLOADS = False  # set True temporarily when inspecting raw payloads
DEBUG_PAYLOAD_MAX_CHARS = 10000  # truncate long payloads in debug logs

# Dispatcher signal name used to announce newly discovered clients (MACs)

PER_CLIENT_URLS = {
    "common": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data={mac}",
    "dot11": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data={mac}",
    "device": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info={mac}",
    "speed": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats={mac}/speed",
    "roaming_history": "/Cisco-IOS-XE-wireless-client-oper:client-oper-data/mm-if-client-history={mac}/mobility-history",
}

def _is_meaningful(value) -> bool:
    """Return True if value is meaningful (not empty/placeholder).

    Treats None, empty/whitespace, and common placeholders like
    'unknown', 'n/a', 'na' (any case) as not meaningful.
    """
    if value is None:
        return False
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return False
        lowered = s.lower()
        if lowered in {"unknown", "n/a", "na"}:
            return False
    return True

def _parse_to_local_datetime(value):
    """Parse various time formats to a timezone-aware local datetime.

    Supports:
    - ISO8601 (e.g., '2025-03-12T22:04:19+00:00', '2025-03-12T22:04:19Z')
    - Cisco-style 'MM/DD/YYYY HH:MM:SS'
    - Epoch seconds or milliseconds (int/str)
    Returns None if parsing fails.
    """
    local_tz = datetime.now().astimezone().tzinfo

    # Epoch integers (or numeric strings)
    if isinstance(value, (int, float)):
        try:
            # Heuristic: ms vs s
            ts = float(value)
            if ts > 1e12:
                ts = ts / 1000.0
            dt = datetime.fromtimestamp(ts)
            return dt.astimezone(local_tz)
        except Exception:
            return None

    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    # Try ISO8601; handle trailing Z
    try:
        iso = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=local_tz)
        return dt.astimezone(local_tz)
    except Exception:
        pass

    # Try Cisco UI format: MM/DD/YYYY HH:MM:SS
    try:
        dt = datetime.strptime(s, "%m/%d/%Y %H:%M:%S")
        dt = dt.replace(tzinfo=local_tz)
        return dt
    except Exception:
        pass

    # Try numeric string epoch
    try:
        ts = float(s)
        if ts > 1e12:
            ts = ts / 1000.0
        dt = datetime.fromtimestamp(ts)
        return dt.astimezone(local_tz)
    except Exception:
        pass

    return None


def format_roaming_time(value):
    """Format various roaming timestamps to 'HH:MM:SS - DD Month' local time.
    Returns empty string when parsing fails or timestamp is zero/invalid.
    """
    dt = _parse_to_local_datetime(value)
    if not dt:
        return ""
    # Treat epoch/very old dates as invalid for display
    try:
        if int(dt.timestamp()) == 0 or dt.year < 1980:
            return ""
    except Exception:
        return ""
    return dt.strftime("%H:%M:%S - %d %B")

def extract_semver_from_version_string(text: str) -> str:
    """Extract x.y.z semantic version from a Cisco version string.

    Examples:
    - "... Version 17.15.3, RELEASE ..." -> "17.15.3"
    - "17.15.3" -> "17.15.3"
    Falls back to the original trimmed text if no match.
    """
    if not isinstance(text, str):
        return "n/a"
    s = text.strip()
    # Prefer explicit "Version <semver>"
    m = re.search(r"\bVersion\s+(\d+\.\d+\.\d+)\b", s, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    # Fallback: any first x.y.z occurrence
    m = re.search(r"\b(\d+\.\d+\.\d+)\b", s)
    if m:
        return m.group(1)
    return s or "n/a"

# MAC address patterns
MAC_REGEX_COLON = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")  # 00:1A:2B:3C:4D:5E
MAC_REGEX_HYPHEN = re.compile(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$")  # 12-34-56-78-9A-BC
MAC_REGEX_CISCO = re.compile(r"^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")  # 001a.23d4.3aa2

class CiscoWLCUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator to manage Cisco 9800 WLC API polling."""

    def __init__(self, hass: HomeAssistant, config: dict):
        polling_enabled = not hass.data[DOMAIN].get(config.get("entry_id", ""), {}).get("options", {}).get("disable_polling", False)
        super().__init__(
            hass, _LOGGER, name=DOMAIN, update_interval=SCAN_INTERVAL if polling_enabled else None
        )

        if not polling_enabled:
            _LOGGER.info("Polling is disabled in system options. Updates will only occur manually.")
        else:
            _LOGGER.info(f"Polling is enabled. Update interval: {SCAN_INTERVAL}")
        self.hass = hass
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self.verify_ssl = not config.get(CONF_IGNORE_SSL, False)
        self.entry_id = config.get("entry_id", "")

        self.api_url = f"https://{self.host}/restconf/data"
        self.data = {}
        self.session = async_get_clientsession(hass, verify_ssl=self.verify_ssl)
        self.api_semaphore = asyncio.Semaphore(5)  # Limit concurrent API requests to 5

        #  Store authentication **once** in `self.auth`
        self.auth = aiohttp.BasicAuth(self.username, self.password)

        self.hass.async_create_task(self.delayed_first_scan())
        # Track clients we've already announced as "new"; persist across restarts
        self._announced_new_clients: set[str] = set()
        self._announced_loaded: bool = False
        self._store = Store(self.hass, 1, f"{DOMAIN}_announced_{self.entry_id}")
        # Version fetch cadence control
        self._last_version_fetch: datetime | None = None
        self._version_fetch_interval = timedelta(minutes=10)
        # One-time INFO summary after first successful full scan
        self._first_scan_info_logged = False

    def _set_wlc_status(
        self,
        online: bool | None = None,
        software_version: str | None = None,
        software_version_raw: str | None = None,
        push: bool = False,
    ) -> None:
        """Update controller status and optionally notify HA.

        online: True -> Online, False -> Offline, None -> keep previous
        software_version: set if provided, else keep previous
        push: when True, calls async_set_updated_data(self.data)
        """
        prev = self.data.get("wlc_status", {}) if isinstance(self.data, dict) else {}
        version = software_version if software_version is not None else prev.get("software_version", "n/a")
        version_raw = (
            software_version_raw if software_version_raw is not None else prev.get("software_version_raw", "n/a")
        )
        status = prev.get("online_status", "Unknown")
        if online is True:
            status = "Online"
        elif online is False:
            status = "Offline"
        if not isinstance(self.data, dict):
            self.data = {}
        self.data["wlc_status"] = {
            "software_version": version,
            "software_version_raw": version_raw,
            "online_status": status,
        }
        if push:
            self.async_set_updated_data(self.data)
    def _polling_disabled(self):
        """Return True if polling is disabled in options."""
        opts = self.hass.data.get(DOMAIN, {}).get(self.entry_id, {}).get("options", {})
        return bool(opts.get("disable_polling", False))

    async def _load_announced(self):
        """Load announced MACs from storage once per session."""
        if self._announced_loaded:
            return
        try:
            data = await self._store.async_load()
            if isinstance(data, list):
                self._announced_new_clients = set(m.lower() for m in data)
            self._announced_loaded = True
        except Exception as err:
            _LOGGER.warning(f"Failed to load announced clients: {err}")
            self._announced_loaded = True

    async def _get(self, url: str, timeout: int = 5):
        """HTTP GET helper that safely returns status, json (if any), and text.
        Uses async context manager to ensure connections are released.
        """
        headers = {"Accept": "application/yang-data+json"}
        async with self.session.get(url, headers=headers, auth=self.auth, timeout=timeout) as response:
            status = response.status
            if status == 200:
                try:
                    data = await response.json()
                    if _LOGGER.isEnabledFor(logging.DEBUG) and DEBUG_LOG_PAYLOADS:
                        try:
                            payload = json.dumps(data, ensure_ascii=False)
                            if len(payload) > DEBUG_PAYLOAD_MAX_CHARS:
                                payload = payload[:DEBUG_PAYLOAD_MAX_CHARS] + " …(truncated)"
                            _LOGGER.debug("GET %s -> %s JSON: %s", url, status, payload)
                        except Exception:
                            _LOGGER.debug("GET %s -> %s (JSON, unserializable)", url, status)
                    return status, data, None
                except Exception as json_err:
                    text = await response.text()
                    _LOGGER.error(f"JSON Parsing Error for {url}: {json_err} - Response: {text}")
                    return status, None, text
            else:
                text = await response.text()
                if _LOGGER.isEnabledFor(logging.DEBUG) and DEBUG_LOG_PAYLOADS:
                    trimmed = text if len(text) <= DEBUG_PAYLOAD_MAX_CHARS else text[:DEBUG_PAYLOAD_MAX_CHARS] + " …(truncated)"
                    _LOGGER.debug("GET %s -> %s TEXT: %s", url, status, trimmed)
                return status, None, text

############################################################################################################

    async def async_fetch_initial_status(self):
        """Fetch the WLC status immediately after setup."""
  
        await self.fetch_wlc_status()  # Manually trigger it at setup


############################################################################################################


    async def delayed_first_scan(self):
        """Wait a short time after startup, then run the first full scan, but only if polling is enabled."""
        await asyncio.sleep(2)  # Short delay after startup

        # ✅ Prevent immediate duplicate calls if polling is already scheduled
        if self._polling_disabled():
            _LOGGER.debug("Polling is disabled. Skipping delayed first scan.")
            return

        _LOGGER.debug("Starting delayed first scan.")
        await self._async_update_data()  # Now do the first full scan
   

############################################################################################################

    async def _async_firstrun(self):
        """Fetch all connected clients from Cisco WLC but only update tracked entities."""

        if self._polling_disabled():
            _LOGGER.info(" Polling is disabled via options. Skipping automatic update.")
            return self.data

        try:
            url = f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac"
            headers = {"Accept": "application/yang-data+json"}

            async with self.session.get(url, headers=headers, auth=self.auth, timeout=5) as response:
                if response.status == 409:
                    _LOGGER.warning("WLC API Overload (Too many sessions). Skipping this update cycle.")
                    return self.data

                if response.status != 200:
                    response_text = await response.text()
                    _LOGGER.error(f"HTTP {response.status}: Error fetching client list - {response_text}")
                    # Mark controller Offline on client fetch failure
                    self._set_wlc_status(online=False, push=True)
                    raise UpdateFailed(f"HTTP {response.status}: {response_text}")

                response_text = await response.text()
                try:
                    data = json.loads(response_text)
                except Exception as json_err:
                    _LOGGER.error(f"JSON Parsing Error: {json_err} - Response: {response_text}")
                    self._set_wlc_status(online=False, push=True)
                    raise UpdateFailed("JSON Parsing Error")

            #  Get the list of currently active clients (only those in the WLC response)
            clients = data.get("Cisco-IOS-XE-wireless-client-oper:sisf-db-mac", [])
            if not isinstance(clients, list):
                _LOGGER.error(f"Unexpected response format from WLC: {data}")
                raise UpdateFailed("Unexpected response format from WLC")

            #  Prepare updated client data, preserving existing attributes for active MACs
            client_data = {}

            for client in clients:
                mac = client.get("mac-addr", "").lower()
                if not mac:
                    continue  # Skip invalid MACs

                # Extract IPv4 address
                ip_entry = client.get("ipv4-binding", {}).get("ip-key", {})
                ipv4_address = ip_entry.get("ip-addr", "N/A")

                # Start with any previously known attributes for this MAC
                prev_attrs = self.data.get(mac, {}) if isinstance(self.data, dict) else {}
                merged = dict(prev_attrs)
                merged["IP Address"] = ipv4_address

                # Stage for further attribute enrichment
                client_data[mac] = merged

            # Preserve and update controller status: mark Online after successful client fetch
            updated = {}
            prev_status = self.data.get("wlc_status", {}) if isinstance(self.data, dict) else {}
            updated["wlc_status"] = {
                "software_version": prev_status.get("software_version", "n/a"),
                "software_version_raw": prev_status.get("software_version_raw", "n/a"),
                "online_status": "Online",
            }
            updated.update(client_data)

            # Return the full updated data to the coordinator
            return updated

        except UpdateFailed as update_err:
            _LOGGER.error(f"UpdateFailed Error: {update_err}")
            # Already set Offline above; ensure entities are notified
            self._set_wlc_status(online=False, push=True)
            raise

        except Exception as err:
            _LOGGER.warning(f"Unexpected error fetching WLC data: {str(err)}")
            self._set_wlc_status(online=False, push=True)
            raise UpdateFailed(f"Unexpected error: {str(err)}")

############################################################################################################

    async def _async_update_data(self):
        """Fetch all connected clients from Cisco WLC but only update tracked entities."""

        if self._polling_disabled():
            _LOGGER.info(" Polling is disabled via options. Skipping automatic update.")
            return self.data

        try:
            # Ensure announced set is loaded before detection
            await self._load_announced()
            url = f"{self.api_url}/Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac"
            headers = {"Accept": "application/yang-data+json"}

            async with self.session.get(url, headers=headers, auth=self.auth, timeout=5) as response:
                if response.status == 409:
                    _LOGGER.warning("WLC API Overload (Too many sessions). Skipping this update cycle.")
                    return self.data

                if response.status != 200:
                    response_text = await response.text()
                    _LOGGER.error(f"HTTP {response.status}: Error fetching client list - {response_text}")
                    self._set_wlc_status(online=False, push=True)
                    raise UpdateFailed(f"HTTP {response.status}: {response_text}")

                response_text = await response.text()
                try:
                    data = json.loads(response_text)
                except Exception as json_err:
                    _LOGGER.error(f"JSON Parsing Error: {json_err} - Response: {response_text}")
                    self._set_wlc_status(online=False, push=True)
                    raise UpdateFailed("JSON Parsing Error")

            #  Get the list of currently active clients (only those in the WLC response)
            clients = data.get("Cisco-IOS-XE-wireless-client-oper:sisf-db-mac", [])
            if not isinstance(clients, list):
                _LOGGER.error(f"Unexpected response format from WLC: {data}")
                raise UpdateFailed("Unexpected response format from WLC")

            #  Get enabled tracked MACs (entities enabled in HA)
            enabled_tracked_macs = self.get_enabled_tracked_macs()
            #  Get all registered MACs (includes disabled entries)
            registered_macs = self.get_registered_macs()

            #  Extract MACs seen in the latest WLC scan
            active_macs = {client.get("mac-addr", "").lower() for client in clients if client.get("mac-addr")}
            _LOGGER.debug(f"Active MAC addresses from WLC: {', '.join(active_macs)}")

            #  Find MACs that are both tracked and currently active
            tracked_and_active_macs = enabled_tracked_macs & active_macs

            # New clients = active but not yet in registry, and not previously announced
            new_clients = (active_macs - registered_macs) - self._announced_new_clients
            if new_clients:
                _LOGGER.info("Discovered %d new client(s) not yet enabled in HA", len(new_clients))
                _LOGGER.debug("New client MACs: %s", ", ".join(sorted(new_clients)))
                async_dispatcher_send(self.hass, SIGNAL_NEW_CLIENTS, self, list(new_clients))
                # Remember we've announced these already this session
                self._announced_new_clients.update(new_clients)
                # Persist to storage
                try:
                    await self._store.async_save(sorted(self._announced_new_clients))
                except Exception as err:
                    _LOGGER.debug("Failed to persist announced clients: %s", err)

            #  Prepare updated client data, preserving existing attributes for active MACs
            client_data = {}

            for client in clients:
                mac = client.get("mac-addr", "").lower()
                if not mac:
                    continue  # Skip invalid MACs

                # Extract and store IPv4 address
                ip_entry = client.get("ipv4-binding", {}).get("ip-key", {})
                ipv4_address = ip_entry.get("ip-addr", "N/A")

                # Start with any previously known attributes for this MAC, then update IP
                prev_attrs = self.data.get(mac, {}) if isinstance(self.data, dict) else {}
                merged = dict(prev_attrs)
                merged["IP Address"] = ipv4_address

                client_data[mac] = merged

            #  Fetch attributes only for tracked & active MACs
            tracked_and_active_list = sorted(tracked_and_active_macs)
            tasks = [self.fetch_attributes(mac) for mac in tracked_and_active_list]

            attribute_results = []
            for i in range(0, len(tasks), 5):  # Process in batches of 5
                batch = tasks[i:i+5]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                attribute_results.extend(batch_results)
                await asyncio.sleep(0.1)

            #  Merge attributes into the final client_data (only for tracked MACs)
            for mac, attributes in zip(tracked_and_active_list, attribute_results):
                if isinstance(attributes, dict) and attributes:
                    for key, value in attributes.items():
                        # Only propagate meaningful values to avoid wiping previously known data
                        if _is_meaningful(value):
                            client_data[mac][key] = value
                elif isinstance(attributes, Exception):
                    _LOGGER.error(f"Error fetching attributes for {mac}: {attributes}")
                else:
                    _LOGGER.warning(f"Skipping empty attributes for {mac}")

            #  Log final processed data before sending to HA
            # _LOGGER.debug(f"Final Processed Client Data (All Active MACs Sent to HA, Extra for Tracked): {client_data}")

            #  Send ALL active MACs (basic data for all, enriched for tracked), and mark controller Online on success
            updated = {}
            prev_status = self.data.get("wlc_status", {}) if isinstance(self.data, dict) else {}
            updated["wlc_status"] = {
                "software_version": prev_status.get("software_version", "n/a"),
                "software_version_raw": prev_status.get("software_version_raw", "n/a"),
                "online_status": "Online",
            }
            updated.update(client_data)

            # Trigger a version refresh in the background on a slower cadence
            now = datetime.now()
            if self._last_version_fetch is None or (now - self._last_version_fetch) >= self._version_fetch_interval:
                self._last_version_fetch = now
                self.hass.async_create_task(self.fetch_wlc_status())

            # One-time INFO summary on first successful scan
            if not self._first_scan_info_logged:
                _LOGGER.info(
                    "Initial WLC scan complete: %d active client(s), %d tracked enabled, %d new",
                    len(active_macs), len(enabled_tracked_macs), len(new_clients),
                )
                self._first_scan_info_logged = True

            # Return the full updated data to the coordinator
            return updated

        except UpdateFailed as update_err:
            _LOGGER.error(f"UpdateFailed Error: {update_err}")
            self._set_wlc_status(online=False, push=True)
            raise

        except Exception as err:
            _LOGGER.warning(f"Unexpected error fetching WLC data: {str(err)}")
            self._set_wlc_status(online=False, push=True)
            raise UpdateFailed(f"Unexpected error: {str(err)}")



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
                        _LOGGER.debug("HTTP %s: Error fetching WLC status - %s", response.status, response_text)
                        # Do not flip connectivity on version fetch errors; keep previous status
                        return

                    data = await response.json()
                    # Some versions may wrap the value differently; be defensive
                    sv_key = "Cisco-IOS-XE-device-hardware-oper:software-version"
                    if sv_key in data and isinstance(data[sv_key], str):
                        software_version = data[sv_key].strip()
                    else:
                        # Fallback: stringify any value
                        software_version = str(data.get(sv_key, "N/A")).strip()

                    # Update software version only; do not change connectivity here
                    prev_status = self.data.get("wlc_status", {}) if isinstance(self.data, dict) else {}
                    self.data["wlc_status"] = {
                        "software_version": extract_semver_from_version_string(software_version),
                        "software_version_raw": software_version,
                        "online_status": prev_status.get("online_status", "Unknown"),
                    }

                    # Notify Home Assistant to refresh entities via coordinator update
                    self.async_set_updated_data(self.data)
                    

            except asyncio.TimeoutError:
                _LOGGER.debug("WLC status request timed out")
                # Keep previous connectivity status; do not mark Offline based on version timeout
                
            except Exception as e:
                _LOGGER.debug("Unexpected error fetching WLC status: %s", e)
                # Keep previous connectivity status; do not mark Offline based on version error

############################################################################################################

    def _normalize_mac(self, mac: str) -> str | None:
        """Convert MAC addresses into a standard colon-separated format."""
        mac = (mac or "").lower().strip()
        if MAC_REGEX_COLON.match(mac):
            return mac
        if MAC_REGEX_HYPHEN.match(mac):
            return mac.replace("-", ":")
        if MAC_REGEX_CISCO.match(mac):
            flat = mac.replace(".", "")
            return ":".join(flat[i:i+2] for i in range(0, 12, 2))
        return None

    def get_enabled_tracked_macs(self):
        """MACs of entities that are enabled (actively tracked)."""
        entity_registry = er.async_get(self.hass)
        macs: set[str] = set()
        for entity_id, entity in entity_registry.entities.items():
            if (
                entity_id.startswith("device_tracker.")
                and not entity.disabled
                and entity.platform == DOMAIN
                and entity.unique_id
            ):
                normalized_mac = self._normalize_mac(entity.unique_id)
                if normalized_mac:
                    macs.add(normalized_mac)
        return macs

    def get_registered_macs(self):
        """MACs of all entities registered for this integration (enabled or disabled)."""
        entity_registry = er.async_get(self.hass)
        macs: set[str] = set()
        for entity_id, entity in entity_registry.entities.items():
            if (
                entity_id.startswith("device_tracker.")
                and entity.platform == DOMAIN
                and entity.unique_id
            ):
                normalized_mac = self._normalize_mac(entity.unique_id)
                if normalized_mac:
                    macs.add(normalized_mac)
        return macs
############################################################################################################

    async def fetch_attributes(self, mac):
        """Fetch multiple attributes for a tracked MAC address from Cisco WLC, handling API limits."""
        async with self.api_semaphore:  # Prevents API flooding (Max concurrent requests)
            encoded_mac = quote(mac, safe="")  # Properly encode the MAC address
            attributes = {"last_updated_time": datetime.now().strftime("%H:%M:%S")}

            # Check if we already have device info stored for this MAC
            existing = self.data.get(mac, {}) if isinstance(self.data, dict) else {}
            has_dc_info = all(
                _is_meaningful(existing.get(attr))
                for attr in ["device-name", "device-type", "device-os"]
            )

            # Define API calls from a single source of truth
            def _client_url(key: str) -> str:
                return f"{self.api_url}{PER_CLIENT_URLS[key].format(mac=encoded_mac)}"

            url_mapping = {
                "common": _client_url("common"),
                "dot11": _client_url("dot11"),
                "speed": _client_url("speed"),
                "roaming_history": _client_url("roaming_history"),
            }

            if not has_dc_info:
                url_mapping["device"] = _client_url("device")

            await asyncio.sleep(0.1)  # Small delay to avoid API rate limits

            # Launch requests concurrently via helper with per-endpoint timeouts
            timeouts = {"dot11": 8, "common": 5, "speed": 5, "roaming_history": 5, "device": 5}
            tasks = {key: self._get(url, timeout=timeouts.get(key, 5)) for key, url in url_mapping.items()}
            if _LOGGER.isEnabledFor(logging.DEBUG) and DEBUG_LOG_PAYLOADS:
                _LOGGER.debug("Fetching attributes for %s using URLs: %s", mac, url_mapping)
            responses = await asyncio.gather(*tasks.values(), return_exceptions=True)

            is_wireless = False

            for (key, result) in zip(tasks.keys(), responses):
                if isinstance(result, Exception):
                    _LOGGER.error(f"fetch_attributes: Request failed for {key} ({mac}): {result}")
                    continue

                status, data, text = result

                if status == 409:
                    _LOGGER.warning(f"WLC API Overload (Too many sessions): Skipping {mac}.")
                    return self.data.get(mac, {})

                if status == 404:
                    continue
                if status != 200:
                    continue

                try:
                    root_key = list(data.keys())[0]
                    items = data[root_key]

                    if isinstance(items, list) and len(items) > 0:
                        items = items[0]

                    if key == "speed" and isinstance(items, int):
                        attributes["speed"] = items
                        continue

                    if not isinstance(items, dict):
                        continue

                    if key == "common":
                        ap_name = items.get("ap-name")
                        # Treat absence of AP name as wired; avoid setting None
                        attributes["ap-name"] = ap_name if ap_name else "Wired Connection"
                        if _is_meaningful(items.get("username")):
                            attributes["username"] = items.get("username")
                        is_wireless = bool(ap_name)

                    elif key == "dot11":
                        # Populate Wi‑Fi fields whenever the dot11 payload returns them,
                        # regardless of whether 'common' included an AP name.
                        ch = items.get("current-channel")
                        if _is_meaningful(ch):
                            attributes["current-channel"] = ch
                        else:
                            _LOGGER.debug(f"dot11 payload missing current-channel for {mac}; keys: {list(items.keys())}")
                        akm = items.get("ms-wifi", {}).get("auth-key-mgmt")
                        if _is_meaningful(akm):
                            attributes["auth-key-mgmt"] = akm
                        ssid = items.get("vap-ssid")
                        if _is_meaningful(ssid):
                            attributes["ssid"] = ssid
                        wifi_std = items.get("ewlc-ms-phy-type")
                        if _is_meaningful(wifi_std):
                            attributes["WifiStandard"] = wifi_std

                    elif key == "device":
                        # Only include device fields if present; avoid overriding with None/Unknown
                        dn = items.get("device-name")
                        if _is_meaningful(dn):
                            attributes["device-name"] = dn
                        dt = items.get("device-type")
                        if _is_meaningful(dt):
                            attributes["device-type"] = dt
                        dos = items.get("device-os")
                        if _is_meaningful(dos):
                            attributes["device-os"] = dos

                    elif key == "roaming_history":
                        mobility_entries = items.get("entry", [])
                        if isinstance(mobility_entries, list):
                            # Sort by parsed datetime descending
                            def _roam_sort_key(e):
                                dt = _parse_to_local_datetime(e.get("ms-assoc-time"))
                                return dt.timestamp() if dt else 0.0
                            mobility_entries.sort(key=_roam_sort_key, reverse=True)

                            formatted_roaming = []
                            for entry in mobility_entries:
                                ap_name = entry.get("ap-name", "Unknown AP")
                                raw_time = entry.get("ms-assoc-time", "")
                                formatted_time = format_roaming_time(raw_time)
                                if _is_meaningful(formatted_time):
                                    formatted_roaming.append(f"Roamed: {ap_name} at {formatted_time}")

                            if formatted_roaming:
                                attributes["most_recent_roam"] = formatted_roaming[0] if len(formatted_roaming) > 0 else None
                                attributes["previous_roam_1"] = formatted_roaming[1] if len(formatted_roaming) > 1 else None
                                attributes["previous_roam_2"] = formatted_roaming[2] if len(formatted_roaming) > 2 else None
                                attributes["previous_roam_3"] = formatted_roaming[3] if len(formatted_roaming) > 3 else None
                except Exception as err:
                    _LOGGER.error(f"Error processing {key} attributes for MAC {mac}: {err}")

            # If channel is still missing but we appear wireless/speedy, retry dot11 once with a longer timeout
            if not _is_meaningful(attributes.get("current-channel")) and not _is_meaningful(existing.get("current-channel")):
                try:
                    status, data, text = await self._get(_client_url("dot11"), timeout=10)
                    if status == 200 and isinstance(data, dict):
                        try:
                            root_key = list(data.keys())[0]
                            items = data[root_key]
                            if isinstance(items, list) and items:
                                items = items[0]
                            if isinstance(items, dict):
                                ch = items.get("current-channel")
                                if _is_meaningful(ch):
                                    attributes["current-channel"] = ch
                                ssid = items.get("vap-ssid")
                                if _is_meaningful(ssid):
                                    attributes["ssid"] = ssid
                        except Exception as err:
                            _LOGGER.debug(f"Retry parse failed for dot11 ({mac}): {err}")
                except Exception as err:
                    _LOGGER.debug(f"Retry failed for dot11 ({mac}): {err}")

            # Persist attributes for this MAC without wiping valid existing data
            merged = dict(existing)
            for k, v in attributes.items():
                if _is_meaningful(v):
                    merged[k] = v
            self.data[mac] = merged
            return attributes
