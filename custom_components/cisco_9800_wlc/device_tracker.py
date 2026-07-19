"""Device tracker for Cisco 9800 WLC integration."""
from __future__ import annotations

import logging
from typing import Any, Iterable, cast

from homeassistant.components.device_tracker import (
    DOMAIN as DEVICE_TRACKER_DOMAIN,
    ScannerEntity,
)
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
from .utils import (
    best_client_label,
    build_client_device_identifier,
    build_client_unique_id,
    client_mac_from_unique_id,
    real_client_name,
)

_LOGGER = logging.getLogger(__name__)

# -------------------------
#  Tracked Client Entity
# Lets remeber that WLC has a idle timeout so clients will report in even when disconnected for the idle time. default 6 mins.
# -------------------------
class CiscoWLCClient(CoordinatorEntity[CiscoWLCUpdateCoordinator], ScannerEntity):
    """Represents a tracked client device connected to the Cisco WLC."""

    _attr_has_entity_name = True

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
        # Presence trackers are cheap: the main WLC client-list poll already has
        # the connected/disconnected state. Detailed polling is controlled by
        # the dedicated detailed_macs option, not by entity enablement.
        self._enable_by_default = True
        self._attr_name = None


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
        return build_client_unique_id(self.coordinator.host, self._normalized_mac())

    @property
    def mac_address(self) -> str:
        """Return the client MAC address."""
        return self._normalized_mac()

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return whether the entity is enabled by default."""
        return True

    @property
    def name(self) -> str | None:
        """Return no entity-specific name for the primary client tracker."""

        return None

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
            "Auth Key Mgmt (AKM)": None,
            "Connection Speed Mbps": None,
            "Device Name": None,
            "Device Type": None,
            "Device OS": None,
            "Device Vendor": None,
            "Device Protocol": None,
            "Device Sub Version": None,
            "Protocol Map": None,
            "Classification Confidence": None,
            "Classified Time": None,
            "Day Zero Classification": None,
            "Roaming History": None,
            "Most Recent Roam": None,
            "Previous Roam 1": None,
            "Previous Roam 2": None,
            "Previous Roam 3": None,
            "Previous Roam 4": None,
            "Previous Roam 5": None,
            "Previous Roam 6": None,
            "IP Address": None,
            "IPv4 Address": None,
            "IPv6 Address": None,
            "IPv6 Addresses": None,
            "Connected to Controller": None,
            "WifiStandard": None,
            "Last Seen": None,
            "Attributes Updated": None,
        }

        # Mapping HA attribute keys to API attribute names
        attribute_key_mapping = {
            "SSID": "ssid",
            "Access Point Name": "ap-name",
            "IP Address": "IP Address",
            "IPv4 Address": "IPv4 Address",
            "IPv6 Address": "IPv6 Address",
            "IPv6 Addresses": "IPv6 Addresses",
            "Connected to Controller": "Connected to Controller",
            "Connection Speed Mbps": "speed",
            "Current Channel": "current-channel",
            "Auth Key Mgmt (AKM)": "auth-key-mgmt",
            "Device Name": "device-name",
            "Device Type": "device-type",
            "Device OS": "device-os",
            "Device Vendor": "device-vendor",
            "Device Protocol": "device-protocol",
            "Device Sub Version": "device-sub-version",
            "Protocol Map": "protocol-map",
            "Classification Confidence": "confidence-level",
            "Classified Time": "classified-time",
            "Day Zero Classification": "day-zero-dc",
            "Roaming History": "roaming_history",
            "Most Recent Roam": "most_recent_roam",
            "Previous Roam 1": "previous_roam_1",
            "Previous Roam 2": "previous_roam_2",
            "Previous Roam 3": "previous_roam_3",
            "Previous Roam 4": "previous_roam_4",
            "Previous Roam 5": "previous_roam_5",
            "Previous Roam 6": "previous_roam_6",
            "WifiStandard": "WifiStandard",
            "Username": "username",
            "Last Seen": "last_seen",
            "Attributes Updated": "attributes_updated",
        }

        merged_attributes: dict[str, Any] = {}

        for ha_key, api_key in attribute_key_mapping.items():
            if ha_key == "Device Name":
                merged_attributes[ha_key] = (
                    real_client_name(attributes)
                    if api_key in attributes
                    else default_attributes.get(ha_key, None)
                )
            elif api_key in attributes and attributes[api_key] is not None:
                merged_attributes[ha_key] = attributes[api_key]
            else:
                merged_attributes[ha_key] = default_attributes.get(ha_key, None)

        for time_key in ("Last Seen", "Attributes Updated", "Classified Time"):
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
        label = best_client_label(attributes)
        if label:
            return label
        return self.mac

    def _mac_suffix(self) -> str:
        parts = self.mac.split(":")
        if len(parts) >= 2:
            return f"{parts[-2]}:{parts[-1]}"
        return self.mac[-5:]

    def _normalized_mac(self) -> str:
        normalizer = getattr(self.coordinator, "_normalize_mac", None)
        normalized = normalizer(self.mac) if callable(normalizer) else None
        return normalized or self.mac.lower()

    def _device_identifier(self) -> str:
        return build_client_device_identifier(
            self.coordinator.host,
            self._normalized_mac(),
        )

    def _current_friendly_name(self) -> str:
        base = self._base_name()
        suffix = self._mac_suffix()
        if base == self.mac:
            return f"Client {suffix}"
        return f"{base} {suffix}"

    def _device_registry_label(self) -> str:
        return self._current_friendly_name()

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry information for this tracked client."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_identifier())},
            name=self._device_registry_label(),
            via_device=(DOMAIN, self.coordinator.entry_id),
        )

    async def _async_update_device_registry_name(self) -> None:
        desired_name = self._device_registry_label()
        device_registry = dr.async_get(self.hass)
        device = device_registry.async_get_device(
            identifiers={(DOMAIN, self._device_identifier())}
        )
        if device and device.name != desired_name:
            device_registry.async_update_device(device.id, name=desired_name)

    def _handle_coordinator_update(self) -> None:
        self._attr_name = None
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
        normalized = coordinator._normalize_mac(key)
        if normalized is None:
            continue
        all_active_clients.add(normalized)

    #  **Step 1: Retrieve all known devices from Home Assistant**
    entity_registry = er.async_get(hass)
    known_clients: set[str] = set()

    for entity_entry in list(entity_registry.entities.values()):
        if (
            entity_entry.entity_id.startswith("device_tracker.")
            and entity_entry.platform == DOMAIN
            and entity_entry.unique_id
        ):
            if entity_entry.config_entry_id != entry.entry_id:
                continue

            uid = entity_entry.unique_id.lower()
            normalized_uid = coordinator._normalize_mac(uid)
            if not normalized_uid:
                normalized_uid = coordinator._normalize_mac(
                    client_mac_from_unique_id(uid)
                )
            if not normalized_uid:
                _LOGGER.debug("Skipping invalid MAC unique_id %s", uid)
                continue

            disabled_by = getattr(entity_entry, "disabled_by", None)
            if disabled_by == er.RegistryEntryDisabler.INTEGRATION:
                entity_registry.async_update_entity(
                    entity_entry.entity_id,
                    disabled_by=None,
                )

            scoped_uid = build_client_unique_id(coordinator.host, normalized_uid)
            if uid != scoped_uid and not entity_registry.async_get_entity_id(
                DEVICE_TRACKER_DOMAIN,
                DOMAIN,
                scoped_uid,
            ):
                entity_registry.async_update_entity(
                    entity_entry.entity_id,
                    new_unique_id=scoped_uid,
                )

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
        normalized = coordinator._normalize_mac(mac)
        if normalized is None:
            continue
        if normalized not in tracked_macs:
            clients_to_add.append(
                CiscoWLCClient(
                    coordinator,
                    normalized,
                    coordinator.data.get(normalized, {}),
                    True,
                )
            )
            tracked_macs.add(normalized)

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
            normalized = coordinator._normalize_mac(mac)
            if normalized is None:
                continue
            if normalized in tracked_macs:
                continue
            new_entities.append(
                CiscoWLCClient(
                    coordinator,
                    normalized,
                    coordinator.data.get(normalized, {}),
                    True,
                )
            )
            tracked_macs.add(normalized)
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
