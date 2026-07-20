"""Sensor for Cisco 9800 WLC software version."""
from __future__ import annotations

from dataclasses import dataclass
import logging

from typing import Any, cast

from homeassistant.components.sensor import (
    DOMAIN as SENSOR_DOMAIN,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    UnitOfDensity,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CiscoWLCUpdateCoordinator
from .registry import async_cleanup_legacy_empty_ap_devices
from .utils import (
    build_ap_device_identifier,
    build_ap_unique_id,
    best_client_label,
    build_client_device_identifier,
    build_client_unique_id,
    build_https_url,
    meaningful_client_label,
)

_LOGGER = logging.getLogger(__name__)

NON_CLIENT_DATA_KEYS = {"wlc_status", "ap_sensors", "ap_devices"}


def _format_ap_display_name(raw_name: Any, ap_mac: str) -> str:
    """Return a normalized AP display name prefixed with 'AP-'."""

    base = ap_mac.upper()
    if isinstance(raw_name, str):
        candidate = raw_name.strip()
        if candidate:
            base = candidate
    if base.lower().startswith("ap-"):
        return base
    return f"AP-{base}"


def _native_number(value: Any) -> int | float | None:
    """Return a numeric state already prepared by the coordinator."""

    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _meaningful_string(value: Any) -> str | None:
    """Return a stripped string when it carries useful state."""

    return meaningful_client_label(value)


@dataclass
class CiscoWLCSensorEntityDescription(SensorEntityDescription):
    """Describes a Cisco WLC sensor."""


VERSION_DESCRIPTION = CiscoWLCSensorEntityDescription(
    key="software_version",
    translation_key="software_version",
    entity_category=EntityCategory.DIAGNOSTIC,
)


@dataclass
class CiscoWLCAPEnvironmentSensorDescription(SensorEntityDescription):
    """Describes an individual AP environmental metric."""

    value_field: str = ""
    last_update_field: str | None = None


@dataclass
class CiscoWLCAPDeviceSensorDescription(SensorEntityDescription):
    """Describes an AP-level aggregate metric."""

    value_field: str = ""


@dataclass
class CiscoWLCAPRadioSensorDescription(SensorEntityDescription):
    """Describes a per-radio metric."""

    value_field: str = ""


@dataclass
class CiscoWLCAPNeighborSensorDescription(SensorEntityDescription):
    """Describes an AP CDP/LLDP neighbor detail."""

    source_field: str = ""
    value_field: str = ""


AP_ENVIRONMENT_SENSOR_DESCRIPTIONS: tuple[CiscoWLCAPEnvironmentSensorDescription, ...] = (
    CiscoWLCAPEnvironmentSensorDescription(
        key="ap_temperature",
        name="Temperature",
        translation_key="ap_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        value_field="temperature",
        last_update_field="temperature_last_update",
    ),
    CiscoWLCAPEnvironmentSensorDescription(
        key="ap_humidity",
        name="Humidity",
        translation_key="ap_humidity",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_field="humidity",
        last_update_field="temperature_last_update",
    ),
    CiscoWLCAPEnvironmentSensorDescription(
        key="ap_air_quality",
        name="Air quality index",
        translation_key="ap_air_quality",
        device_class=SensorDeviceClass.AQI,
        state_class=SensorStateClass.MEASUREMENT,
        value_field="iaq",
        last_update_field="air_quality_last_update",
    ),
    CiscoWLCAPEnvironmentSensorDescription(
        key="ap_air_quality_tvoc",
        name="TVOC",
        translation_key="ap_air_quality_tvoc",
        device_class=SensorDeviceClass.VOLATILE_ORGANIC_COMPOUNDS,
        icon="mdi:molecule",
        native_unit_of_measurement=UnitOfDensity.MILLIGRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        value_field="tvoc",
        last_update_field="air_quality_last_update",
    ),
    CiscoWLCAPEnvironmentSensorDescription(
        key="ap_air_quality_etoh",
        name="EtOH",
        translation_key="ap_air_quality_etoh",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:molecule",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        value_field="etoh",
        last_update_field="air_quality_last_update",
    ),
)


AP_DEVICE_SENSOR_DESCRIPTIONS: tuple[CiscoWLCAPDeviceSensorDescription, ...] = (
    CiscoWLCAPDeviceSensorDescription(
        key="ap_clients",
        name="Total Clients Connected",
        translation_key="ap_clients",
        icon="mdi:account-multiple",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_field="client_count",
    ),
    CiscoWLCAPDeviceSensorDescription(
        key="ap_clients_24ghz",
        name="Clients (2.4 GHz)",
        translation_key="ap_clients_24ghz",
        icon="mdi:access-point",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_field="clients_24ghz",
    ),
    CiscoWLCAPDeviceSensorDescription(
        key="ap_clients_5ghz",
        name="Clients (5 GHz)",
        translation_key="ap_clients_5ghz",
        icon="mdi:access-point",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_field="clients_5ghz",
    ),
    CiscoWLCAPDeviceSensorDescription(
        key="ap_clients_6ghz",
        name="Clients (6 GHz)",
        translation_key="ap_clients_6ghz",
        icon="mdi:access-point",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_field="clients_6ghz",
    ),
)


AP_RADIO_SENSOR_DESCRIPTIONS: tuple[CiscoWLCAPRadioSensorDescription, ...] = (
    CiscoWLCAPRadioSensorDescription(
        key="ap_radio_channel",
        name="Radio channel",
        translation_key="ap_radio_channel",
        icon="mdi:access-point",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_field="channel",
    ),
    CiscoWLCAPRadioSensorDescription(
        key="ap_radio_channel_width",
        name="Channel width",
        translation_key="ap_radio_channel_width",
        icon="mdi:signal",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="MHz",
        suggested_display_precision=0,
        value_field="channel_width_mhz",
    ),
    CiscoWLCAPRadioSensorDescription(
        key="ap_radio_tx_power",
        name="Transmit power",
        translation_key="ap_radio_tx_power",
        icon="mdi:signal-cellular-3",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="dBm",
        suggested_display_precision=0,
        value_field="tx_power_dbm",
    ),
)


AP_STATUS_SENSOR_DESCRIPTION = SensorEntityDescription(
    key="ap_status",
    name="AP Online Status",
    icon="mdi:access-point-network",
    entity_category=EntityCategory.DIAGNOSTIC,
)


AP_NEIGHBOR_SENSOR_DESCRIPTIONS: tuple[CiscoWLCAPNeighborSensorDescription, ...] = (
    CiscoWLCAPNeighborSensorDescription(
        key="ap_cdp_device_id",
        name="CDP Device ID",
        icon="mdi:lan-connect",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="cdp",
        value_field="device_id",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_cdp_neighbor_port",
        name="CDP Neighbor Port",
        icon="mdi:ethernet",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="cdp",
        value_field="neighbor_port",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_cdp_platform",
        name="CDP Platform",
        icon="mdi:router-network",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="cdp",
        value_field="platform",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_cdp_neighbor_ip",
        name="CDP Neighbor IP",
        icon="mdi:ip-network",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="cdp",
        value_field="neighbor_ip",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_cdp_last_update",
        name="CDP Last Update",
        icon="mdi:clock-outline",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="cdp",
        value_field="last_update",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_lldp_neighbor_mac",
        name="LLDP Neighbor MAC",
        icon="mdi:lan-connect",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="lldp",
        value_field="neighbor_mac",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_lldp_port_id",
        name="LLDP Port ID",
        icon="mdi:ethernet",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="lldp",
        value_field="port_id",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_lldp_system_name",
        name="LLDP System Name",
        icon="mdi:router-network",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="lldp",
        value_field="system_name",
    ),
    CiscoWLCAPNeighborSensorDescription(
        key="ap_lldp_management_address",
        name="LLDP Management Address",
        icon="mdi:ip-network",
        entity_category=EntityCategory.DIAGNOSTIC,
        source_field="lldp",
        value_field="management_address",
    ),
)


CLIENT_CURRENT_AP_DESCRIPTION = SensorEntityDescription(
    key="client_current_ap",
    name="Current AP",
    translation_key="client_current_ap",
    icon="mdi:access-point",
)


class CiscoWLCVersionSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Shows the WLC software version."""

    entity_description = VERSION_DESCRIPTION
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CiscoWLCUpdateCoordinator, config_entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._attr_unique_id = f"{config_entry.entry_id}_{self.entity_description.key}"
        self._attr_native_value: str | None = None
        self._last_raw_version: str | None = None

    @property
    def native_value(self) -> str:
        return self._attr_native_value or "n/a"

    @property
    def available(self) -> bool:
        return bool(self.coordinator.last_update_success)

    @property
    def device_info(self) -> DeviceInfo:
        status = (
            self.coordinator.data.get("wlc_status", {})
            if isinstance(self.coordinator.data, dict)
            else {}
        )
        sw_raw = status.get("software_version_raw")
        if sw_raw and sw_raw.lower() != "n/a":
            self._last_raw_version = sw_raw
        elif not self._last_raw_version:
            fallback = status.get("software_version")
            if fallback and fallback.lower() != "n/a":
                self._last_raw_version = fallback
        sw_value = self._last_raw_version or self._attr_native_value or "n/a"
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name="Cisco 9800 WLC",
            manufacturer="Cisco",
            model="9800 Series Wireless Controller",
            sw_version=sw_value,
            configuration_url=build_https_url(self._entry.data["host"]),
        )

    def _handle_coordinator_update(self) -> None:
        status = (
            self.coordinator.data.get("wlc_status", {})
            if isinstance(self.coordinator.data, dict)
            else {}
        )
        version = status.get("software_version")
        if isinstance(version, str) and version.lower() != "n/a" and version.strip():
            self._attr_native_value = version
        elif self._attr_native_value is None:
            self._attr_native_value = version or "n/a"

        raw = status.get("software_version_raw")
        if isinstance(raw, str) and raw.lower() != "n/a" and raw.strip():
            self._last_raw_version = raw
        elif self._last_raw_version is None and isinstance(version, str) and version.strip():
            self._last_raw_version = version

        super()._handle_coordinator_update()


class CiscoWLCClientCurrentAPSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Expose a client's current AP name as recorder-friendly state history."""

    entity_description = CLIENT_CURRENT_AP_DESCRIPTION
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        config_entry: ConfigEntry,
        mac: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        normalized = coordinator._normalize_mac(mac)
        self._mac = normalized or str(mac).strip().lower()
        self._attr_unique_id = (
            f"{build_client_unique_id(coordinator.host, self._mac)}"
            f"_{self.entity_description.key}"
        )

    def _client_record(self) -> dict[str, Any]:
        data = self.coordinator.data if isinstance(self.coordinator.data, dict) else {}
        record = data.get(self._mac)
        if isinstance(record, dict):
            return record

        for key, value in data.items():
            if key in NON_CLIENT_DATA_KEYS or not isinstance(value, dict):
                continue
            normalized = self.coordinator._normalize_mac(key)
            if normalized == self._mac:
                return value
        return {}

    @property
    def available(self) -> bool:
        detailed_macs, _ = self.coordinator.get_detailed_macs()
        return bool(self.coordinator.last_update_success and self._mac in detailed_macs)

    @property
    def native_value(self) -> str | None:
        record = self._client_record()
        if not record:
            return None
        if record.get("connected") is False:
            return "not_home"
        return _meaningful_string(record.get("ap-name"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        record = self._client_record()
        attrs: dict[str, Any] = {"client_mac": self._mac}
        for api_key, attr_key in (
            ("ssid", "ssid"),
            ("current-channel", "current_channel"),
            ("connected", "connected"),
            ("last_seen", "last_seen"),
            ("attributes_updated", "attributes_updated"),
            ("roaming_history", "roaming_history"),
            ("most_recent_roam", "most_recent_roam"),
            ("previous_roam_1", "previous_roam_1"),
            ("previous_roam_2", "previous_roam_2"),
            ("previous_roam_3", "previous_roam_3"),
            ("previous_roam_4", "previous_roam_4"),
            ("previous_roam_5", "previous_roam_5"),
            ("previous_roam_6", "previous_roam_6"),
        ):
            if api_key in record and record[api_key] is not None:
                attrs[attr_key] = record[api_key]
        return attrs

    def _client_display_name(self) -> str:
        record = self._client_record()
        label = best_client_label(record)
        suffix_parts = (
            self._mac.split(":")[-2:] if ":" in self._mac else [self._mac[-5:]]
        )
        suffix = ":".join(suffix_parts)
        if label:
            return f"{label} {suffix}"
        return f"Client {suffix}"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={
                (
                    DOMAIN,
                    build_client_device_identifier(self.coordinator.host, self._mac),
                )
            },
            name=self._client_display_name(),
            via_device=(DOMAIN, self.coordinator.entry_id),
        )


class CiscoWLCAPEnvironmentSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Represents an individual AP environmental reading."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        config_entry: ConfigEntry,
        ap_mac: str,
        description: CiscoWLCAPEnvironmentSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._ap_mac = ap_mac
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = build_ap_unique_id(
            coordinator.host,
            ap_mac,
            description.key,
        )

    def _ap_record(self) -> dict:
        data = self.coordinator.data if isinstance(self.coordinator.data, dict) else {}
        env_data = (
            data.get("ap_sensors") if isinstance(data, dict) else {}
        )
        env_record = env_data.get(self._ap_mac) if isinstance(env_data, dict) else None
        if not isinstance(env_record, dict):
            env_record = {}
        device_record = (
            data.get("ap_devices", {}).get(self._ap_mac)
            if isinstance(data.get("ap_devices"), dict)
            else {}
        )
        if not isinstance(device_record, dict):
            device_record = {}
        merged: dict[str, Any] = {}
        merged.update(device_record)
        merged.update(device_record.get("environment", {}))
        merged.update(env_record)
        return merged

    def _display_name(self) -> str:
        record = self._ap_record()
        name = record.get("name") if isinstance(record, dict) else None
        return _format_ap_display_name(name, self._ap_mac)

    @property
    def native_value(self) -> int | float | None:
        value = self._ap_record().get(self.entity_description.value_field)
        return _native_number(value)

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return whether this AP environmental entity is enabled by default."""

        return self.entity_description.key != "ap_air_quality_etoh"

    @property
    def extra_state_attributes(self) -> dict:
        record = self._ap_record()
        attrs: dict[str, str | float] = {"ap_mac": self._ap_mac}
        last_update_field = self.entity_description.last_update_field
        if last_update_field and record.get(last_update_field):
            attrs["last_update"] = record[last_update_field]
        if self.entity_description.key == "ap_air_quality":
            for key in ("tvoc", "etoh", *(f"rmox-{index}" for index in range(13))):
                if record.get(key) is not None:
                    attrs[key] = record[key]
        return attrs

    @property
    def device_info(self) -> DeviceInfo:
        record = self._ap_record()
        ip_address = record.get("ip_address")
        config_url = None
        if isinstance(ip_address, str) and ip_address:
            config_url = build_https_url(ip_address)
        return DeviceInfo(
            identifiers={
                (
                    DOMAIN,
                    build_ap_device_identifier(self.coordinator.host, self._ap_mac),
                )
            },
            name=self._display_name(),
            manufacturer="Cisco",
            model=record.get("model"),
            serial_number=record.get("serial_number") or self._ap_mac,
            suggested_area=record.get("location"),
            configuration_url=config_url,
            via_device=(DOMAIN, self._entry.entry_id),
        )


class CiscoWLCAPDeviceSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Represents an AP-level aggregate metric."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        config_entry: ConfigEntry,
        ap_mac: str,
        description: CiscoWLCAPDeviceSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._ap_mac = ap_mac
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = build_ap_unique_id(
            coordinator.host,
            ap_mac,
            description.key,
        )

    def _ap_record(self) -> dict:
        data = self.coordinator.data if isinstance(self.coordinator.data, dict) else {}
        devices = data.get("ap_devices") if isinstance(data, dict) else {}
        if not isinstance(devices, dict):
            return {}
        record = devices.get(self._ap_mac)
        return record if isinstance(record, dict) else {}

    def _display_name(self) -> str:
        record = self._ap_record()
        return _format_ap_display_name(record.get("name"), self._ap_mac)

    @property
    def native_value(self) -> int | float | None:
        record = self._ap_record()
        value = record.get(self.entity_description.value_field)
        return _native_number(value)

    @property
    def extra_state_attributes(self) -> dict:
        record = self._ap_record()
        attrs: dict[str, Any] = {"ap_mac": self._ap_mac}
        for key in ("ip_address", "location", "mode", "admin_state", "oper_state"):
            if record.get(key) is not None:
                attrs[key] = record[key]
        if record.get("last_seen"):
            attrs["last_seen"] = record["last_seen"]
        return attrs

    @property
    def device_info(self) -> DeviceInfo:
        record = self._ap_record()
        return DeviceInfo(
            identifiers={
                (
                    DOMAIN,
                    build_ap_device_identifier(self.coordinator.host, self._ap_mac),
                )
            },
            name=self._display_name(),
            manufacturer="Cisco",
            model=record.get("model"),
            serial_number=record.get("serial_number") or self._ap_mac,
            suggested_area=record.get("location"),
            via_device=(DOMAIN, self._entry.entry_id),
        )


class CiscoWLCAPStatusSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Represents the online status of an AP."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        config_entry: ConfigEntry,
        ap_mac: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._ap_mac = ap_mac
        self.entity_description = AP_STATUS_SENSOR_DESCRIPTION
        self._attr_name = AP_STATUS_SENSOR_DESCRIPTION.name
        self._attr_unique_id = build_ap_unique_id(
            coordinator.host,
            ap_mac,
            self.entity_description.key,
        )

    def _ap_record(self) -> dict:
        data = self.coordinator.data if isinstance(self.coordinator.data, dict) else {}
        devices = data.get("ap_devices") if isinstance(data, dict) else {}
        if not isinstance(devices, dict):
            return {}
        record = devices.get(self._ap_mac)
        return record if isinstance(record, dict) else {}

    @property
    def native_value(self) -> str | None:
        record = self._ap_record()
        if not record:
            return None
        online = record.get("online")
        if online is None:
            oper_state = str(record.get("oper_state") or "").lower()
            if oper_state:
                online = oper_state in {"registered", "oper-up", "up"}
        if online is False:
            return "Offline"
        if online:
            return "Online"
        return None

    @property
    def icon(self) -> str | None:
        value = self.native_value
        if value == "Offline":
            return "mdi:access-point-network-off"
        if value == "Online":
            return "mdi:access-point-network"
        return self.entity_description.icon

    @property
    def extra_state_attributes(self) -> dict:
        record = self._ap_record()
        attrs: dict[str, Any] = {"ap_mac": self._ap_mac}
        if record.get("last_seen"):
            attrs["last_seen"] = record["last_seen"]
        return attrs

    @property
    def device_info(self) -> DeviceInfo:
        record = self._ap_record()
        ip_address = record.get("ip_address")
        config_url = None
        if isinstance(ip_address, str) and ip_address:
            config_url = build_https_url(ip_address)
        return DeviceInfo(
            identifiers={
                (
                    DOMAIN,
                    build_ap_device_identifier(self.coordinator.host, self._ap_mac),
                )
            },
            name=_format_ap_display_name(record.get("name"), self._ap_mac),
            manufacturer="Cisco",
            model=record.get("model"),
            serial_number=record.get("serial_number") or self._ap_mac,
            suggested_area=record.get("location"),
            configuration_url=config_url,
            via_device=(DOMAIN, self._entry.entry_id),
        )


class CiscoWLCAPNeighborSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Represents an AP CDP/LLDP neighbor detail as a string sensor."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        config_entry: ConfigEntry,
        ap_mac: str,
        description: CiscoWLCAPNeighborSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._ap_mac = ap_mac
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = build_ap_unique_id(
            coordinator.host,
            ap_mac,
            description.key,
        )

    def _ap_record(self) -> dict:
        data = self.coordinator.data if isinstance(self.coordinator.data, dict) else {}
        devices = data.get("ap_devices") if isinstance(data, dict) else {}
        if not isinstance(devices, dict):
            return {}
        record = devices.get(self._ap_mac)
        return record if isinstance(record, dict) else {}

    @property
    def native_value(self) -> str | None:
        source = self._ap_record().get(self.entity_description.source_field)
        if not isinstance(source, dict):
            return None
        value = source.get(self.entity_description.value_field)
        if value is None:
            return None
        return str(value)

    @property
    def extra_state_attributes(self) -> dict:
        return {
            "ap_mac": self._ap_mac,
            "protocol": self.entity_description.source_field.upper(),
        }

    @property
    def device_info(self) -> DeviceInfo:
        record = self._ap_record()
        ip_address = record.get("ip_address")
        config_url = None
        if isinstance(ip_address, str) and ip_address:
            config_url = build_https_url(ip_address)
        return DeviceInfo(
            identifiers={
                (
                    DOMAIN,
                    build_ap_device_identifier(self.coordinator.host, self._ap_mac),
                )
            },
            name=_format_ap_display_name(record.get("name"), self._ap_mac),
            manufacturer="Cisco",
            model=record.get("model"),
            serial_number=record.get("serial_number") or self._ap_mac,
            suggested_area=record.get("location"),
            configuration_url=config_url,
            via_device=(DOMAIN, self._entry.entry_id),
        )


class CiscoWLCAPRadioSensor(
    CoordinatorEntity[CiscoWLCUpdateCoordinator], SensorEntity
):
    """Represents a per-radio attribute for an AP."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CiscoWLCUpdateCoordinator,
        config_entry: ConfigEntry,
        ap_mac: str,
        slot: int,
        description: CiscoWLCAPRadioSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self._entry = config_entry
        self._ap_mac = ap_mac
        self._slot = slot
        self.entity_description = description
        base_name = description.name or description.key.replace("_", " ").title()
        self._attr_name = f"{base_name} (Slot {slot})"
        self._attr_unique_id = build_ap_unique_id(
            coordinator.host,
            ap_mac,
            f"{description.key}_slot{slot}",
        )

    def _radio_record(self) -> tuple[dict, dict]:
        data = self.coordinator.data if isinstance(self.coordinator.data, dict) else {}
        devices = data.get("ap_devices") if isinstance(data, dict) else {}
        if not isinstance(devices, dict):
            return {}, {}
        ap_record = devices.get(self._ap_mac)
        if not isinstance(ap_record, dict):
            return {}, {}
        radios = ap_record.get("radios", {})
        if not isinstance(radios, dict):
            return ap_record, {}
        radio = radios.get(self._slot, {})
        radio = radio if isinstance(radio, dict) else {}
        return ap_record, radio

    def _display_name(self) -> str:
        ap_record, radio = self._radio_record()
        base = _format_ap_display_name(ap_record.get("name"), self._ap_mac)
        band = radio.get("band")
        if band:
            return f"{base} Slot {self._slot} {band}".strip()
        return f"{base} Slot {self._slot}"

    @property
    def native_value(self) -> int | float | None:
        _, radio = self._radio_record()
        value = radio.get(self.entity_description.value_field)
        return _native_number(value)

    @property
    def extra_state_attributes(self) -> dict:
        ap_record, radio = self._radio_record()
        attrs: dict[str, str | float] = {
            "ap_mac": self._ap_mac,
            "slot": self._slot,
        }
        for key in ("band", "radio_type", "admin_state", "oper_state", "channel_width_cap"):
            if radio.get(key) is not None:
                attrs[key] = radio[key]
        if ap_record.get("ip_address"):
            attrs.setdefault("ap_ip", ap_record["ip_address"])
        return attrs

    @property
    def device_info(self) -> DeviceInfo:
        ap_record, _ = self._radio_record()
        friendly = _format_ap_display_name(ap_record.get("name"), self._ap_mac)
        ip_address = ap_record.get("ip_address")
        config_url = None
        if isinstance(ip_address, str) and ip_address:
            config_url = build_https_url(ip_address)
        return DeviceInfo(
            identifiers={
                (
                    DOMAIN,
                    build_ap_device_identifier(self.coordinator.host, self._ap_mac),
                )
            },
            name=friendly,
            manufacturer="Cisco",
            model=ap_record.get("model"),
            serial_number=ap_record.get("serial_number") or self._ap_mac,
            suggested_area=ap_record.get("location"),
            configuration_url=config_url,
            via_device=(DOMAIN, self._entry.entry_id),
        )


def _ap_sensor_unique_id_migrations(
    coordinator: CiscoWLCUpdateCoordinator,
) -> dict[str, str]:
    """Return legacy AP sensor unique IDs mapped to WLC-scoped IDs."""

    data = coordinator.data if isinstance(coordinator.data, dict) else {}
    env_data = data.get("ap_sensors") if isinstance(data, dict) else {}
    device_data = data.get("ap_devices") if isinstance(data, dict) else {}
    migrations: dict[str, str] = {}
    ap_macs: set[str] = set()

    def _add(mac: str, key: str) -> None:
        legacy_uid = f"{mac}_{key}".lower()
        migrations[legacy_uid] = build_ap_unique_id(coordinator.host, mac, key)

    if isinstance(env_data, dict):
        ap_macs.update(mac for mac in env_data if isinstance(mac, str))

    if isinstance(device_data, dict):
        ap_macs.update(mac for mac in device_data if isinstance(mac, str))

    for mac in ap_macs:
        for description in AP_ENVIRONMENT_SENSOR_DESCRIPTIONS:
            _add(mac, description.key)
        _add(mac, AP_STATUS_SENSOR_DESCRIPTION.key)
        for description in AP_DEVICE_SENSOR_DESCRIPTIONS:
            _add(mac, description.key)
        for description in AP_NEIGHBOR_SENSOR_DESCRIPTIONS:
            _add(mac, description.key)

    if isinstance(device_data, dict):
        for mac, info in device_data.items():
            if not isinstance(mac, str) or not isinstance(info, dict):
                continue
            radios = info.get("radios")
            if not isinstance(radios, dict):
                continue
            for slot, slot_info in radios.items():
                if not isinstance(slot_info, dict):
                    continue
                for description in AP_RADIO_SENSOR_DESCRIPTIONS:
                    _add(mac, f"{description.key}_slot{slot}")

    return migrations


def _async_migrate_ap_sensor_unique_ids(
    hass: HomeAssistant,
    coordinator: CiscoWLCUpdateCoordinator,
    entry: ConfigEntry,
) -> None:
    """Move legacy MAC-only AP sensor unique IDs to WLC-scoped unique IDs."""

    migrations = _ap_sensor_unique_id_migrations(coordinator)
    if not migrations:
        return

    entity_registry = er.async_get(hass)
    for entity_entry in list(entity_registry.entities.values()):
        if (
            entity_entry.platform != DOMAIN
            or entity_entry.config_entry_id != entry.entry_id
            or not entity_entry.entity_id.startswith(f"{SENSOR_DOMAIN}.")
            or not entity_entry.unique_id
        ):
            continue
        uid = entity_entry.unique_id.lower()
        scoped_uid = migrations.get(uid)
        if not scoped_uid or uid == scoped_uid:
            continue
        if entity_registry.async_get_entity_id(SENSOR_DOMAIN, DOMAIN, scoped_uid):
            continue
        entity_registry.async_update_entity(
            entity_entry.entity_id,
            new_unique_id=scoped_uid,
        )


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:
    coordinator = cast(CiscoWLCUpdateCoordinator | None, entry.runtime_data)
    if not coordinator:
        _LOGGER.error(
            "Failed to find WLC coordinator for entry %s. Aborting sensor setup.",
            entry.entry_id,
        )
        return

    _async_migrate_ap_sensor_unique_ids(hass, coordinator, entry)

    entities: list[SensorEntity] = [CiscoWLCVersionSensor(coordinator, entry)]
    async_add_entities(entities)

    known_sensors: set[tuple[str, str, int | None]] = set()

    def _schedule_legacy_ap_cleanup() -> None:
        hass.async_create_task(
            async_cleanup_legacy_empty_ap_devices(hass, coordinator, entry)
        )

    @callback
    def _async_add_dynamic_entities() -> None:
        data = coordinator.data if isinstance(coordinator.data, dict) else {}

        env_data = data.get("ap_sensors") if isinstance(data, dict) else {}
        device_data = data.get("ap_devices") if isinstance(data, dict) else {}
        if not isinstance(device_data, dict):
            device_data = {}
        new_entities: list[SensorEntity] = []
        detailed_macs, _ = coordinator.get_detailed_macs()

        for mac, info in data.items():
            if mac in NON_CLIENT_DATA_KEYS or not isinstance(info, dict):
                continue
            normalized = coordinator._normalize_mac(mac)
            if not normalized or normalized not in detailed_macs:
                continue
            key = (normalized, CLIENT_CURRENT_AP_DESCRIPTION.key, None)
            if key in known_sensors:
                continue
            new_entities.append(
                CiscoWLCClientCurrentAPSensor(
                    coordinator,
                    entry,
                    normalized,
                )
            )
            known_sensors.add(key)

        if isinstance(env_data, dict):
            for mac, info in env_data.items():
                if not isinstance(info, dict):
                    continue
                for description in AP_ENVIRONMENT_SENSOR_DESCRIPTIONS:
                    if description.value_field not in info:
                        continue
                    key = (mac, description.key, None)
                    if key in known_sensors:
                        continue
                    new_entities.append(
                        CiscoWLCAPEnvironmentSensor(
                            coordinator,
                            entry,
                            mac,
                            description,
                        )
                    )
                    known_sensors.add(key)

        for mac, info in device_data.items():
            if not isinstance(info, dict):
                continue
            status_key = (mac, AP_STATUS_SENSOR_DESCRIPTION.key, None)
            if status_key not in known_sensors:
                new_entities.append(
                    CiscoWLCAPStatusSensor(
                        coordinator,
                        entry,
                        mac,
                    )
                )
                known_sensors.add(status_key)
            for description in AP_DEVICE_SENSOR_DESCRIPTIONS:
                if description.value_field not in info:
                    continue
                key = (mac, description.key, None)
                if key in known_sensors:
                    continue
                new_entities.append(
                    CiscoWLCAPDeviceSensor(
                        coordinator,
                        entry,
                        mac,
                        description,
                    )
                )
                known_sensors.add(key)

            for description in AP_NEIGHBOR_SENSOR_DESCRIPTIONS:
                source = info.get(description.source_field)
                if (
                    not isinstance(source, dict)
                    or source.get(description.value_field) is None
                ):
                    continue
                key = (mac, description.key, None)
                if key in known_sensors:
                    continue
                new_entities.append(
                    CiscoWLCAPNeighborSensor(
                        coordinator,
                        entry,
                        mac,
                        description,
                    )
                )
                known_sensors.add(key)

            radios = info.get("radios")
            if isinstance(radios, dict):
                for slot, slot_info in radios.items():
                    if not isinstance(slot_info, dict):
                        continue
                    try:
                        slot_index = int(slot)
                    except (TypeError, ValueError):
                        continue
                    for description in AP_RADIO_SENSOR_DESCRIPTIONS:
                        if description.value_field not in slot_info:
                            continue
                        key = (mac, description.key, slot_index)
                        if key in known_sensors:
                            continue
                        new_entities.append(
                            CiscoWLCAPRadioSensor(
                                coordinator,
                                entry,
                                mac,
                                slot_index,
                                description,
                            )
                        )
                        known_sensors.add(key)

        if new_entities:
            async_add_entities(new_entities)
        _schedule_legacy_ap_cleanup()

    _async_add_dynamic_entities()
    coordinator.async_add_listener(_async_add_dynamic_entities)
