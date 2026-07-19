"""Tests for Cisco WLC sensors."""
from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    UnitOfDensity,
)
from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.helpers.entity import EntityCategory
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.const import DOMAIN
from custom_components.cisco_9800_wlc.sensor import (
    AP_DEVICE_SENSOR_DESCRIPTIONS,
    AP_ENVIRONMENT_SENSOR_DESCRIPTIONS,
    AP_RADIO_SENSOR_DESCRIPTIONS,
    CiscoWLCAPStatusSensor,
    CiscoWLCAPDeviceSensor,
    CiscoWLCAPEnvironmentSensor,
    CiscoWLCAPRadioSensor,
    CiscoWLCVersionSensor,
    CiscoWLCClientCurrentAPSensor,
    async_setup_entry as async_setup_sensor_entry,
)
from custom_components.cisco_9800_wlc.utils import (
    CLIENT_NAME_VERIFIED_FIELD,
    CLIENT_NAME_VERIFIED_VALUE,
)

AP_MAC = "34:5d:a8:0a:2e:40"
AIR_QUALITY_LAST_UPDATE = "2026-07-19T09:12:49.248687+00:00"


def _config_entry(entry_id: str = "entry_ap", options: dict | None = None) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        entry_id=entry_id,
        data={
            CONF_HOST: "wlc.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
        options=options or {},
    )


def _coordinator(hass, entry: MockConfigEntry) -> CiscoWLCUpdateCoordinator:
    with patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        return CiscoWLCUpdateCoordinator(hass, entry.data, entry.entry_id, entry.options)


def _env_description(key: str):
    return next(
        description
        for description in AP_ENVIRONMENT_SENSOR_DESCRIPTIONS
        if description.key == key
    )


def _full_air_quality_record() -> dict:
    return {
        "iaq": 2.57,
        "tvoc": 0.41,
        "etoh": 0.22,
        **{f"rmox-{index}": float(index + 1) for index in range(13)},
        "air_quality_last_update": AIR_QUALITY_LAST_UPDATE,
    }


async def _setup_sensor_entities(hass, coordinator, entry: MockConfigEntry) -> list:
    entry.runtime_data = coordinator
    added_entities: list = []

    def _add_entities(entities):
        added_entities.extend(entities)

    await async_setup_sensor_entry(hass, entry, _add_entities)
    return added_entities


def _environment_entity_keys(entities: list) -> set[str]:
    return {
        entity.entity_description.key
        for entity in entities
        if isinstance(entity, CiscoWLCAPEnvironmentSensor)
    }


async def test_version_sensor_native_value(hass) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_2",
        data={
            CONF_HOST: "wlc.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
    )

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, entry.data, entry.entry_id, entry.options)

    coordinator.data = {
        "wlc_status": {
            "software_version": "17.15.4",
            "software_version_raw": "17.15.4a",
        }
    }

    sensor = CiscoWLCVersionSensor(coordinator, entry)

    assert sensor.unique_id == "entry_2_software_version"
    assert sensor.entity_description.translation_key == "software_version"
    assert sensor.native_value == "17.15.4"


async def test_ap_environment_sensor_native_values(hass) -> None:
    entry = _config_entry()
    coordinator = _coordinator(hass, entry)

    coordinator.data = {
        "ap_sensors": {
            AP_MAC: {
                "temperature": 21.86,
                "humidity": 50.92,
                "temperature_last_update": "2025-09-27T01:12:19.453981+00:00",
                **_full_air_quality_record(),
            }
        }
    }

    temp_description = AP_ENVIRONMENT_SENSOR_DESCRIPTIONS[0]
    air_quality_description = AP_ENVIRONMENT_SENSOR_DESCRIPTIONS[2]
    tvoc_description = _env_description("ap_air_quality_tvoc")
    etoh_description = _env_description("ap_air_quality_etoh")

    temp_sensor = CiscoWLCAPEnvironmentSensor(
        coordinator,
        entry,
        AP_MAC,
        temp_description,
    )
    air_sensor = CiscoWLCAPEnvironmentSensor(
        coordinator,
        entry,
        AP_MAC,
        air_quality_description,
    )
    tvoc_sensor = CiscoWLCAPEnvironmentSensor(
        coordinator,
        entry,
        AP_MAC,
        tvoc_description,
    )
    etoh_sensor = CiscoWLCAPEnvironmentSensor(
        coordinator,
        entry,
        AP_MAC,
        etoh_description,
    )

    assert temp_sensor.native_value == 21.86
    assert air_sensor.native_value == 2.57
    assert tvoc_sensor.native_value == 0.41
    assert etoh_sensor.native_value == 0.22
    assert isinstance(air_sensor.native_value, float)
    assert air_quality_description.suggested_display_precision is None
    assert tvoc_description.device_class == SensorDeviceClass.VOLATILE_ORGANIC_COMPOUNDS
    assert (
        tvoc_description.native_unit_of_measurement
        == UnitOfDensity.MILLIGRAMS_PER_CUBIC_METER
    )
    assert tvoc_description.suggested_display_precision == 2
    assert etoh_description.entity_category == EntityCategory.DIAGNOSTIC
    assert etoh_sensor.entity_registry_enabled_default is False
    assert air_sensor.extra_state_attributes["tvoc"] == 0.41
    assert air_sensor.extra_state_attributes["etoh"] == 0.22
    assert air_sensor.extra_state_attributes["rmox-0"] == 1.0
    assert air_sensor.extra_state_attributes["rmox-12"] == 13.0
    assert (
        tvoc_sensor.extra_state_attributes["last_update"]
        == AIR_QUALITY_LAST_UPDATE
    )
    assert temp_sensor.device_info["identifiers"] == {(DOMAIN, f"ap-{AP_MAC}")}
    assert temp_sensor.device_info["name"] == "AP-34:5D:A8:0A:2E:40"


async def test_air_quality_entity_classification_and_units(hass) -> None:
    entry = _config_entry("entry_air_quality_class")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {"ap_sensors": {AP_MAC: _full_air_quality_record()}}

    iaq_description = _env_description("ap_air_quality")
    tvoc_description = _env_description("ap_air_quality_tvoc")
    etoh_description = _env_description("ap_air_quality_etoh")
    descriptions_by_key = {
        description.key: description
        for description in AP_ENVIRONMENT_SENSOR_DESCRIPTIONS
    }

    assert iaq_description.entity_category is None
    assert tvoc_description.entity_category is None
    assert etoh_description.entity_category == EntityCategory.DIAGNOSTIC
    assert tvoc_description.device_class == SensorDeviceClass.VOLATILE_ORGANIC_COMPOUNDS
    assert not any(
        key.startswith("ap_air_quality_rmox_")
        for key in descriptions_by_key
    )

    assert iaq_description.native_unit_of_measurement is None
    assert (
        tvoc_description.native_unit_of_measurement
        == UnitOfDensity.MILLIGRAMS_PER_CUBIC_METER
    )
    assert etoh_description.native_unit_of_measurement is None

    etoh_sensor = CiscoWLCAPEnvironmentSensor(
        coordinator,
        entry,
        AP_MAC,
        etoh_description,
    )
    assert etoh_sensor.entity_registry_enabled_default is False


async def test_full_air_quality_payload_creates_no_rmox_entities(hass) -> None:
    entry = _config_entry("entry_air_quality_full")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {"ap_sensors": {AP_MAC: _full_air_quality_record()}}

    entities = await _setup_sensor_entities(hass, coordinator, entry)

    assert _environment_entity_keys(entities) == {
        "ap_air_quality",
        "ap_air_quality_tvoc",
        "ap_air_quality_etoh",
    }


async def test_partial_air_quality_payload_with_iaq_only(hass) -> None:
    entry = _config_entry("entry_air_quality_iaq")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "ap_sensors": {
            AP_MAC: {
                "iaq": 1.0,
                "air_quality_last_update": AIR_QUALITY_LAST_UPDATE,
            }
        }
    }

    entities = await _setup_sensor_entities(hass, coordinator, entry)

    assert _environment_entity_keys(entities) == {"ap_air_quality"}


async def test_partial_air_quality_payload_with_tvoc_but_no_etoh(hass) -> None:
    entry = _config_entry("entry_air_quality_tvoc")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "ap_sensors": {
            AP_MAC: {
                "tvoc": 0.41,
                "air_quality_last_update": AIR_QUALITY_LAST_UPDATE,
            }
        }
    }

    entities = await _setup_sensor_entities(hass, coordinator, entry)

    assert _environment_entity_keys(entities) == {"ap_air_quality_tvoc"}


async def test_air_quality_zero_values_create_entities(hass) -> None:
    entry = _config_entry("entry_air_quality_zero")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "ap_sensors": {
            AP_MAC: {
                "iaq": 0.0,
                "tvoc": 0.0,
                "etoh": 0.0,
                "air_quality_last_update": AIR_QUALITY_LAST_UPDATE,
            }
        }
    }

    entities = await _setup_sensor_entities(hass, coordinator, entry)
    entity_keys = _environment_entity_keys(entities)

    assert entity_keys == {
        "ap_air_quality",
        "ap_air_quality_tvoc",
        "ap_air_quality_etoh",
    }
    for entity in entities:
        if isinstance(entity, CiscoWLCAPEnvironmentSensor):
            assert entity.native_value == 0.0


async def test_ap_without_air_quality_record_creates_no_air_quality_entities(hass) -> None:
    entry = _config_entry("entry_air_quality_absent")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "ap_sensors": {
            AP_MAC: {
                "temperature": 21.86,
                "humidity": 50.92,
                "temperature_last_update": "2025-09-27T01:12:19.453981+00:00",
            }
        }
    }

    entities = await _setup_sensor_entities(hass, coordinator, entry)

    assert not any(
        key.startswith("ap_air_quality")
        for key in _environment_entity_keys(entities)
    )


async def test_air_quality_existing_unique_ids_remain_stable(hass) -> None:
    entry = _config_entry("entry_air_quality_ids")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {"ap_sensors": {AP_MAC: _full_air_quality_record()}}

    sensors = {
        key: CiscoWLCAPEnvironmentSensor(
            coordinator,
            entry,
            AP_MAC,
            _env_description(key),
        )
        for key in (
            "ap_temperature",
            "ap_humidity",
            "ap_air_quality",
            "ap_air_quality_tvoc",
            "ap_air_quality_etoh",
        )
    }

    assert sensors["ap_temperature"].unique_id == f"{AP_MAC}_ap_temperature"
    assert sensors["ap_humidity"].unique_id == f"{AP_MAC}_ap_humidity"
    assert sensors["ap_air_quality"].unique_id == f"{AP_MAC}_ap_air_quality"
    assert (
        sensors["ap_air_quality_tvoc"].unique_id
        == f"{AP_MAC}_ap_air_quality_tvoc"
    )
    assert (
        sensors["ap_air_quality_etoh"].unique_id
        == f"{AP_MAC}_ap_air_quality_etoh"
    )


async def test_client_current_ap_sensor_native_value_tracks_ap_name(hass) -> None:
    entry = _config_entry("entry_client_ap")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "aa:bb:cc:dd:ee:ff": {
            "connected": True,
            "ap-name": "HHO-1haed-9166",
            "device-name": "blackey-iphone",
            CLIENT_NAME_VERIFIED_FIELD: CLIENT_NAME_VERIFIED_VALUE,
        }
    }

    sensor = CiscoWLCClientCurrentAPSensor(
        coordinator,
        entry,
        "aa:bb:cc:dd:ee:ff",
    )

    assert sensor.native_value == "HHO-1haed-9166"
    assert sensor.unique_id == (
        "wlc.example.com_aa:bb:cc:dd:ee:ff_client_current_ap"
    )
    assert sensor.entity_description.translation_key == "client_current_ap"
    assert sensor.entity_description.native_unit_of_measurement is None
    assert sensor.entity_description.device_class is None
    assert sensor.device_info["identifiers"] == {
        (DOMAIN, "wlc.example.com_client_aa:bb:cc:dd:ee:ff")
    }
    assert sensor.device_info["name"] == "blackey-iphone ee:ff"


async def test_client_current_ap_sensor_ignores_unknown_device_name(hass) -> None:
    entry = _config_entry("entry_client_ap_unknown_name")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "aa:bb:cc:dd:ee:ff": {
            "connected": True,
            "ap-name": "HHO-1haed-9166",
            "device-name": "Unknown Device",
            "device-type": "Tablet",
        }
    }

    sensor = CiscoWLCClientCurrentAPSensor(
        coordinator,
        entry,
        "aa:bb:cc:dd:ee:ff",
    )

    assert sensor.device_info["name"] == "Client ee:ff"


async def test_client_current_ap_sensor_uses_default_without_real_name(hass) -> None:
    entry = _config_entry("entry_client_ap_vendor_os")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "f0:b3:ec:14:97:8f": {
            "connected": True,
            "ap-name": "HHO-1haed-9166",
            "device-name": "Unknown",
            "device-type": "Unknown",
            "device-vendor": "Apple",
            "device-os": "iOS 26.5",
        }
    }

    sensor = CiscoWLCClientCurrentAPSensor(
        coordinator,
        entry,
        "f0:b3:ec:14:97:8f",
    )

    assert sensor.device_info["name"] == "Client 97:8f"


async def test_client_current_ap_sensor_ignores_stale_classification_device_name(
    hass,
) -> None:
    entry = _config_entry("entry_client_ap_vendor_name")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "80:b9:89:7b:62:2d": {
            "connected": True,
            "ap-name": "HHO-1haed-9166",
            "device-name": "APPLE, INC.",
            CLIENT_NAME_VERIFIED_FIELD: CLIENT_NAME_VERIFIED_VALUE,
            "device-type": "Apple-Device",
            "device-os": "iPhone16,2",
            "day-zero-dc": "APPLE, INC.",
        }
    }

    sensor = CiscoWLCClientCurrentAPSensor(
        coordinator,
        entry,
        "80:b9:89:7b:62:2d",
    )

    assert sensor.device_info["name"] == "Client 62:2d"


async def test_client_current_ap_sensor_does_not_use_ssid_for_unclassified(
    hass,
) -> None:
    entry = _config_entry("entry_client_ap_unclassified")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "68:3a:48:ef:ca:64": {
            "connected": True,
            "ap-name": "HHO-Vedis-9120",
            "device-name": "Unknown Device",
            "device-type": "Un-Classified Device",
            "ssid": "r2d2",
        }
    }

    sensor = CiscoWLCClientCurrentAPSensor(
        coordinator,
        entry,
        "68:3a:48:ef:ca:64",
    )

    assert sensor.device_info["name"] == "Client ca:64"


async def test_client_current_ap_sensor_reports_not_home_when_disconnected(hass) -> None:
    entry = _config_entry("entry_client_ap_offline")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "aa:bb:cc:dd:ee:ff": {
            "connected": False,
            "ap-name": "HHO-1haed-9166",
        }
    }

    sensor = CiscoWLCClientCurrentAPSensor(
        coordinator,
        entry,
        "aa:bb:cc:dd:ee:ff",
    )

    assert sensor.native_value == "not_home"


async def test_client_current_ap_sensor_attributes_include_roaming_history(hass) -> None:
    entry = _config_entry("entry_client_ap_history")
    coordinator = _coordinator(hass, entry)
    roaming_history = [f"AP-{index} at 12:0{index}:00 - 25 Apr" for index in range(7)]
    coordinator.data = {
        "aa:bb:cc:dd:ee:ff": {
            "connected": True,
            "ap-name": "HHO-2haed-9166",
            "ssid": "Home",
            "current-channel": 100,
            "last_seen": "2026-07-19 14:19:19",
            "attributes_updated": "2026-07-19T14:19:19+00:00",
            "roaming_history": roaming_history,
            "most_recent_roam": roaming_history[0],
            "previous_roam_1": roaming_history[1],
            "previous_roam_6": roaming_history[6],
        }
    }

    sensor = CiscoWLCClientCurrentAPSensor(
        coordinator,
        entry,
        "aa:bb:cc:dd:ee:ff",
    )

    attrs = sensor.extra_state_attributes
    assert attrs["client_mac"] == "aa:bb:cc:dd:ee:ff"
    assert attrs["ssid"] == "Home"
    assert attrs["current_channel"] == 100
    assert attrs["connected"] is True
    assert attrs["last_seen"] == "2026-07-19 14:19:19"
    assert attrs["attributes_updated"] == "2026-07-19T14:19:19+00:00"
    assert attrs["roaming_history"] == roaming_history
    assert attrs["most_recent_roam"] == roaming_history[0]
    assert attrs["previous_roam_1"] == roaming_history[1]
    assert attrs["previous_roam_6"] == roaming_history[6]


async def test_client_current_ap_sensor_is_added_for_client_data(hass) -> None:
    entry = _config_entry(
        "entry_client_ap_setup",
        options={"detailed_macs": ["aa:bb:cc:dd:ee:ff"]},
    )
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "wlc_status": {"online_status": "Online"},
        "aa:bb:cc:dd:ee:ff": {
            "connected": True,
            "ap-name": "HHO-1haed-9166",
        },
        "ap_sensors": {
            AP_MAC: {
                "temperature": 21.86,
            }
        },
    }

    entities = await _setup_sensor_entities(hass, coordinator, entry)

    client_sensors = [
        entity
        for entity in entities
        if isinstance(entity, CiscoWLCClientCurrentAPSensor)
    ]
    assert len(client_sensors) == 1
    assert client_sensors[0].native_value == "HHO-1haed-9166"


async def test_client_current_ap_sensor_is_not_added_for_presence_only_client(hass) -> None:
    entry = _config_entry("entry_client_ap_presence_only")
    coordinator = _coordinator(hass, entry)
    coordinator.data = {
        "aa:bb:cc:dd:ee:ff": {
            "connected": True,
            "ap-name": "HHO-1haed-9166",
        }
    }

    entities = await _setup_sensor_entities(hass, coordinator, entry)

    assert not any(
        isinstance(entity, CiscoWLCClientCurrentAPSensor)
        for entity in entities
    )


async def test_ap_device_and_radio_sensors(hass) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_device",
        data={
            CONF_HOST: "wlc.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
    )

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, entry.data, entry.entry_id, entry.options)

    coordinator.data = {
        "ap_devices": {
            "34:5d:a8:0a:2e:40": {
                "ap_mac": "34:5d:a8:0a:2e:40",
                "name": "Lab AP",
                "location": "Lab",
                "model": "C9166I",
                "last_seen": "2025-09-27T11:55:00+00:00",
                "client_count": 7,
                "clients_24ghz": 3,
                "clients_5ghz": 4,
                "clients_6ghz": 0,
                "cdp": {
                    "device_id": "3560CX-Core-Kjallari.local.is",
                    "neighbor_port": "GigabitEthernet0/4",
                    "platform": "cisco WS-C3560CX-8PC-S",
                    "neighbor_ip": "192.168.10.1",
                    "last_update": "2025-09-27T11:41:04.910951+00:00",
                },
                "lldp": {
                    "neighbor_mac": "08:cc:a7:c4:41:80",
                    "port_id": "Gi0/8",
                    "system_name": "2960CX-Kjallari.local.is",
                    "management_address": "192.168.10.121",
                },
                "radios": {
                    0: {
                        "channel": 1,
                        "channel_width_mhz": 20,
                        "tx_power_dbm": 12,
                        "client_count": 3,
                        "band": "dot11-2-dot-4-ghz-band",
                    },
                    1: {
                        "channel": 36,
                        "channel_width_mhz": 80,
                        "tx_power_dbm": 14,
                        "client_count": 4,
                        "band": "dot11-5-ghz-band",
                    },
                },
            }
        }
    }

    device_description = AP_DEVICE_SENSOR_DESCRIPTIONS[0]
    device_sensor = CiscoWLCAPDeviceSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        device_description,
    )

    sensor_24ghz = CiscoWLCAPDeviceSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        AP_DEVICE_SENSOR_DESCRIPTIONS[1],
    )

    sensor_5ghz = CiscoWLCAPDeviceSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        AP_DEVICE_SENSOR_DESCRIPTIONS[2],
    )

    sensor_6ghz = CiscoWLCAPDeviceSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        AP_DEVICE_SENSOR_DESCRIPTIONS[3],
    )

    status_sensor = CiscoWLCAPStatusSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
    )

    radio_description = AP_RADIO_SENSOR_DESCRIPTIONS[0]
    radio_sensor = CiscoWLCAPRadioSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        0,
        radio_description,
    )
    radio_width_sensor = CiscoWLCAPRadioSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        0,
        AP_RADIO_SENSOR_DESCRIPTIONS[1],
    )
    radio_tx_power_sensor = CiscoWLCAPRadioSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        0,
        AP_RADIO_SENSOR_DESCRIPTIONS[2],
    )

    assert device_sensor.native_value == 7
    assert isinstance(device_sensor.native_value, int)
    assert sensor_24ghz.native_value == 3
    assert sensor_5ghz.native_value == 4
    assert sensor_6ghz.native_value == 0
    assert radio_sensor.native_value == 1
    assert isinstance(radio_sensor.native_value, int)
    assert radio_width_sensor.native_value == 20
    assert isinstance(radio_width_sensor.native_value, int)
    assert radio_tx_power_sensor.native_value == 12
    assert isinstance(radio_tx_power_sensor.native_value, int)
    assert all(
        description.suggested_display_precision == 0
        for description in AP_DEVICE_SENSOR_DESCRIPTIONS
    )
    assert all(
        description.suggested_display_precision == 0
        for description in AP_RADIO_SENSOR_DESCRIPTIONS
    )
    assert device_sensor.device_info["model"] == "C9166I"
    assert radio_sensor.extra_state_attributes["band"] == "dot11-2-dot-4-ghz-band"
    assert device_sensor.device_info["name"] == "AP-Lab AP"
    assert radio_sensor.device_info["name"] == "AP-Lab AP"
    device_attrs = device_sensor.extra_state_attributes
    assert device_attrs["last_seen"] == "2025-09-27T11:55:00+00:00"
    assert status_sensor.native_value == "Online"
    status_attrs = status_sensor.extra_state_attributes
    assert status_attrs["cdp_device_id"] == "3560CX-Core-Kjallari.local.is"
    assert status_attrs["cdp_neighbor_port"] == "GigabitEthernet0/4"
    assert status_attrs["cdp_platform"] == "cisco WS-C3560CX-8PC-S"
    assert status_attrs["cdp_neighbor_ip"] == "192.168.10.1"
    assert status_attrs["cdp_last_update"] == "2025-09-27T11:41:04.910951+00:00"
    assert status_attrs["lldp_neighbor_mac"] == "08:cc:a7:c4:41:80"
    assert status_attrs["lldp_port_id"] == "Gi0/8"
    assert status_attrs["lldp_system_name"] == "2960CX-Kjallari.local.is"
    assert status_attrs["lldp_management_address"] == "192.168.10.121"
    assert status_attrs["last_seen"] == "2025-09-27T11:55:00+00:00"
