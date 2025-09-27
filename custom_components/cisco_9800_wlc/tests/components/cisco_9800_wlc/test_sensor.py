"""Tests for Cisco WLC sensors."""
from __future__ import annotations

from unittest.mock import patch

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
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
)


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
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_ap",
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
        "ap_sensors": {
            "34:5d:a8:0a:2e:40": {
                "temperature": 21.86,
                "humidity": 50.92,
                "temperature_last_update": "2025-09-27T01:12:19.453981+00:00",
                "iaq": 2.55,
                "air_quality_last_update": "2025-09-27T01:12:48.253801+00:00",
            }
        }
    }

    temp_description = AP_ENVIRONMENT_SENSOR_DESCRIPTIONS[0]
    air_quality_description = AP_ENVIRONMENT_SENSOR_DESCRIPTIONS[2]

    temp_sensor = CiscoWLCAPEnvironmentSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        temp_description,
    )
    air_sensor = CiscoWLCAPEnvironmentSensor(
        coordinator,
        entry,
        "34:5d:a8:0a:2e:40",
        air_quality_description,
    )

    assert temp_sensor.native_value == 21.86
    assert air_sensor.native_value == 2.55
    assert temp_sensor.device_info["identifiers"] == {(DOMAIN, "ap-34:5d:a8:0a:2e:40")}
    assert temp_sensor.device_info["name"] == "AP-34:5D:A8:0A:2E:40"


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

    assert device_sensor.native_value == 7
    assert sensor_24ghz.native_value == 3
    assert sensor_5ghz.native_value == 4
    assert sensor_6ghz.native_value == 0
    assert radio_sensor.native_value == 1
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
