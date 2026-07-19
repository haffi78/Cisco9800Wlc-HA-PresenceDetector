"""Tests for Cisco WLC device tracker entity naming."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import entity_registry as er
from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc.const import DOMAIN
from custom_components.cisco_9800_wlc.coordinator import CiscoWLCUpdateCoordinator
from custom_components.cisco_9800_wlc.device_tracker import CiscoWLCClient


def _make_client(
    mac: str,
    attributes: dict[str, str] | None = None,
    *,
    host: str = "wlc.example.com",
    entry_id: str = "entry_1",
) -> CiscoWLCClient:
    client = CiscoWLCClient.__new__(CiscoWLCClient)
    client.mac = mac
    client.coordinator = SimpleNamespace(
        data={mac: attributes or {}},
        entry_id=entry_id,
        host=host,
        last_update_success=True,
    )
    client._enable_by_default = True  # type: ignore[attr-defined]
    client._attr_should_poll = False  # type: ignore[attr-defined]
    return client


def test_client_name_uses_device_name_with_suffix() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(mac, {"device-name": "Haffi iPhone"})

    assert client.name is None
    assert client._device_registry_label() == "Haffi iPhone ee:ff"
    assert client._current_friendly_name() == "Haffi iPhone ee:ff"
    assert client.device_info["name"] == "Haffi iPhone ee:ff"


def test_client_name_uses_default_when_name_missing() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(mac, {"device-type": "Tablet"})

    assert client._device_registry_label() == "Client ee:ff"
    assert client._current_friendly_name() == "Client ee:ff"


def test_client_name_ignores_unknown_device_placeholder() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(
        mac,
        {
            "device-name": "Unknown Device",
            "device-type": "Tablet",
            "device-os": "Android",
        },
    )

    assert client._device_registry_label() == "Client ee:ff"
    assert client._current_friendly_name() == "Client ee:ff"


def test_client_name_uses_default_when_name_is_unknown() -> None:
    mac = "f0:b3:ec:14:97:8f"
    client = _make_client(
        mac,
        {
            "device-name": "Unknown",
            "device-type": "Unknown",
            "device-vendor": "Apple",
            "device-os": "iOS 26.5",
            "day-zero-dc": "APPLE, INC.",
        },
    )

    assert client._device_registry_label() == "Client 97:8f"
    assert client._current_friendly_name() == "Client 97:8f"


def test_client_name_uses_any_non_placeholder_device_name() -> None:
    mac = "80:b9:89:7b:62:2d"
    client = _make_client(
        mac,
        {
            "device-name": "APPLE, INC.",
            "device-type": "Apple-Device",
            "device-os": "iPhone16,2",
            "day-zero-dc": "APPLE, INC.",
        },
    )

    assert client._device_registry_label() == "APPLE, INC. 62:2d"
    assert client._current_friendly_name() == "APPLE, INC. 62:2d"


def test_client_name_does_not_use_udhcp_vendor_as_label() -> None:
    mac = "44:3e:07:27:28:e8"
    client = _make_client(
        mac,
        {
            "device-name": "Unknown Device",
            "device-vendor": "udhcp 1.19.4",
            "device-protocol": "DHCP",
        },
    )

    assert client._device_registry_label() == "Client 28:e8"
    assert client._current_friendly_name() == "Client 28:e8"


def test_client_name_does_not_use_ssid_for_unclassified_device() -> None:
    mac = "68:3a:48:ef:ca:64"
    client = _make_client(
        mac,
        {
            "device-name": "Unknown Device",
            "device-type": "Un-Classified Device",
            "ssid": "r2d2",
            "protocol-map": "protocol-map-oui protocol-map-dhcp",
            "confidence-level": 0,
        },
    )

    assert client._device_registry_label() == "Client ca:64"
    assert client._current_friendly_name() == "Client ca:64"


def test_client_attributes_ignore_unknown_device_placeholder() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(
        mac,
        {
            "device-name": "Unknown Device",
            "device-type": "Tablet",
        },
    )

    attrs = client.extra_state_attributes

    assert attrs["Device Name"] is None
    assert attrs["Device Type"] == "Tablet"


def test_client_attributes_keep_non_placeholder_device_name() -> None:
    mac = "80:b9:89:7b:62:2d"
    client = _make_client(
        mac,
        {
            "device-name": "APPLE, INC.",
            "device-type": "Apple-Device",
            "device-os": "iPhone16,2",
            "day-zero-dc": "APPLE, INC.",
        },
    )

    attrs = client.extra_state_attributes

    assert attrs["Device Name"] == "APPLE, INC."
    assert attrs["Day Zero Classification"] == "APPLE, INC."


def test_client_attributes_include_device_classification() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(
        mac,
        {
            "protocol-map": "protocol-map-oui protocol-map-dhcp protocol-map-http",
            "confidence-level": 10,
            "classified-time": "2026-07-19T17:10:00+00:00",
            "day-zero-dc": "APPLE, INC.",
            "device-vendor": "Apple",
            "device-protocol": "DHCP",
        },
    )

    attrs = client.extra_state_attributes

    assert attrs["Protocol Map"] == (
        "protocol-map-oui protocol-map-dhcp protocol-map-http"
    )
    assert attrs["Classification Confidence"] == 10
    assert attrs["Classified Time"]
    assert attrs["Day Zero Classification"] == "APPLE, INC."
    assert attrs["Device Vendor"] == "Apple"
    assert attrs["Device Protocol"] == "DHCP"


def test_client_name_falls_back_to_generic_label() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(mac, {})

    assert client._device_registry_label() == "Client ee:ff"
    assert client._current_friendly_name() == "Client ee:ff"


def test_client_unique_id_is_scoped_to_wlc_host() -> None:
    mac = "aa:bb:cc:dd:ee:ff"

    client_a = _make_client(mac, host="wlc-int.example.com", entry_id="entry_a")
    client_b = _make_client(mac, host="wlc-ext.example.com", entry_id="entry_b")

    assert client_a.unique_id == "wlc-int.example.com_aa:bb:cc:dd:ee:ff"
    assert client_b.unique_id == "wlc-ext.example.com_aa:bb:cc:dd:ee:ff"
    assert client_a.unique_id != client_b.unique_id
    assert client_a.mac_address == mac


def test_client_presence_tracker_is_enabled_by_default() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(mac)
    client._enable_by_default = False  # type: ignore[attr-defined]

    assert client.entity_registry_enabled_default is True


def test_client_device_info_is_scoped_to_wlc_entry() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(mac, host="wlc-int.example.com", entry_id="entry_a")

    assert client.device_info["identifiers"] == {
        (DOMAIN, "wlc-int.example.com_client_aa:bb:cc:dd:ee:ff")
    }
    assert client.device_info["via_device"] == (DOMAIN, "entry_a")


def test_client_attributes_include_ip_versions_and_controller() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(
        mac,
        {
            "IP Address": "192.0.2.10",
            "IPv4 Address": "192.0.2.10",
            "IPv6 Address": "2001:db8::10",
            "IPv6 Addresses": ["fe80::1", "2001:db8::10"],
            "Connected to Controller": "wlc-int.example.com",
        },
    )

    attrs = client.extra_state_attributes

    assert attrs["IP Address"] == "192.0.2.10"
    assert attrs["IPv4 Address"] == "192.0.2.10"
    assert attrs["IPv6 Address"] == "2001:db8::10"
    assert attrs["IPv6 Addresses"] == ["fe80::1", "2001:db8::10"]
    assert attrs["Connected to Controller"] == "wlc-int.example.com"


def test_client_attributes_include_extended_roaming_history() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    roaming_history = [f"AP-{index} at 12:0{index}:00 - 25 Apr" for index in range(7)]
    client = _make_client(
        mac,
        {
            "roaming_history": roaming_history,
            "most_recent_roam": roaming_history[0],
            "previous_roam_1": roaming_history[1],
            "previous_roam_2": roaming_history[2],
            "previous_roam_3": roaming_history[3],
            "previous_roam_4": roaming_history[4],
            "previous_roam_5": roaming_history[5],
            "previous_roam_6": roaming_history[6],
        },
    )

    attrs = client.extra_state_attributes

    assert attrs["Roaming History"] == roaming_history
    assert attrs["Most Recent Roam"] == roaming_history[0]
    assert attrs["Previous Roam 1"] == roaming_history[1]
    assert attrs["Previous Roam 4"] == roaming_history[4]
    assert attrs["Previous Roam 6"] == roaming_history[6]


async def test_coordinator_registry_lookup_is_scoped_to_config_entry(hass) -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    entry_a = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_a",
        data={
            CONF_HOST: "wlc-int.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
    )
    entry_b = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_b",
        data={
            CONF_HOST: "wlc-ext.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
    )
    entry_a.add_to_hass(hass)
    entry_b.add_to_hass(hass)

    registry = er.async_get(hass)
    registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        "wlc-int.example.com_aa:bb:cc:dd:ee:ff",
        suggested_object_id="client_a",
        config_entry=entry_a,
    )
    registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        "wlc-ext.example.com_aa:bb:cc:dd:ee:ff",
        suggested_object_id="client_b",
        config_entry=entry_b,
    )

    with patch(
        "custom_components.cisco_9800_wlc.coordinator.CiscoWLCUpdateCoordinator._start_enrich_worker",
        return_value=None,
    ):
        coordinator = CiscoWLCUpdateCoordinator(hass, entry_a.data, entry_a.entry_id)

    assert coordinator.get_registered_macs() == {mac}
