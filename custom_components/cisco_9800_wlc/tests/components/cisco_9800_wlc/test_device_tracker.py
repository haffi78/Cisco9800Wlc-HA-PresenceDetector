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

    assert client._device_registry_label() == "Haffi iPhone"
    assert client._current_friendly_name() == "Haffi iPhone ee:ff"
    assert client.device_info["name"] == "Haffi iPhone"


def test_client_name_uses_device_type_when_name_missing() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    client = _make_client(mac, {"device-type": "Tablet"})

    assert client._device_registry_label() == "Tablet"
    assert client._current_friendly_name() == "Tablet ee:ff"


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
