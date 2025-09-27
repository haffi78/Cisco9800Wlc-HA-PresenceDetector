"""Tests for Cisco WLC device tracker entity naming."""
from __future__ import annotations

from types import SimpleNamespace

from custom_components.cisco_9800_wlc.device_tracker import CiscoWLCClient


def _make_client(mac: str, attributes: dict[str, str] | None = None) -> CiscoWLCClient:
    client = CiscoWLCClient.__new__(CiscoWLCClient)
    client.mac = mac
    client.coordinator = SimpleNamespace(
        data={mac: attributes or {}},
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
    assert client.device_info.name == "Haffi iPhone"


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
