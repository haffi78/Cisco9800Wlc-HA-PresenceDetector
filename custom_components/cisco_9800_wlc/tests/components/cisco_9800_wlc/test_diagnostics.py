"""Tests for diagnostics output."""
from __future__ import annotations

from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

from tests.common import MockConfigEntry

from custom_components.cisco_9800_wlc import diagnostics
from custom_components.cisco_9800_wlc.const import CONF_DETAILED_MACS, DOMAIN


class DummyCoordinator:
    def __init__(self) -> None:
        self.host = "wlc.example.com"
        self._options = {}
        self.update_interval = None
        self.data = {
            "wlc_status": {"online_status": "Online", "software_version": "17.15.4"},
            "aa:bb:cc:dd:ee:ff": {
                "IP Address": "192.0.2.10",
                "username": "user1",
                "attributes_updated": "2025-09-24T22:00:00Z",
            },
        }

    def _polling_disabled(self) -> bool:
        return False


async def test_diagnostics_sanitizes_clients(hass):
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry_1",
        title="Test WLC",
        data={
            CONF_HOST: "wlc.example.com",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        },
        options={CONF_DETAILED_MACS: ["aa:bb:cc:dd:ee:ff"]},
    )
    coordinator = DummyCoordinator()
    entry.add_to_hass(hass)
    entry.runtime_data = coordinator

    result = await diagnostics.async_get_config_entry_diagnostics(hass, entry)

    assert result["controller"]["host"] == "wlc.example.com"
    assert result["client_count"] == 1
    client = result["clients"]["aa:bb:cc:dd:ee:ff"]
    assert client["username"] == "**REDACTED**"
    assert client["attributes_updated"] == "**REDACTED**"
    assert result["entry"]["data"][CONF_USERNAME] == "**REDACTED**"
    assert result["entry"]["data"][CONF_PASSWORD] == "**REDACTED**"
