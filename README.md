# Cisco 9800 WLC Device Tracker

## Overview

The **Cisco 9800 WLC Device Tracker** is a Home Assistant custom integration that discovers and monitors clients connected to a Cisco 9800 Wireless LAN Controller using the RESTCONF API. It provides router-based device tracker entities, a controller connectivity sensor, and a software-version diagnostic sensor, keeping Home Assistant informed about who is on the network.

## Features

- Tracks every client currently reported by the controller and keeps last-known attributes even when clients disconnect.
- UI-only setup and configuration; no YAML required.
- Adjustable polling interval (default 30 seconds) directly from the Options dialog.
- Selective detailed telemetry: choose which MAC addresses receive the heavier per-client RESTCONF lookups (AP name, SSID, device metadata, roaming history, etc.).
- Newly discovered clients trigger an optional dispatcher signal so you can enable them on demand.
- Supports ignoring self-signed SSL certificates when talking to the controller.
- All Wi-Fi client entities start disabled by default to avoid pulling data you do not need.

## Installation

### Manual Installation
1. Download the latest release from [GitHub](https://github.com/haffi78/Cisco9800Wlc-HA-PresenceDetector).
2. Copy the `cisco_9800_wlc` directory into your Home Assistant `custom_components` folder:
   ```
   /config/custom_components/cisco_9800_wlc
   ```
3. Restart Home Assistant.

### HACS (Recommended)
1. Open **HACS** → **Integrations** → **+ Explore & Add Repositories**.
2. Add `https://github.com/haffi78/Cisco9800Wlc-HA-PresenceDetector` as an integration repository.
3. Install and restart Home Assistant.

## Configuration

1. In Home Assistant, go to **Settings → Devices & Services → Add Integration**.
2. Search for **Cisco 9800 WLC** and fill in:
   - WLC IP address or hostname
   - Username / password (RESTCONF enabled user)
   - Whether to ignore SSL certificate validation
3. Submit to create the config entry.
4. After setup, open **Settings → Devices & Services → Cisco 9800 WLC → Configure → Options** to fine-tune the behaviour.

### Options Dialog

- **Disable newly discovered devices** – when enabled, new device tracker entities remain disabled until you turn them on manually.
- **Polling interval (seconds)** – adjust how often the integration polls the controller (minimum 5 seconds, default 30).
- **Clients to poll for detailed telemetry** – multi-select of known MAC addresses. Only selected clients trigger the heavier per-client RESTCONF calls for SSID, AP, roaming history, etc.; the rest receive lightweight presence/IP updates.

> Tip: leave the list empty if you only need basic presence or IP tracking. Add clients selectively to keep controller load low.

## Entities

- **Device trackers** (`device_tracker.*`) – one per client. The entity stays present even when the client disconnects so you retain useful attributes.
- **Binary sensor** – reports the controller’s Online/Offline status.
- **Software version sensor** – exposes the WLC software version and continues to show the last known value even if polling is temporarily disabled.

## Troubleshooting

| Symptom | Suggested Action |
| --- | --- |
| Integration fails to load with SSL errors | Enable “Ignore self-signed SSL certificates” or install a trusted certificate on the controller. |
| Detailed telemetry never appears | Ensure the MAC is ticked in the Options dialog and allow one polling interval for attributes to populate. |
| Polling feels slow | Reduce the detailed telemetry list or increase the polling interval. The base client list fetch typically returns in <0.2s with no detailed MACs selected. |
| Entities remain disabled | Enable them under **Settings → Devices & Services → Cisco 9800 WLC → Entities**. New devices are created disabled by default. |

## License

Released under the MIT License.

