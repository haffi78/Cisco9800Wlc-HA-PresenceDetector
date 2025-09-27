# Cisco 9800 WLC Home Assistant Integration

## Overview
This custom integration brings Cisco 9800 Wireless LAN Controller data into Home Assistant. It collects connected-client telemetry, access-point metadata, environmental sensor readings, and exposes controller actions such as toggling AP LEDs. The project follows Home Assistant’s silver-quality checklist: every user-facing feature is documented, options have clear defaults, diagnostics are available, and service/command feedback is surfaced through the UI.

## Features
- **Client presence tracking** – Every connected client is exposed as a `device_tracker` entity with enrichment for device name, OS, RSSI, and optional deep polling per MAC.
- **Controller status sensors** – Diagnostic binary sensor for controller availability plus a software-version sensor that survives restarts.
- **Access point metadata** – Each AP appears as a device with aggregated client counts (total / 2.4 / 5 / 6 GHz), radio details, and automatic “last seen” timestamps.
- **Environmental telemetry** – Temperature, humidity, and air-quality values are normalised per AP and merged into the device sensors.
- **CDP/LLDP insights** – AP entities include attributes describing wired neighbours (device ID, port, platform, management address) for quick topology checks.
- **LED control** – Per-AP buttons trigger LED on/off commands and start/stop flashing (60 s default) via the controller’s RESTCONF RPCs.
- **Options UI** – Users can adjust scan cadence, AP detail refresh cadence, and choose clients for deep polling directly from the config entry options.
- **Diagnostics bundle** – Downloadable diagnostics report the current options, cached AP/client state (sanitised), and latest controller responses to assist troubleshooting.

## Installation

### Through HACS (recommended)
1. Install and configure [HACS](https://hacs.xyz/) in Home Assistant.
2. In HACS, open *Integrations*, select the overflow menu, and choose *Custom repositories*.
3. Enter `https://github.com/haffi78/Cisco9800Wlc-HA-PresenceDetector` as an `Integration` repository.
4. Locate **Cisco 9800 WLC** in the integrations list and click *Download*.
5. Restart Home Assistant so the component is loaded.

### Manual installation
1. Copy `custom_components/cisco_9800_wlc` into `<config>/custom_components/` on your Home Assistant host.
2. Restart Home Assistant.
3. Go to *Settings → Devices & Services → Add Integration* and search for **Cisco 9800 WLC**.
4. Provide the controller hostname/IP and RESTCONF-capable credentials.
5. Enable *Ignore Self-Signed SSL Certificates* only if the controller uses an untrusted certificate.

## Setup & Options
- **Host / Credentials** – Required during setup. Changing them later triggers a re-authentication flow.
- **Ignore Self-Signed SSL Certificates** – Skip TLS validation for lab controllers (avoid in production).
- **Disable newly discovered devices by default** – When enabled, new client trackers remain disabled until you manually enable them in the entity registry.
- **Scan interval (sec)** – Global client polling cadence (default 120 s, minimum 5 s).
- **AP detail scan interval (sec)** – How often AP metadata (radios, CDP/LLDP, sensors) is refreshed (default 3600 s, minimum 60 s).
- **Check the detailed MAC addresses** – Multi-select of clients that should receive deep per-cycle polling; leave empty to rely on passive tracking.

## Entities & Services
- **Devices:**
  - Controller device with status/diagnostic sensors.
  - One device per AP containing:
    - Aggregate sensors (`Total Clients Connected`, band-specific client counts, environment metrics).
    - Buttons: `AP LED On`, `AP LED Off`, `AP LED Flash Start`, `AP LED Flash Stop`.
- **Device trackers:** One per connected client (auto-created/disabled based on options).
- **Services:**
  - `cisco_9800_wlc.set_ap_led_state` (`ap_mac`/`ap_name`, `enabled`, optional `entry_id`).
  - `cisco_9800_wlc.set_ap_led_flash` (`enabled`, optional `duration` seconds).
  - Services are documented under *Developer Tools → Services* thanks to `services.yaml`.

## Diagnostics & System Health
- Use *Settings → Devices & Services → Cisco 9800 WLC → Download Diagnostics* to obtain a redacted JSON snapshot containing controller responses, cached clients, and options.
- The System Health card lists the last successful poll, queued enrichments, and polling status for quick observability.

## Removal / Reset
1. If desired, disable or delete individual client entities under *Entities*.
2. Remove the integration entry from *Settings → Devices & Services*.
3. (Optional) Delete `.storage/cisco_9800_wlc_*` files to clear cached client and AP state.
4. Restart Home Assistant to terminate background tasks.

## Troubleshooting
- **HTTP 401 / authentication failures** – Validate credentials, ensure RESTCONF is enabled, and complete the re-auth prompt when shown.
- **HTTP 4xx/5xx on LED services** – Check the Home Assistant logs; errors identify the AP and include controller feedback. Confirm the AP is online and the account has config privileges.
- **Controller overload (HTTP 409)** – Increase the scan interval, reduce detailed MACs, or stagger multiple integrations.
- **Missing AP data** – Verify the AP appears in the controller RESTCONF API and that the AP detail scan interval is not set too high for your use case.

For questions or bug reports use the GitHub issue tracker linked in the manifest. Contributions—bugs, docs, or new features—are welcomed via pull request.
