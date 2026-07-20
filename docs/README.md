# Cisco 9800 WLC Home Assistant Integration

## Overview
This custom integration brings Cisco 9800 Wireless LAN Controller data into Home Assistant. It collects connected-client telemetry, access-point metadata, environmental sensor readings, and exposes controller actions such as toggling AP LEDs. The project follows Home Assistant’s bronze-quality checklist while continuing to add the documentation, diagnostics, and runtime handling expected of higher tiers.

## Features
- **Client presence tracking** – Every connected client is exposed as a `device_tracker` entity with one-shot naming enrichment and optional recurring deep polling per selected MAC.
- **Client AP history** – Selected detailed clients also get a `Current AP` sensor whose state is the AP name, allowing Home Assistant recorder/history to show where the client has roamed over time.
- **Controller status sensors** – Diagnostic binary sensor for controller availability plus a software-version sensor that survives restarts.
- **Access point metadata** – Each AP appears as a device with aggregated client counts (total / 2.4 / 5 / 6 GHz), radio details, and automatic “last seen” timestamps.
- **Environmental telemetry** – Temperature, humidity, IAQ, and TVOC sensors are normalised per AP, with EtOH as a disabled-by-default diagnostic sensor and RMOX values exposed as AP Air Quality attributes when reported.
- **CDP/LLDP insights** – AP devices include string sensors describing wired neighbours (device ID, port, platform, management address) for quick topology checks.
- **LED control** – Per-AP buttons trigger LED on/off commands and start/stop flashing (60 s default) via the controller’s RESTCONF RPCs.
- **Options UI** – Users can adjust scan cadence, AP inventory/radio refresh cadence, and choose which clients receive recurring deep polling directly from the config entry options.
- **Diagnostics bundle** – Downloadable diagnostics report the current options, cached AP/client state (sanitised), and latest controller responses to assist troubleshooting.

## AP Air-Quality Values
- **IAQ** is Cisco's processed indoor-air-quality value from the AP environmental sensor data. Lower values appear to represent better air quality, but Cisco does not publicly document RESTCONF category boundaries.
- **TVOC** is Cisco's processed total volatile organic compounds value. Cisco Spaces can display TVOC in ppb or micrograms per cubic meter; this integration presents the Catalyst 9800 RESTCONF value as milligrams per cubic meter based on observed AP scale and Cisco Spaces' recommended level.
- **EtOH** is an ethanol/alcohol-like volatile compound output included in WLC operational data. It is exposed as a disabled-by-default diagnostic sensor because Cisco Spaces does not normally present it as a user-facing environmental metric.
- **RMOX 0-12** are raw metal-oxide gas-sensor values used as air-quality processing inputs. They are exposed as attributes on the AP Air Quality sensor, not standalone entities. They are diagnostic values, not separate named pollutants, and Cisco does not document individual gas meanings, thresholds, or health interpretations.

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
- **Scan interval (sec)** – Global client polling and AP environmental telemetry cadence, including temperature, humidity, IAQ, and TVOC (default 120 s, minimum 5 s).
- **AP inventory/radio refresh interval (sec)** – How often AP identity, join state, radio details, client totals, and CDP/LLDP neighbour data are refreshed (default 3600 s, minimum 60 s).
- **Check the detailed MAC addresses** – Multi-select of clients that should receive recurring deep polling; leave empty for presence tracking plus one-shot naming only. Current AP history only updates continuously for clients selected here.

## Entities & Services
- **Devices:**
  - Controller device with status/diagnostic sensors.
  - One device per AP containing:
    - Aggregate sensors (`Total Clients Connected`, band-specific client counts, environment metrics).
    - Buttons: `AP LED On`, `AP LED Off`, `AP LED Flash Start`, `AP LED Flash Stop`.
- **Device trackers:** One enabled presence tracker per discovered client, with one-shot enrichment for naming; selected clients also receive recurring detailed telemetry attributes.
- **Client Current AP sensors:** One sensor per selected detailed client. Its state is the detailed `ap-name` value when available and `not_home` when the client drops offline, so Home Assistant can retain AP-name history through recorder. The sensor itself does not perform extra WLC calls.
- **Client roaming history:** Detailed client attributes include the current AP plus most recent roam, six previous roams, and a compact `Roaming History` list.
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
- **Missing AP inventory/radio data** – Verify the AP appears in the controller RESTCONF API and that the AP inventory/radio refresh interval is not set too high for your use case.

For questions or bug reports use the GitHub issue tracker linked in the manifest. Contributions—bugs, docs, or new features—are welcomed via pull request.
