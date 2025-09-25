# Cisco 9800 WLC Home Assistant Integration Guide

## Overview
This guide explains how to install, configure, and maintain the custom integration that exposes Cisco 9800 Wireless LAN Controller client telemetry to Home Assistant. It complements the in-product help text and should be referenced from the integration manifest.

## Installation
1. Copy the `custom_components/cisco_9800_wlc` directory into `<config>/custom_components/` on your Home Assistant instance.
2. Restart Home Assistant to load the new integration code.
3. In the UI, navigate to *Settings → Devices & Services → Add Integration* and search for **Cisco 9800 WLC**.
4. Provide the controller hostname or IP, along with credentials that allow RESTCONF read access.
5. (Optional) Toggle *Ignore Self-Signed SSL Certificates* if your controller uses a self-signed certificate.

## Configuration Parameters
- **Controller Host** (`host`): The management IP address or DNS name of the WLC. This value cannot be changed after setup; remove and re-add the integration if the host changes.
- **Username / Password** (`username`, `password`): Credentials used for RESTCONF authentication. If they change later, the integration will prompt you to re-authenticate.
- **Ignore Self-Signed SSL Certificates** (`ignore_ssl`): When enabled, the integration will trust certificates that cannot be validated. Disable whenever possible.
- **Disable Newly Discovered Clients by Default** (`enable_new_entities` option): When enabled, newly discovered client trackers remain disabled until you manually enable them in the entity registry.
- **Polling Interval** (`scan_interval` option): Controls how frequently the controller is polled for the client list. Defaults to 120 seconds; lowering the value increases controller load.
- **Detailed Client Telemetry** (`detailed_macs` option): A list of client MAC addresses that should receive per-cycle deep polling.

## Entity Management
- Each wireless client is exposed as a device tracker entity named after the client and its MAC suffix.
- The integration also provides a connectivity binary sensor and a software version diagnostic sensor for the controller itself.
- Entities support the *Enable* toggle in the registry; use it to remove stale clients without deleting the entire integration.

## Diagnostics and System Health
- Home Assistant’s diagnostics explorer includes redacted payloads with controller settings, options, and cached client data.
- The System Health panel reports the most recent successful poll, queued enrichment requests, and whether polling is disabled.

## Removal and Reset
1. Disable or delete any client entities you no longer need from *Settings → Devices & Services → Entities*.
2. Open the **Cisco 9800 WLC** integration entry and choose *Delete* to remove the config entry and stored credentials.
3. Clear the `.storage` files prefixed with `cisco_9800_wlc_` if you want to reset cached client state.
4. Restart Home Assistant to ensure all background tasks terminate cleanly.

## Troubleshooting
- **Authentication errors (HTTP 401)**: Confirm credentials and re-run through the re-authentication prompt when presented.
- **Frequent HTTP 400 responses**: Increase the polling interval or reduce the number of clients listed for detailed telemetry.
- **Missing clients**: Verify that the client appears in the WLC RESTCONF API and that it has not been manually disabled in the entity registry.

For community support or to report issues, use the GitHub issue tracker referenced in the integration manifest.
