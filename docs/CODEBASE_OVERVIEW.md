# Cisco 9800 WLC Home Assistant Integration - Codebase Overview

This document is an onboarding summary for new developers and for future AI
coding sessions. It explains what the integration does, how data moves through
the code, and which areas need extra care when making changes.

## Project Purpose

This repository contains a Home Assistant custom integration for Cisco Catalyst
9800 Wireless LAN Controllers. The integration connects to the WLC RESTCONF API
over HTTPS and exposes controller, client, and access point data inside Home
Assistant.

The integration currently provides:

- Device tracker entities for connected wireless or wired clients.
- A controller connectivity binary sensor.
- A controller software version diagnostic sensor.
- AP status, AP client-count, AP radio, and AP environmental sensors.
- AP LED control buttons and services.
- Config flow, options flow, diagnostics, and system health support.
- Local fixture capture tooling for testing with real WLC RESTCONF payloads.

The integration is configured in Home Assistant as `cisco_9800_wlc`.

## Repository Layout

- `custom_components/cisco_9800_wlc/`
  Main Home Assistant integration package.

- `custom_components/cisco_9800_wlc/__init__.py`
  Entry setup and unload logic. Creates the coordinator, registers services,
  loads cached state, runs the first refresh, and forwards setup to platforms.

- `custom_components/cisco_9800_wlc/coordinator.py`
  Core runtime logic. Owns RESTCONF polling, status tracking, client enrichment,
  AP metadata parsing, AP environmental parsing, caching, and LED RPC calls.

- `custom_components/cisco_9800_wlc/config_flow.py`
  Initial setup, reauthentication, and options UI.

- `custom_components/cisco_9800_wlc/device_tracker.py`
  Client `device_tracker` entities.

- `custom_components/cisco_9800_wlc/sensor.py`
  Controller version sensor plus AP status, AP aggregate, AP radio, and AP
  environmental sensors.

- `custom_components/cisco_9800_wlc/binary_sensor.py`
  Controller online/offline binary sensor.

- `custom_components/cisco_9800_wlc/button.py`
  Per-AP LED control buttons.

- `custom_components/cisco_9800_wlc/diagnostics.py`
  Downloadable redacted diagnostics.

- `custom_components/cisco_9800_wlc/system_health.py`
  Home Assistant System Health information.

- `custom_components/cisco_9800_wlc/utils.py`
  Shared URL and entity-identifier helpers.

- `custom_components/cisco_9800_wlc/services.yaml`
  User-facing service descriptions for AP LED control.

- `custom_components/cisco_9800_wlc/tests/`
  Unit tests for setup flows, coordinator behavior, entities, diagnostics, and
  local fixture parsing.

- `custom_components/cisco_9800_wlc/tests/fixtures/cisco_9800_wlc/`
  Local-only fixture capture tooling. JSON captures are intentionally ignored
  because real WLC payloads may contain sensitive data.

## Home Assistant Startup Flow

1. Home Assistant loads the integration domain from `manifest.json`.

2. `async_setup` in `__init__.py` initializes `hass.data[DOMAIN]` with:
   - `tracked_macs`
   - `coordinators`
   - `services_registered`

3. `async_setup_entry` creates one `CiscoWLCUpdateCoordinator` for the config
   entry and stores it as `entry.runtime_data`.

4. Before the first refresh, the coordinator loads cached controller status and
   cached client attributes from Home Assistant storage.

5. The coordinator performs `async_config_entry_first_refresh()`, which calls
   `_async_update_data()` unless polling is disabled.

6. The integration registers AP LED services once per Home Assistant instance.

7. Home Assistant forwards platform setup to:
   - `device_tracker`
   - `binary_sensor`
   - `sensor`
   - `button`

8. On unload, platforms are unloaded, background enrichment work is cancelled,
   service registration is removed when no WLC entries remain, and
   `entry.runtime_data` is cleared.

## Configuration And Options

The config flow validates the controller by sending a GET request to:

```text
/restconf/data
```

Required setup fields:

- `host`
- `username`
- `password`
- `ignore_ssl`

The config entry unique ID is the host value. This means one Home Assistant
entry per WLC host.

The options flow controls:

- `enable_new_entities`
  Despite the current README wording, the code passes this value to
  `entity_registry_enabled_default`. `True` means newly created client tracker
  entities are enabled by default. `False` means they are disabled by default.

- `scan_interval`
  Main client polling interval. The minimum is 5 seconds.

- `ap_detail_interval`
  AP metadata refresh interval. The minimum is 60 seconds. Default is 3600
  seconds.

- `detailed_macs`
  A list of client MACs that should receive detailed per-cycle enrichment.

If `detailed_macs` is not explicitly set, enabled device tracker entities are
used as the detailed enrichment target set.

## Coordinator Responsibilities

`CiscoWLCUpdateCoordinator` is the most important class in the project.

It owns:

- RESTCONF API URLs and authentication.
- Main client polling.
- Controller online/offline state.
- Software version polling.
- New client detection.
- One-shot client enrichment queue.
- Detailed client telemetry polling.
- Client attribute cache persistence.
- AP metadata polling and caching.
- AP environmental telemetry polling.
- AP MAC alias resolution.
- AP LED RPC operations.

The coordinator keeps its current state in `self.data`. Home Assistant entities
read from that dictionary through `CoordinatorEntity`.

Important top-level keys in `coordinator.data`:

- `wlc_status`
  Controller software version and online status.

- one key per client MAC
  Client tracker data and optional enriched attributes.

- `ap_sensors`
  Raw AP environmental telemetry keyed by AP MAC.

- `ap_devices`
  Merged AP metadata, radio data, client totals, CDP/LLDP, and environmental
  values keyed by canonical AP MAC.

## Main Client Polling

The main polling method is `_async_update_data()` in `coordinator.py`.

It fetches the active client list from:

```text
/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac
```

For each client, it records:

- MAC address.
- IPv4 address if present.
- IPv6 address if present, preferring the first non-link-local address for the
  single `IPv6 Address` attribute.
- All reported IPv6 addresses in `IPv6 Addresses`.
- The configured controller host/FQDN that reported the client.
- `last_seen`.
- `connected = True`.

Clients that disappear from the WLC response are carried forward with
`connected = False`. This is important because WLCs can retain idle clients for
some time, and Home Assistant should not immediately delete or lose historical
attributes.

The coordinator also compares active clients with registered Home Assistant
entities. New clients are announced through the dispatcher signal
`cisco_9800_wlc_new_clients`, which lets `device_tracker.py` create new tracker
entities dynamically.

## Client Detailed Enrichment

Detailed client enrichment is optional and controlled by `detailed_macs` or by
enabled tracker entities when the option is unset.

Detailed enrichment uses these RESTCONF endpoints:

```text
/common-oper-data={mac}
/dot11-oper-data={mac}
/dc-info={mac}
/traffic-stats={mac}/speed
/mm-if-client-history={mac}/mobility-history
```

The code extracts:

- AP name or wired connection fallback.
- Username.
- SSID.
- Current channel.
- Authentication/key management.
- Wi-Fi standard.
- Device name, type, and OS.
- Connection speed.
- Recent roaming history.

Enrichment avoids replacing useful old values with empty, unknown, or placeholder
values. `_is_meaningful()` is the key helper for this behavior.

There are two enrichment paths:

- Per-cycle enrichment for configured detailed MACs.
- Background one-shot enrichment for new or previously unseen clients.

The one-shot enrichment worker has retries and mild throttling awareness. It is
started by the coordinator and cancelled during unload.

## Client Entity Model

Client entities are implemented in `device_tracker.py` by `CiscoWLCClient`.

Important behavior:

- `source_type` is `ROUTER`.
- `is_connected` reads the client's `connected` flag from coordinator data.
- Entity attributes are converted into user-facing names such as `SSID`,
  `Access Point Name`, `IPv4 Address`, `IPv6 Address`, `IPv6 Addresses`,
  `Connected to Controller`, `Connection Speed Mbps`, `Device Name`, and
  roaming fields.
- Timestamps are formatted into local time for display.
- Entity names prefer device name, then device type, then device OS, then a
  generic `Client xx:yy` fallback.

Unique IDs are intentionally controller-scoped:

```text
{controller_host}_{client_mac}
```

Device registry identifiers are also controller-scoped:

```text
{controller_host}_client_{client_mac}
```

This matters because the same client MAC can appear on multiple WLCs. Do not
change this back to MAC-only unique IDs.

Legacy MAC-only unique IDs are migrated to controller-scoped IDs when possible.

## Controller Status

Controller connectivity lives in `wlc_status` inside coordinator data.

The binary sensor in `binary_sensor.py` reports online when:

```text
wlc_status["online_status"] == "Online"
```

Main client polling marks the controller online on success and offline on client
poll failures. Software-version fetch failures do not mark the controller
offline, because version polling is secondary and should not falsely report the
controller down.

The software version sensor in `sensor.py` extracts a shorter semantic version
from Cisco's raw version string but keeps the raw version in device info.

## AP Metadata And Sensors

AP metadata is fetched in `_async_fetch_ap_metadata()` from:

```text
/restconf/data/Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data/ap-join-stats
/restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data
```

The coordinator merges several Cisco payload sections:

- `ap-join-stats`
- `ethernet-mac-wtp-mac-map`
- `ap-name-mac-map`
- `capwap-data`
- `radio-oper-data`
- `radio-oper-stats`
- `ap-sensor-status`
- `cdp-cache-data`
- `lldp-neigh`

AP records are keyed by a canonical AP MAC. The WLC may expose multiple MACs for
the same AP, so `_ap_mac_aliases` and `_canonical_ap_mac()` are important.

AP metadata includes:

- AP name.
- IP address.
- Location.
- Model.
- Admin and operational state.
- Online state.
- LED state.
- Radio slot data.
- Per-radio client counts.
- Per-band total client counts.
- CDP neighbor details.
- LLDP neighbor details.
- Last seen timestamp.

AP environmental telemetry is fetched separately from:

```text
/access-point-oper-data/ap-temp
/access-point-oper-data/ap-air-quality
```

Environmental values include:

- Temperature.
- Humidity.
- IAQ.
- TVOC.
- EtOH.
- RMOX values.
- Last update timestamps.

Air-quality interpretation:

- `iaq` is Cisco's processed indoor-air-quality value. Lower values appear to
  represent better air quality, but Cisco does not publicly document RESTCONF
  category boundaries.
- `tvoc` is Cisco's processed total volatile organic compounds value. Cisco
  Spaces can display TVOC in ppb or micrograms per cubic meter. The integration
  presents the Catalyst 9800 RESTCONF value as milligrams per cubic meter based
  on observed AP scale and Cisco Spaces' recommended level.
- `etoh` is an ethanol/alcohol-like volatile compound output in WLC operational
  data. It is exposed as a disabled-by-default diagnostic entity because Cisco
  Spaces does not normally show it as a user-facing environmental metric.
- `rmox-0` through `rmox-12` are raw metal-oxide gas-sensor values used as
  air-quality processing inputs. They are exposed as AP Air Quality attributes,
  not standalone entities. They are diagnostic values, not separate named
  pollutants, and Cisco does not document individual gas meanings, thresholds,
  or health interpretations.

`_async_update_ap_devices()` controls when AP metadata is refreshed. It uses
`ap_detail_interval` to avoid expensive metadata polling every client scan, then
merges fresh environmental telemetry into the cached AP records.

## AP Entity Model

AP entities are implemented mostly in `sensor.py` and `button.py`.

All AP entities use the same Home Assistant device identifier:

```text
(DOMAIN, f"ap-{ap_mac}")
```

That keeps AP status sensors, AP metric sensors, environmental sensors, and AP
LED buttons grouped under the same AP device.

AP sensors include:

- AP online status.
- Total connected clients.
- 2.4 GHz client count.
- 5 GHz client count.
- 6 GHz client count.
- Per-radio channel.
- Per-radio channel width.
- Per-radio TX power.
- Temperature.
- Humidity.
- Air quality index.
- TVOC.
- EtOH.

The AP Air Quality sensor also exposes `tvoc`, `etoh`, and `rmox-0` through
`rmox-12` as attributes when the AP reports them. The `RMOX` fields deliberately
do not create standalone Home Assistant entities.

AP numeric sensors only return native `int` or `float` values. This is deliberate
so Home Assistant statistics and display precision behave correctly.

AP status sensor attributes include CDP and LLDP neighbor data when available.

## AP LED Controls

AP LED controls exist in two forms:

- Per-AP button entities in `button.py`.
- Home Assistant services registered in `__init__.py`.

Services:

- `cisco_9800_wlc.set_ap_led_state`
- `cisco_9800_wlc.set_ap_led_flash`

The RESTCONF operations are:

```text
/restconf/operations/Cisco-IOS-XE-wireless-access-point-cfg-rpc:set-lrad-led-state
/restconf/operations/Cisco-IOS-XE-wireless-access-point-cfg-rpc:set-lrad-led-flash
```

Service calls can target by `ap_mac` or `ap_name`. If multiple WLC controllers
are configured, callers should provide `entry_id`; otherwise the service refuses
to guess.

LED flash duration is clamped by schema and coordinator validation to 0-3600
seconds.

## HTTP And RESTCONF Handling

All controller communication uses Home Assistant's shared aiohttp client session.

Important behavior:

- HTTP Basic Auth is used for RESTCONF.
- `ignore_ssl` controls TLS certificate verification.
- `api_semaphore` limits concurrent API requests to 5.
- Main client list timeout is short, currently 5 seconds.
- Status timeout is shorter, currently 3 seconds.
- AP metadata and LED operations use longer timeouts.
- HTTP 401 raises `ConfigEntryAuthFailed`, which triggers Home Assistant
  reauthentication behavior.
- HTTP 409 is treated as controller overload and generally skips or retries
  rather than hammering the controller.

The code has defensive JSON decoding helpers because Cisco responses can contain
bad encodings or unexpected payloads. `_get()` is the preferred helper for new
GET endpoints because it handles safe decoding and auth failures consistently.

## IPv6 And URL Helpers

`utils.py` contains URL helpers that should be used for any controller or AP
HTTPS URL:

- `format_host_for_url()`
- `build_https_url()`

These helpers add IPv6 brackets and encode IPv6 zone identifiers. Do not build
controller URLs with raw string interpolation unless the value is already a full
RESTCONF path attached to `self.api_url` or `self.operations_url`.

## Diagnostics And System Health

`diagnostics.py` returns a redacted snapshot containing:

- Controller host and polling settings.
- Entry data and options.
- WLC status.
- Client count.
- Client attributes.

The diagnostics redaction list includes stored credentials and usernames.

`system_health.py` reports:

- Number of loaded config entries.
- Host.
- Polling disabled flag.
- Last update success.
- Last successful update time.
- Number of queued enrichments.

## Local Fixture Testing

The fixture tools are under:

```text
custom_components/cisco_9800_wlc/tests/fixtures/cisco_9800_wlc/
```

`capture_fixtures.sh` captures real WLC payloads into a local directory. JSON
files are ignored by git because they can contain MAC addresses, IP addresses,
AP names, hostnames, usernames, locations, and neighbor information.

Tests that need local JSON captures skip automatically when the files are absent.
Before any fixture is shared or committed, sanitize it.

## Important Design Constraints

- Keep client tracker unique IDs controller-scoped. MAC-only unique IDs collide
  when multiple WLCs see the same device.

- Keep registry lookups scoped by `config_entry_id`. Without this, multiple WLC
  entries can see and mutate each other's entities.

- Keep AP records keyed by canonical AP MAC. Cisco payloads expose Ethernet MACs,
  WTP MACs, AP names, and sometimes IP-like fields; alias resolution prevents AP
  data from splitting across multiple Home Assistant devices.

- Do not let empty Cisco values overwrite useful cached values. Use
  `_is_meaningful()` and `_merge_client_attributes()` patterns.

- Be careful with polling frequency. Client list polling, detailed client
  enrichment, AP metadata polling, and environmental polling all hit the same
  controller. Cisco WLCs may return HTTP 409 when overloaded.

- Keep AP metadata polling slower than client polling unless there is a strong
  reason. AP metadata payloads are larger and more expensive.

- Do not use LED fixture captures for tests. LED RESTCONF operations change AP
  state.

- Do not commit real fixture JSON payloads.

- If adding new RESTCONF calls, prefer `_get()` for GET requests and
  `_post_operation()` for operations so decoding, auth, timeout, and error
  behavior stays consistent.

- Home Assistant entity naming and unique IDs are user-visible and migration
  sensitive. Any change here can create duplicate entities or break existing
  automations.

## Common Change Areas

When adding or changing client telemetry:

1. Add the endpoint or parsing logic in `coordinator.py`.
2. Merge only meaningful values.
3. Add user-facing attributes in `device_tracker.py` if needed.
4. Add or update tests in `test_coordinator.py` and `test_device_tracker.py`.

When adding AP metrics:

1. Parse and normalize values in `_async_fetch_ap_metadata()` or
   `_async_fetch_ap_environment()`.
2. Store numeric values as `int` or `float`, not strings.
3. Add a sensor description in `sensor.py`.
4. Ensure the entity groups under `(DOMAIN, f"ap-{ap_mac}")`.
5. Add tests in `test_sensor.py` and fixture-backed coordinator tests if useful.

When adding options:

1. Define constants in `const.py` if reused.
2. Add fields to `CiscoWLCOptionsFlow`.
3. Read the option in `CiscoWLCUpdateCoordinator`.
4. Add translations in `strings.json` and `translations/*.json`.
5. Add tests for default values, validation, and reload behavior.

When adding services:

1. Add constants in `const.py`.
2. Add schema and handler in `__init__.py`.
3. Add user-facing docs in `services.yaml`.
4. Implement coordinator operation logic with `_post_operation()`.
5. Handle multiple controllers by accepting `entry_id` where needed.

## Known Operational Notes

- The WLC idle timeout means a client may appear connected for a short time after
  it has actually left the network.

- Some client detail endpoints may return 404 or partial data depending on
  whether the client is wired, wireless, sleeping, roaming, or recently gone.

- Software version polling is intentionally not used as the only online/offline
  signal.

- The README currently says "Disable newly discovered devices by default", but
  the code option is named `enable_new_entities`. Check wording carefully when
  changing the options UI.

- `gh` is not required by the integration itself. It only matters for release
  automation from a developer workstation.
