Cisco 9800 WLC local fixture captures
=====================================

The JSON files in this directory are intentionally ignored by git. They are
local-only captures from a real Cisco 9800 WLC and may contain MAC addresses,
IP addresses, AP names, locations, CDP/LLDP neighbor data, and hostnames.

Create the files from a machine that can reach the WLC:

  mkdir -p /tmp/cisco_9800_wlc_fixtures

  export WLC_HOST="your-wlc-host-or-ip"
  export WLC_USER="your-user"
  export CLIENT_MAC="aa:bb:cc:dd:ee:ff"  # optional, for detailed client fixtures

  bash tests/fixtures/cisco_9800_wlc/capture_fixtures.sh

The script captures every GET payload the coordinator currently pulls:

  client_list.json
    /restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac

  software_version.json
    /restconf/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-system-data/software-version

  ap_join_stats.json
    /restconf/data/Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data/ap-join-stats

  access_point_oper_data.json
    /restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data

  ap_temperature.json
    /restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-temp

  ap_air_quality.json
    /restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-air-quality

If CLIENT_MAC is set, the script also captures the optional per-client
enrichment payloads used for detailed telemetry:

  client_common_oper_data.json
    /restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data={CLIENT_MAC}

  client_dot11_oper_data.json
    /restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data={CLIENT_MAC}

  client_dc_info.json
    /restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info={CLIENT_MAC}

  client_speed.json
    /restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats={CLIENT_MAC}/speed

  client_roaming_history.json
    /restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/mm-if-client-history={CLIENT_MAC}/mobility-history

The coordinator also has LED control service calls that use RESTCONF operations:

  /restconf/operations/Cisco-IOS-XE-wireless-access-point-cfg-rpc:set-lrad-led-state
  /restconf/operations/Cisco-IOS-XE-wireless-access-point-cfg-rpc:set-lrad-led-flash

Those are intentionally not captured by the fixture script because they change
WLC/AP state.

Manual curl equivalents:

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac" \
    -o /tmp/cisco_9800_wlc_fixtures/client_list.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-system-data/software-version" \
    -o /tmp/cisco_9800_wlc_fixtures/software_version.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data/ap-join-stats" \
    -o /tmp/cisco_9800_wlc_fixtures/ap_join_stats.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data" \
    -o /tmp/cisco_9800_wlc_fixtures/access_point_oper_data.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-temp" \
    -o /tmp/cisco_9800_wlc_fixtures/ap_temperature.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-air-quality" \
    -o /tmp/cisco_9800_wlc_fixtures/ap_air_quality.json

For detailed client fixtures, URL-encode the client MAC first:

  CLIENT_MAC_ENCODED="$(CLIENT_MAC="$CLIENT_MAC" python3 -c 'from urllib.parse import quote; import os; print(quote(os.environ["CLIENT_MAC"], safe=""))')"

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data=${CLIENT_MAC_ENCODED}" \
    -o /tmp/cisco_9800_wlc_fixtures/client_common_oper_data.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data=${CLIENT_MAC_ENCODED}" \
    -o /tmp/cisco_9800_wlc_fixtures/client_dot11_oper_data.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info=${CLIENT_MAC_ENCODED}" \
    -o /tmp/cisco_9800_wlc_fixtures/client_dc_info.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats=${CLIENT_MAC_ENCODED}/speed" \
    -o /tmp/cisco_9800_wlc_fixtures/client_speed.json

  curl -k -u "$WLC_USER" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/mm-if-client-history=${CLIENT_MAC_ENCODED}/mobility-history" \
    -o /tmp/cisco_9800_wlc_fixtures/client_roaming_history.json

Copy the files into this directory when you want to run the local fixture tests:

  cp /tmp/cisco_9800_wlc_fixtures/*.json \
    tests/fixtures/cisco_9800_wlc/

Before sharing any fixture, sanitize it:

  - MAC addresses -> aa:bb:cc:dd:ee:ff or another dummy value
  - IP addresses -> 192.0.2.x documentation addresses
  - AP names -> Lab AP
  - Locations -> Lab
  - Hostnames, CDP/LLDP neighbor names, usernames -> generic test values

The tests that use these files skip automatically when the JSON captures are
not present.
