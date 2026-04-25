#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-/tmp/cisco_9800_wlc_fixtures}"
WLC_HOST="${WLC_HOST:-}"
WLC_USER="${WLC_USER:-}"
WLC_PASS="${WLC_PASS:-}"
CLIENT_MAC="${CLIENT_MAC:-}"

if [[ -z "$WLC_HOST" || -z "$WLC_USER" ]]; then
  echo "Set WLC_HOST and WLC_USER before running this script." >&2
  echo "Optional: set WLC_PASS and CLIENT_MAC." >&2
  exit 1
fi

if [[ -z "$WLC_PASS" ]]; then
  read -rsp "WLC password: " WLC_PASS
  echo
fi

mkdir -p "$OUT_DIR"

capture() {
  local path="$1"
  local output="$2"

  echo "Capturing $output"
  curl -k -sS -u "${WLC_USER}:${WLC_PASS}" \
    -H "Accept: application/yang-data+json" \
    "https://${WLC_HOST}/restconf/data/${path}" \
    -o "${OUT_DIR}/${output}"
}

capture "Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac" \
  "client_list.json"
capture "Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-system-data/software-version" \
  "software_version.json"
capture "Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data/ap-join-stats" \
  "ap_join_stats.json"
capture "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data" \
  "access_point_oper_data.json"
capture "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-temp" \
  "ap_temperature.json"
capture "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-air-quality" \
  "ap_air_quality.json"

if [[ -n "$CLIENT_MAC" ]]; then
  ENCODED_CLIENT_MAC="$(CLIENT_MAC="$CLIENT_MAC" python3 - <<'PY'
import os
from urllib.parse import quote

print(quote(os.environ["CLIENT_MAC"], safe=""))
PY
)"

  capture "Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data=${ENCODED_CLIENT_MAC}" \
    "client_common_oper_data.json"
  capture "Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data=${ENCODED_CLIENT_MAC}" \
    "client_dot11_oper_data.json"
  capture "Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info=${ENCODED_CLIENT_MAC}" \
    "client_dc_info.json"
  capture "Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats=${ENCODED_CLIENT_MAC}/speed" \
    "client_speed.json"
  capture "Cisco-IOS-XE-wireless-client-oper:client-oper-data/mm-if-client-history=${ENCODED_CLIENT_MAC}/mobility-history" \
    "client_roaming_history.json"
else
  echo "CLIENT_MAC was not set; skipped per-client detail fixtures."
fi

echo "Fixtures written to ${OUT_DIR}"
