#!/usr/bin/env python3
"""Check what a Cisco 9800 WLC returns for one client MAC."""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import ssl
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


DEFAULT_ENDPOINTS = (
    "main_client_list",
    "dc_info",
    "common",
    "dot11",
    "speed",
    "roaming_history",
)

CLIENT_ENDPOINTS = {
    "client_oper_data": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data"
    ),
    "main_client_list": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac"
    ),
    "all_dc_info": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info"
    ),
    "dc_info": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/dc-info={mac}"
    ),
    "all_common": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data"
    ),
    "common": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/"
        "common-oper-data={mac}"
    ),
    "all_dot11": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data"
    ),
    "dot11": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/"
        "dot11-oper-data={mac}"
    ),
    "speed": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/"
        "traffic-stats={mac}/speed"
    ),
    "roaming_history": (
        "Cisco-IOS-XE-wireless-client-oper:client-oper-data/"
        "mm-if-client-history={mac}/mobility-history"
    ),
}

SUMMARY_FIELDS = (
    "client-mac",
    "mac-addr",
    "ap-name",
    "device-name",
    "device-type",
    "device-os",
    "device-vendor",
    "day-zero-dc",
    "protocol-map",
    "confidence-level",
    "classified-time",
    "username",
    "vap-ssid",
    "current-channel",
)


def normalize_mac(value: str) -> str:
    """Normalize colon, dotted, dashed, or plain MAC input to colon form."""

    raw = value.strip().lower()
    hex_chars = re.sub(r"[^0-9a-f]", "", raw)
    if len(hex_chars) != 12:
        raise ValueError(f"Expected 12 MAC hex characters, got {value!r}")
    return ":".join(hex_chars[index : index + 2] for index in range(0, 12, 2))


def restconf_base_url(host: str) -> str:
    """Return the RESTCONF data base URL for a host or URL."""

    host = host.strip().rstrip("/")
    if not host:
        raise ValueError("WLC host is required")
    if host.startswith(("http://", "https://")):
        return f"{host}/restconf/data"
    return f"https://{host}/restconf/data"


def request_json(
    url: str,
    *,
    username: str,
    password: str,
    verify_tls: bool,
    timeout: float,
) -> tuple[int | None, str | None, Any]:
    """Fetch JSON from a RESTCONF URL."""

    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = Request(
        url,
        headers={
            "Accept": "application/yang-data+json",
            "Authorization": f"Basic {token}",
        },
    )
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, response.headers.get("content-type"), parse_json(body)
    except HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        return err.code, err.headers.get("content-type"), parse_json(body)
    except URLError as err:
        return None, None, {"error": str(err.reason)}


def parse_json(body: str) -> Any:
    """Parse JSON, preserving raw text if the response is not JSON."""

    if not body.strip():
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"raw": body}


def first_payload_item(data: Any) -> Any:
    """Return the first useful RESTCONF payload item for summary output."""

    if not isinstance(data, dict) or not data:
        return data
    payload = next(iter(data.values()))
    if isinstance(payload, list):
        return payload[0] if payload else None
    return payload


def find_mac_records(data: Any, mac: str) -> list[dict[str, Any]]:
    """Find dicts anywhere in a payload that mention the target MAC."""

    matches: list[dict[str, Any]] = []
    normalized = normalize_mac(mac)
    plain = normalized.replace(":", "")

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if any(normalize_if_mac(str(child)) == plain for child in value.values()):
                matches.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(data)
    return matches


def find_text_records(data: Any, terms: list[str]) -> list[dict[str, Any]]:
    """Find dicts anywhere in a payload that contain all search terms."""

    lowered_terms = [term.lower() for term in terms if term]
    matches: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            text = json.dumps(value, sort_keys=True, default=str).lower()
            if all(term in text for term in lowered_terms):
                matches.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    if lowered_terms:
        visit(data)
    return matches


def normalize_if_mac(value: str) -> str:
    """Return normalized MAC hex if a string looks like a MAC."""

    candidate = re.sub(r"[^0-9a-fA-F]", "", value)
    return candidate.lower() if len(candidate) == 12 else ""


def summary_lines(data: Any, *, mac: str, endpoint: str) -> list[str]:
    """Build a compact human-readable summary for one endpoint."""

    item = first_payload_item(data)
    if endpoint == "main_client_list" or endpoint.startswith("all_"):
        records = find_mac_records(data, mac)
        if not records:
            return [f"target MAC not found in {endpoint}"]
        item = records[0]

    if not isinstance(item, dict):
        return []

    lines = []
    for field in SUMMARY_FIELDS:
        if field in item:
            lines.append(f"{field}: {item[field]!r}")
    return lines


def print_endpoint(
    name: str,
    path: str,
    *,
    base_url: str,
    mac: str,
    username: str,
    password: str,
    verify_tls: bool,
    timeout: float,
    raw: bool,
    search: list[str],
) -> None:
    """Query and print one endpoint."""

    encoded_mac = quote(mac, safe="")
    url = f"{base_url}/{path.format(mac=encoded_mac)}"
    status, content_type, data = request_json(
        url,
        username=username,
        password=password,
        verify_tls=verify_tls,
        timeout=timeout,
    )

    print(f"\n== {name} ==")
    print(f"GET {url}")
    print(f"HTTP_STATUS={status}")
    if content_type:
        print(f"CONTENT_TYPE={content_type}")

    lines = summary_lines(data, mac=mac, endpoint=name)
    if lines:
        print("-- summary --")
        for line in lines:
            print(line)

    search_terms = list(search)
    if search_terms:
        matches = find_text_records(data, search_terms)
        print(f"-- search matches for {search_terms!r}: {len(matches)} --")
        for index, match in enumerate(matches[:10], start=1):
            print(f"[{index}]")
            match_lines = []
            if isinstance(match, dict):
                for field in SUMMARY_FIELDS:
                    if field in match:
                        match_lines.append(f"{field}: {match[field]!r}")
            if match_lines:
                for line in match_lines:
                    print(line)
            else:
                print(json.dumps(match, indent=2, sort_keys=True))
        if len(matches) > 10:
            print(f"... {len(matches) - 10} more match(es) omitted")

    if raw:
        print("-- raw json --")
        print(json.dumps(data, indent=2, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query Cisco 9800 WLC RESTCONF data for one client MAC."
    )
    parser.add_argument("mac", help="Client MAC, e.g. 80:b9:89:7b:62:2d")
    parser.add_argument("--host", default=os.getenv("WLC_HOST"), help="WLC host or URL")
    parser.add_argument("--user", default=os.getenv("WLC_USER"), help="WLC username")
    parser.add_argument(
        "--password",
        default=os.getenv("WLC_PASS"),
        help="WLC password. If omitted, prompt securely.",
    )
    parser.add_argument(
        "--endpoint",
        choices=sorted(CLIENT_ENDPOINTS),
        action="append",
        help="Endpoint to query. Can be repeated. Defaults to all endpoints.",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print full JSON responses after the summary.",
    )
    parser.add_argument(
        "--search",
        action="append",
        default=[],
        help=(
            "Search each response for text, e.g. --search blackey. "
            "Can be repeated; all terms must match in a record."
        ),
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify the WLC TLS certificate. Default skips verification.",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        mac = normalize_mac(args.mac)
        base_url = restconf_base_url(args.host or "")
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    username = args.user or input("WLC username: ").strip()
    password = args.password or getpass.getpass("WLC password: ")
    if not username or not password:
        print("error: WLC username and password are required", file=sys.stderr)
        return 2

    endpoints = args.endpoint or list(DEFAULT_ENDPOINTS)
    print(f"Target MAC: {mac}")
    for endpoint in endpoints:
        print_endpoint(
            endpoint,
            CLIENT_ENDPOINTS[endpoint],
            base_url=base_url,
            mac=mac,
            username=username,
            password=password,
            verify_tls=args.verify_tls,
            timeout=args.timeout,
            raw=args.raw,
            search=args.search,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
