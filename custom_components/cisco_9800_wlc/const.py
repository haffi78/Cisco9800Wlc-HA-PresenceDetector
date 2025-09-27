# Default values
DOMAIN = "cisco_9800_wlc"
DEFAULT_TRACK_NEW = False
CONF_IGNORE_SSL = "ignore_ssl"
SIGNAL_NEW_CLIENTS = f"{DOMAIN}_new_clients"
CONF_DETAILED_MACS = "detailed_macs"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_AP_DETAIL_INTERVAL = "ap_detail_interval"

DEFAULT_AP_DETAIL_INTERVAL = 3600

SERVICE_SET_LED_STATE = "set_ap_led_state"
SERVICE_SET_LED_FLASH = "set_ap_led_flash"

ATTR_AP_MAC = "ap_mac"
ATTR_AP_NAME = "ap_name"
ATTR_ENTRY_ID = "entry_id"
ATTR_ENABLED = "enabled"
ATTR_DURATION = "duration"
