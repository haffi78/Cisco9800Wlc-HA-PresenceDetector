Cisco 9800 WLC Home Assistant Integration

Overview

This is a custom Home Assistant integration to track devices connected to a Cisco 9800 Wireless LAN Controller (WLC) using RESTCONF API. It retrieves client operational data and updates Home Assistant's device_tracker component.

Features

Tracks clients connected to the Cisco 9800 WLC.

Uses RESTCONF API for data retrieval.

Supports secure authentication with username and password.

Configurable scan interval for periodic updates.

SSL verification can be enabled or disabled.

Installation

1. Create the Custom Component Directory

Navigate to your Home Assistant configuration directory and create a new folder for the custom component:

/config/custom_components/cisco_9800_wlc/

Copy the Python script (device_tracker.py) into this folder.

2. Configure configuration.yaml

Add the following section to your configuration.yaml file to enable the integration:

device_tracker:
  - platform: cisco_9800_wlc
    host: 192.168.10.6
    username: admin
    password: XXXXXXX
    verify_ssl: false
    new_device_defaults:
      track_new_devices: false

3. Restart Home Assistant

After making these changes, restart Home Assistant to apply the configuration.

ha core restart

Configuration Options

Key

Required

Description

host

Yes

IP or hostname of the Cisco 9800 WLC.

username

Yes

Username for RESTCONF API authentication.

password

Yes

Password for RESTCONF API authentication.

verify_ssl

No

Set to false if using a self-signed certificate (default: false).

scan_interval

No

Interval (in seconds) between API calls (default: 30).

new_device_defaults.track_new_devices

No

Determines whether new devices should be tracked by default (default: false).

How It Works

The integration connects to the Cisco 9800 WLC using the RESTCONF API.

It retrieves client operational data, including MAC addresses and connection status.

This information is updated periodically in Home Assistant, based on the configured scan_interval.

Troubleshooting

Home Assistant fails to start: Ensure the custom_components/cisco_9800_wlc folder exists and contains device_tracker.py.

No devices detected: Double-check the WLC IP, username, password, and ensure RESTCONF is enabled on your controller.

SSL certificate errors: If using a self-signed certificate, set verify_ssl: false in configuration.yaml.

dont forget to config wlc 9800 to enable restconf and the approrate access list if needed.

Future Enhancements

Add support for more detailed client information.

Implement additional configuration options for filtering devices.

Enhance logging and debugging capabilities.

License

This project is open-source and available under the MIT License.

Contributions

Pull requests and feature suggestions are welcome! Please submit issues or enhancements via GitHub.

Author

Hafþór Hilmarsson O'Connor
