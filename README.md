Cisco 9800 WLC Home Assistant Integration

Overview:
This is a custom Home Assistant integration to track devices connected to a Cisco 9800 Wireless LAN Controller (WLC) using RESTCONF API. It retrieves client operational data and updates Home Assistant's device_tracker component.

Features:
- Tracks clients connected to the Cisco 9800 WLC.
- Uses RESTCONF API for data retrieval.
- Supports secure authentication with username and password.
- Configurable scan interval for periodic updates.
- SSL verification can be enabled or disabled.

Installation:
1. Create the Custom Component Directory:
   - Navigate to Home Assistant config directory and create:
     /config/custom_components/cisco_9800_wlc/
   - Copy device_tracker.py into this folder.

2. Configure configuration.yaml:
   - Add the following section to configuration.yaml:
   
     device_tracker:
       - platform: cisco_9800_wlc
         host: 192.168.10.6
         username: admin
         password: XXXXXXX
         verify_ssl: false
         new_device_defaults:
           track_new_devices: false

3. Restart Home Assistant:
   - Restart Home Assistant with: ha core restart

Configuration Options:
- host (Required): IP or hostname of the Cisco 9800 WLC.
- username (Required): Username for RESTCONF API authentication.
- password (Required): Password for RESTCONF API authentication.
- verify_ssl (Optional): Set to false for self-signed certificates (default: false).
- scan_interval (Optional): Interval (in seconds) between API calls (default: 30).
- new_device_defaults.track_new_devices (Optional): Determines if new devices are tracked by default (default: false).

How It Works:
- Connects to the Cisco 9800 WLC using the RESTCONF API.
- Retrieves client operational data (MAC addresses, connection status).
- Updates Home Assistant periodically based on scan_interval.

Troubleshooting:
- Home Assistant fails to start: Ensure custom_components/cisco_9800_wlc folder and device_tracker.py are present.
- No devices detected: Verify WLC IP, username, password, and ensure RESTCONF is enabled.
- SSL certificate errors: Set verify_ssl: false in configuration.yaml for self-signed certificates.

Note: Don't forget to configure WLC 9800 to enable RESTCONF and adjust access list if needed.

Future Enhancements:
- Support for more detailed client info.
- Additional filtering configuration options.
- Enhanced logging and debugging.

License:
This project is open-source and available under the MIT License.

Contributions:
Pull requests and feature suggestions are welcome! Submit issues or enhancements via GitHub.

Author:
Hafþór Hilmarsson O'Connor
