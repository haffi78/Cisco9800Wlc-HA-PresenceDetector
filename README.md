# Cisco 9800 WLC Device Tracker

[![Cisco 9800 WLC]([icons/logo.png](https://github.com/haffi78/Cisco9800Wlc-HA-PresenceDetector/blob/main/custom_components/cisco_9800_wlc/icons/icon.png))](https://github.com/haffi78/Cisco9800Wlc-HA-PresenceDetector/blob/main/custom_components/cisco_9800_wlc/icons/icon.png)

##  Overview

The **Cisco 9800 WLC Device Tracker** is a **Home Assistant** custom integration that tracks devices connected to a **Cisco 9800 Wireless LAN Controller (WLC)**. This integration retrieves connection details using the **RESTCONF API** and updates Home Assistant entities.

##  Features

✔️ **Track connected devices** on your Cisco 9800 WLC.  
✔️ **UI-based setup** – No YAML needed.  
✔️ **Local polling** – No cloud dependencies.  
✔️ **SSL Support** – Ignore self-signed SSL certificates if needed.  
✔️ **Options for auto-disabling new devices**.  
✔️ **Wifi clients start disabled to avoid over pulling
✔️ System pulls wifi connected clients, get mac and ip address, then looks up enabled devices from home and pulls extra attributes.


##  Installation Guide

### **Manual Installation**
1. Download the latest release from [GitHub](https://github.com/haffi78/Cisco9800Wlc-HA-PresenceDetector).
2. Copy the `cisco_9800_wlc` folder to your **Home Assistant custom_components directory**:
   ```sh
   /config/custom_components/cisco_9800_wlc
   ```
3. Restart Home Assistant.

### **Installation via HACS (Recommended)**
1. Open **HACS** in Home Assistant.
2. Go to **Integrations** → **+ Explore & Add Repositories**.
3. Add this repository (`https://github.com/haffi78/Cisco9800Wlc-HA-PresenceDetector`) as an **Integration**.
4. Install and restart Home Assistant.

## 🛠️ Configuration Steps

1. Go to **Settings** → **Devices & Services** → **Add Integration**.
2. Search for **Cisco 9800 WLC** and select it.
3. Enter the required details:
   -  **WLC IP Address**
   -  **Username**
   -  **Password**
   -  **SSL Verification** (Optional)
4. Click **Submit**.
5. Go Under - Settings - Device & services - Cisco 9800 WLC - three dots on your WLC , you should have 1 Device, and X many entities, you need to click on the Entities and enable the ones you want to follow.

### ⚙️ Available Options
- **Disable newly discovered devices**: Prevents new entities from being added automatically.

## 🔍 Troubleshooting

| Issue | Solution |
|-------|----------|


##  License

This project is licensed under the **MIT License**.

---

