# Cisco 9800 WLC Device Tracker

![Cisco 9800 WLC](icons/logo.png)

## 📌 Overview

The **Cisco 9800 WLC Device Tracker** is a **Home Assistant** custom integration that tracks devices connected to a **Cisco 9800 Wireless LAN Controller (WLC)**. This integration retrieves connection details using the **RESTCONF API** and updates Home Assistant entities.

## ✨ Features

✔️ **Track connected devices** on your Cisco 9800 WLC.  
✔️ **UI-based setup** – No YAML needed.  
✔️ **Local polling** – No cloud dependencies.  
✔️ **SSL Support** – Ignore self-signed SSL certificates if needed.  
✔️ **Options for auto-disabling new devices**.  

## 🚀 Installation Guide

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
   - 🏠 **WLC IP Address**
   - 👤 **Username**
   - 🔑 **Password**
   - 🔒 **SSL Verification** (Optional)
4. Click **Submit**.

### ⚙️ Available Options
- **Disable newly discovered devices**: Prevents new entities from being added automatically.

## 🔍 Troubleshooting

| Issue | Solution |
|-------|----------|
| ❌ Unable to connect | Ensure RESTCONF is enabled and credentials are correct. |
| ❌ Invalid authentication | Verify username and password. |
| ⚠️ SSL verification failed | Enable "Ignore Self-Signed SSL" during setup. |
| ❓ Unknown error | Check Home Assistant logs for details. |

## 📜 License

This project is licensed under the **MIT License**.

---

### 🎯 **Want a Better Webpage? Use GitHub Pages**
If you want to **turn this into a GitHub Pages site**, create a **`docs/`** folder in your repository and move the `README.md` file inside it. Then:
- Enable **GitHub Pages** in the repository settings.
- Select the `docs/` folder as the source.
- GitHub will generate a webpage at:  
  `https://yourusername.github.io/yourrepository/`

