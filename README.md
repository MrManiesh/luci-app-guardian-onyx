<div align="center">

# 🛡️ Guardian Onyx (`luci-app-guardian-onyx`)

### Unified Security, AdGuard Home DNS & Firewall Dashboard for OpenWrt

[![Release](https://img.shields.io/github/v/release/MrManiesh/luci-app-guardian-onyx?color=6366f1&style=flat-square)](https://github.com/MrManiesh/luci-app-guardian-onyx/releases)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05%20|%2024.10%2B-0099e5?style=flat-square&logo=openwrt&logoColor=white)](https://openwrt.org)
[![ImmortalWrt](https://img.shields.io/badge/ImmortalWrt-23.05%20|%2025.12%2B-10b981?style=flat-square)](https://immortalwrt.org)
[![Package Format](https://img.shields.io/badge/package-APK%20%7C%20IPK-blueviolet?style=flat-square)](#-installation)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Architecture](https://img.shields.io/badge/arch-all-orange?style=flat-square)](#)

A fast, responsive, and theme-adaptive LuCI dashboard for OpenWrt and ImmortalWrt that seamlessly unifies **AdGuard Home DNS filtering**, **Linux kernel firewall (`fw4`/`nftables`)**, and **connected client security & bandwidth telemetry** under a single elegant interface.

[Highlights](#-highlights) • [Tabs & Features](#️-control-center-tabs) • [Installation](#-installation) • [CLI Commands](#️-backend-cli-reference) • [Configuration](#️-configuration-reference)

</div>

---

## 🌟 Highlights

* **📱 Per-Device App & Service Blocker**: Restrict YouTube, TikTok, Roblox, Steam, Instagram, and 130+ platforms on specific devices with 1 click without affecting the rest of your household.
* **⚡ Live Domain Whitelist / Blacklist Manager**: Add game bypasses (like BGMI / PUBG), banking exceptions, or ad-block rules directly from LuCI without navigating AdGuard menus.
* **⏸️ 1-Click Internet Pause / Resume**: Temporarily freeze external internet for any phone, PC, or smart TV via hardware-level `nftables` rules.
* **📊 Comprehensive Client Telemetry**: Live Wi-Fi PHY bitrates (e.g. `⚡ 1.2 Gbps`), 5GHz/2.4GHz bands, RSSI signal strength (dBm), conntrack sessions, and total download/upload traffic.
* **📌 1-Click Static DHCP Leases**: Lock dynamic clients to permanent static reservations directly from the table.
* **🌓 Zero-Config Theme Blending**: Automatically adapts to dark and light LuCI themes (Argon, Bootstrap, Material, Aurora) with zero external CDNs and 100% offline air-gap reliability.

---

## 🗂️ Control Center Tabs

### 1. Connected Clients & Security Access (Default Landing)

| Feature | Description |
|---|---|
| **KPI Metric Cards** | Instant summary of discovered devices, 5GHz vs 2.4GHz Wi-Fi breakdown, wired Ethernet count, total download/upload bytes, and active session counts. |
| **App & Service Blocker** | Restrict specific platforms (**YouTube, TikTok, Netflix, Roblox, Discord, Steam, Tinder, etc.**) per client using native AdGuard Home client enforcement. |
| **Internet Access Control** | 1-click **Pause** drops outbound WAN traffic for that client via `fw4` / `nftables`; **Resume** restores access immediately. |
| **Friendly Nicknames** | Set custom aliases (e.g. *"Living Room TV"*, *"Work Laptop"*) stored permanently in `/etc/config/guardian`. |
| **Static IP Reservations** | 1-click **+ Reserve IP** turns dynamic leases into permanent static DHCP reservations; active static leases show a dedicated `📌 Static` badge with 1-click release. |
| **Link Quality & Speed** | Live Wi-Fi PHY rates (`⚡ 866 Mbps`), association uptime (`⏱️ 4h 12m`), signal strength pills, and active conntrack session counters. |
| **Direct DNS Threat Audit** | **DNS Logs ↗** button jumps straight into AdGuard Home's live query log pre-filtered for that specific client. |

---

### 2. AdGuard Home Core Engine

| Feature | Description |
|---|---|
| **Instance Health Banner** | Displays live host, port, upstream latency, engine version, and active status (`Connected & Active` vs `Protection Paused`). |
| **1-Click Protection Toggle** | Instantly pause or resume AdGuard Home DNS protection without stopping background services. |
| **Quick Rules Manager** | Built-in **Custom Filtering Rules** table to add **Whitelists (`@@||domain^`)** or **Blacklists (`||domain^`)** with 1-click deletion. |
| **24h Analytics KPIs** | Total DNS requests, blocked ads/trackers, SafeBrowsing malware stops, and parental protection counts. |
| **Live Query Inspector Link** | Direct link into AdGuard's real-time query log inspector. |
| **Web UI Shortcut** | 1-click button to launch the full AdGuard Home Web UI in a new browser tab. |

---

### 3. OpenWrt Firewall Engine

| Feature | Description |
|---|---|
| **Engine Status & Telemetry** | Displays active backend (`nftables` / `fw4`) and live conntrack session count. |
| **Firewall Security Zones** | Comprehensive breakdown of `lan`, `wan`, and custom zones with color-coded policy badges (`ACCEPT`, `DROP`, `REJECT`). |
| **Port Forwarding (DNAT)** | Full inspector for active WAN-to-LAN port redirects. |
| **1-Click Firewall Reload** | Safely flush and reload the firewall ruleset with instant UI feedback. |

---

### 4. Settings & Auto-Discovery

| Feature | Description |
|---|---|
| **Custom Endpoint** | Configurable AdGuard Host IP and Web UI Port (e.g. `127.0.0.1:8080`, `3000`). |
| **"Retrieve from File"** | 1-click discovery that automatically recovers stored credentials from `/etc/guardian_credentials.json` or `adguardhome.yaml`. |
| **Live Connection Test** | Live test button to verify API connectivity and response times before saving. |
| **Secure UCI Storage** | Settings are safely saved to `/etc/config/guardian` with restricted file permissions (`chmod 0600`). |

---

## 📦 Installation

### Prerequisites
Guardian Onyx runs on lightweight standard utilities:
```sh
opkg update && opkg install curl ca-bundle jq
```

---

### Option A: Install via APK (OpenWrt 24.10+ / ImmortalWrt 25.x)
Download and install the latest APK from [GitHub Releases](https://github.com/MrManiesh/luci-app-guardian-onyx/releases):

```sh
# Download and install the latest release
wget -O /tmp/luci-app-guardian-onyx-1.3.1.apk https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.3.1/luci-app-guardian-onyx-1.3.1.apk
apk add --allow-untrusted /tmp/luci-app-guardian-onyx-1.3.1.apk
```

---

### Option B: Install via IPK (OpenWrt 23.05 & opkg systems)
```sh
# Download and install the IPK package
opkg install /tmp/luci-app-guardian-onyx_1.3.1_all.ipk
```

---

### Option C: Manual Installation via SCP / SSH
If deploying directly to a running router from source:
```sh
# Copy files to router
scp -r root/* root@192.168.1.1:/
scp -r htdocs/* root@192.168.1.1/www/

# Set execution permissions & refresh LuCI cache
ssh root@192.168.1.1 "chmod +x /usr/libexec/guardian-action.sh /etc/init.d/guardian && \
  /etc/init.d/rpcd restart && \
  rm -rf /tmp/luci-indexcache /tmp/luci-modulecache"
```

---

## 🛠️ Backend CLI Reference

The helper controller `/usr/libexec/guardian-action.sh` can be executed directly from the terminal or scripts:

```sh
/usr/libexec/guardian-action.sh <action> [arguments]
```

| Action | Arguments | Description |
|---|---|---|
| `status` | — | Returns full system JSON (AdGuard status, firewall state, client counts) |
| `clients` | — | Scans ARP, wireless associations, conntrack, and AdGuard blocked services |
| `client_block` | `<mac> [ip]` | Drops outbound WAN access for specified device via `fw4` |
| `client_unblock` | `<mac>` | Restores outbound WAN access for specified device |
| `set_nickname` | `<mac> <name>` | Sets or clears custom friendly alias in `/etc/config/guardian` |
| `reserve_ip` | `<mac> <ip> [host]` | Converts dynamic client into permanent static DHCP lease |
| `unreserve_ip` | `<mac>` | Removes static DHCP reservation |
| `adguard_rules` | — | Returns all custom user filtering rules as JSON |
| `adguard_add_rule` | `<domain\|rule> [whitelist\|blacklist]` | Adds and enforces custom filter rule in AdGuard Home |
| `adguard_delete_rule`| `<rule>` | Removes specified rule from AdGuard Home |
| `adguard_services_list`| — | Returns catalog of all 136 supported blockable platforms |
| `adguard_client_services`| `<ip> <mac>` | Returns current blocked services configured for this client |
| `adguard_set_client_services`| `<ip> <mac> <name> <json_array>` | Sets or clears blocked services for this client (e.g. `'["youtube","roblox"]'`) |
| `adguard_stats` | — | Returns raw statistics from AdGuard `/control/stats` |
| `adguard_toggle` | — | Toggles AdGuard protection on or off |
| `firewall_rules` | — | Returns active `nftables` ruleset in JSON format |
| `firewall_zones` | — | Returns UCI firewall zones with default input/forward policies |
| `firewall_reload`| — | Safely reloads firewall ruleset (`fw4 reload` / `fw3 reload`) |

---

## ⚙️ Configuration Reference

Configuration is managed in `/etc/config/guardian`:

```ini
config guardian 'main'
    option enabled '1'
    option adguard_enabled '1'
    option adguard_host '127.0.0.1'
    option adguard_port '8080'
    option adguard_user 'Onyx'
    option adguard_password 'yourpassword'
    option threat_scan_interval '60'
    option log_level 'info'

config alias
    option mac '98:87:4c:ee:8c:6f'
    option name 'OnePlus 12R'
```

### Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `1` | Master toggle for Guardian service |
| `adguard_enabled` | boolean | `1` | Enables AdGuard Home API integration |
| `adguard_host` | string | `127.0.0.1` | AdGuard Home API host IP or hostname |
| `adguard_port` | integer | `8080` | AdGuard Home Web UI / API port |
| `adguard_user` | string | `""` | AdGuard Home authentication username |
| `adguard_password` | string | `""` | AdGuard Home authentication password |
| `threat_scan_interval`| integer | `60` | Background scan interval in seconds |

---

## 📁 Repository Structure

```text
luci-app-guardian-onyx/
├── Makefile                                       # Universal package Makefile (APK & IPK)
├── README.md                                      # Project documentation
├── RELEASE_NOTES.md                               # Version changelog
├── LICENSE                                        # Apache 2.0 license
├── htdocs/
│   └── luci-static/
│       └── resources/
│           └── view/
│               └── guardian/
│                   └── index.js                   # LuCI Single-Page Application View
└── root/
    ├── etc/
    │   ├── config/
    │   │   └── guardian                           # UCI configuration defaults
    │   └── init.d/
    │       └── guardian                           # Procd background daemon service
    └── usr/
        ├── libexec/
        │   └── guardian-action.sh                 # Backend controller script
        └── share/
            ├── luci/
            │   └── menu.d/
            │       └── luci-app-guardian-onyx.json# LuCI navigation menu entry
            └── rpcd/
                └── acl.d/
                    └── luci-app-guardian-onyx.json# rpcd ACL security permissions
```

---

## 📄 License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

Developed with ❤️ for the **OpenWrt** & **ImmortalWrt** community.
