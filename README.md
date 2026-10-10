<div align="center">

# luci-app-guardian-onyx

### Unified Security, AdGuard Home & Firewall Dashboard for OpenWrt

[![Version](https://img.shields.io/badge/version-1.0.1--r1-blue.svg)](https://github.com/MrManiesh/luci-app-guardian-onyx/releases)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05%20|%2024.10%2B%20(apk)-success.svg)](https://openwrt.org)
[![ImmortalWrt](https://img.shields.io/badge/ImmortalWrt-Compatible-success.svg)](https://immortalwrt.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Architectures](https://img.shields.io/badge/arch-all-orange.svg)](#supported-architectures)

A modern, responsive LuCI web dashboard for OpenWrt that unifies **AdGuard Home DNS filtering**, **Firewall policies & NAT rules**, and **connected client security monitoring** under a single cohesive, high-performance Onyx interface.

</div>

---

## Overview

**Guardian Onyx** (`luci-app-guardian-onyx`) bridges the gap between DNS-level threat blocking, kernel packet filtering, and local client discovery. Rather than switching between disparate configuration screens, network administrators get a single real-time operational security dashboard directly inside LuCI.

Built with the **Onyx Design System**, Guardian automatically adapts to any OpenWrt theme (Argon, Bootstrap, Material, Aurora, Proton2025) while operating completely offline with zero CDN dependencies.

---

## Features

### Automatic Theme-Adaptive Design
- **True Theme Blending**: Automatically measures background luminance and checks theme metadata (`data-theme`, CSS links) to seamlessly render in **Obsidian Dark** or **High-Contrast Crisp Light**.
- **Zero External CDNs**: Self-contained inline SVG vector icons and system typography ensure full functionality on air-gapped routers without internet access.
- **Glassmorphism & Elevation**: Smooth border glows, pill badges, pulsing status indicators, and hover micro-animations.

---

### 5-Tab Unified Control Center

#### 1. Dashboard (Overview)
- **Top Status KPI Cards**:
  - **AdGuard Home**: Real-time online/offline badge with pulsing indicator and today's blocked queries counter.
  - **Firewall Security**: Running engine status (`nftables` / `fw4` or `iptables` / `fw3`) and active zone filter count.
  - **Connected Clients**: ARP-monitored active device count.
  - **Threats Filtered**: Combined malware, phishing, and parental block counter.
- **1-Click Protection Toggle**: Instantly pause or resume AdGuard Home DNS protection with automatic state refresh.
- **24-Hour Telemetry Bar**: Visual block-percentage progress bar, total queries, filter rate, and average upstream query latency.
- **Live DNS Activity**: Compact preview table showing recent queries with domain, client IP, query type, and color-coded status badges (`BLOCKED` in red, `ALLOWED` in green).

#### 2. AdGuard Home Suite
- **Instance Banner**: Host, port, core version, connection state, and quick shortcut to open the full AdGuard Web UI in a new tab.
- **Deep Analytics Cards**: Total queries (24h), queries blocked by filters, safe browsing malicious hits, parental control stops, and processing latency.
- **Blocklist & Filter Rules**: Inspect all active blocklists, rule counts, enabled status, and last update times. Includes a **"Refresh Filters"** button.
- **Interactive Query Inspector**: Searchable table of recent DNS requests with real-time domain/client filtering and status dropdown (All / Blocked / Allowed).

#### 3. Firewall Management
- **Engine Status & Telemetry**: Shows active firewall backend (`nftables` / `fw4`) and real-time conntrack session count.
- **Firewall Security Zones**: Full breakdown of zones (`lan`, `wan`, `guest`) with color-coded policy badges (`ACCEPT` = green, `DROP` = red, `REJECT` = orange).
- **Port Redirection (DNAT)**: Clear list of active port forwarding rules showing rule name, protocol, external source, internal destination, and status.
- **1-Click Reload**: Dedicated **"Reload Firewall"** button triggers safe firewall ruleset reloading with instant feedback.

#### 4. Connected Clients & Security Audit
- **Discovery Summary**: Total ARP clients, verified DHCP leases, unregistered devices, and suspicious hardware flags.
- **Client Security Table**:
  - **Risk Dot**: Green (Verified DHCP hostname), Orange (Unregistered / unknown hostname), Red (Suspicious MAC / multicast anomaly).
  - Monospace IP and MAC formatting.
  - Interface binding (`br-lan`, `eth0`, `wlan0`).
  - Active ARP status and risk assessment badges.
- **Real-Time Client Filter**: Instantly search clients by IP, MAC, hostname, or interface.
- **On-Demand Scan**: "Scan Now" button triggers immediate ARP cache refresh.
- **Hardening Recommendations**: Built-in best practices for static DHCP reservation and IoT VLAN segmentation.

#### 5. Settings & AdGuard Configuration
- **Customizable Endpoint**: Configurable AdGuard Host IP and Web UI Port (e.g. `8080`, `8081`, `3000`).
- **Authentication**: Optional username and password credentials.
- **"Retrieve from File" Auto-Discovery**: 1-click credential recovery that automatically checks `/etc/guardian_credentials.json`, UCI, and `adguardhome.yaml` if username/password are forgotten.
- **Live Test Connection**: Verify AdGuard Home reachability and API status before saving.
- **Persistent Secure Storage**: Settings are safely applied to UCI with an encrypted/restricted backup file (`chmod 0600`).

---

## ? Non-Blocking Architecture

Standard LuCI RPC calls can freeze or encounter gateway timeouts on slow API queries. Guardian Onyx isolates execution:

1. **Lightweight Controller**: `/usr/libexec/guardian-action.sh` executes fast backend queries with strict timeouts (`curl -m 5`).
2. **State Caching**: AdGuard stats and ARP discovery cache data in `/tmp/guardian_state.json` and `/tmp/adguard_stats.json`.
3. **Smooth LuCI Frontend**: The client-side view evaluates promises concurrently via `Promise.all` with fallbacks, ensuring zero router UI freezing.
4. **Smart Polling**: Automatically refreshes telemetry every 10 seconds only while on the Dashboard tab, suspending polling when viewing other tabs to conserve CPU cycles.

---

## ?? Repository Structure

```
luci-app-guardian-onyx/
+-- Makefile                                       # Universal OpenWrt package Makefile (luci.mk / package.mk)
+-- README.md                                      # Project documentation
+-- .gitignore                                     # Git build artifact exclusions
+-- .gitattributes                                 # Line ending configurations
+-- htdocs/
¦   +-- luci-static/
¦       +-- resources/
¦           +-- view/
¦               +-- guardian/
¦                   +-- index.js                   # Primary LuCI JavaScript Single-Page View
+-- root/
    +-- etc/
    ¦   +-- config/
    ¦   ¦   +-- guardian                           # UCI configuration defaults
    ¦   +-- init.d/
    ¦       +-- guardian                           # Procd background daemon service
    +-- usr/
        +-- libexec/
        ¦   +-- guardian-action.sh                 # Backend controller script (AdGuard API, fw4, ARP)
        +-- share/
            +-- luci/
            ¦   +-- menu.d/
            ¦       +-- luci-app-guardian-onyx.json# LuCI navigation menu definition
            +-- rpcd/
                +-- acl.d/
                    +-- luci-app-guardian-onyx.json# rpcd ACL security permissions
```

---

## ?? Installation

### Prerequisites
Guardian Onyx requires standard OpenWrt utilities:
```sh
opkg update
opkg install curl ca-bundle jq
```

### Installation via APK (OpenWrt 24.10+)
```sh
apk add luci-app-guardian-onyx_1.0-1_all.apk
```

### Installation via OPKG (OpenWrt 23.05 & ImmortalWrt)
```sh
opkg install luci-app-guardian-onyx_1.0-1_all.ipk
```

### Manual Installation
If deploying directly to a running router via SCP / SSH:
```sh
# Copy files
scp -r root/* root@192.168.1.1:/
scp -r htdocs/* root@192.168.1.1/www/

# Set execution permissions & reload services
ssh root@192.168.1.1 "chmod +x /usr/libexec/guardian-action.sh /etc/init.d/guardian && \
  /etc/init.d/rpcd reload && \
  rm -rf /tmp/luci-indexcache /tmp/luci-modulecache"
```

---

## ?? Configuration Reference

Configuration is managed in `/etc/config/guardian`:

```ini
config guardian 'main'
    option enabled '1'
    option adguard_enabled '1'
    option adguard_host '127.0.0.1'
    option adguard_port '3000'
    option adguard_user 'admin'
    option adguard_password 'yourpassword'
    option firewall_show_defaults '1'
    option threat_scan_interval '60'
    option log_level 'info'
```

### Option Descriptions

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `1` | Master toggle for Guardian service |
| `adguard_enabled` | boolean | `0` | Enable AdGuard Home API polling |
| `adguard_host` | string | `127.0.0.1` | AdGuard Home API host IP or hostname |
| `adguard_port` | integer | `3000` | AdGuard Home API port |
| `adguard_user` | string | `admin` | AdGuard Home API username |
| `adguard_password` | string | `""` | AdGuard Home API password |
| `threat_scan_interval`| integer | `60` | Background daemon scan interval in seconds |

---

## ?? Backend Script Reference

The controller script `/usr/libexec/guardian-action.sh` supports the following actions:

| Action | Description | Sample Output |
|---|---|---|
| `status` | Full system state JSON (AdGuard status, firewall state, client count) | `{"enabled":1,"adguard":{...},"firewall":{...}}` |
| `adguard_stats` | Raw statistics from AdGuard `/control/stats` | `{"num_dns_queries":1420,...}` |
| `adguard_toggle` | Toggles AdGuard protection on/off | `{"result":"ok"}` |
| `adguard_log` | Retrieves last 50 DNS query records | `{"data":[{...}]}` |
| `adguard_filters`| Retrieves active filter blocklists | `{"filters":[{...}]}` |
| `adguard_filter_refresh` | Triggers upstream blocklist update | `{"result":"ok"}` |
| `firewall_zones`| Returns UCI firewall zones with policies | `[{"name":"lan","input":"ACCEPT",...}]` |
| `firewall_rules`| Returns active nft ruleset in JSON format | `{"nftables":[...]}` |
| `clients` | Scans ARP cache & DHCP leases for connected devices | `[{"ip":"192.168.1.5","mac":"...","hostname":"PC"}]` |

---

## ?? License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

Developed with ?? for the OpenWrt & ImmortalWrt communities.
