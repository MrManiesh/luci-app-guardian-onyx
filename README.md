<div align="center">

# 🛡️ Guardian Onyx (`luci-app-guardian-onyx`)

### Unified Security, AdGuard Home DNS & Client Access Dashboard for OpenWrt

[![Release](https://img.shields.io/github/v/release/MrManiesh/luci-app-guardian-onyx?color=6366f1&style=flat-square)](https://github.com/MrManiesh/luci-app-guardian-onyx/releases)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-24.10%2B-0099e5?style=flat-square&logo=openwrt&logoColor=white)](https://openwrt.org)
[![ImmortalWrt](https://img.shields.io/badge/ImmortalWrt-25.12%2B-10b981?style=flat-square)](https://immortalwrt.org)
[![Package](https://img.shields.io/badge/package-APK%20only-blueviolet?style=flat-square)](https://github.com/MrManiesh/luci-app-guardian-onyx/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)

<br/>

**Guardian Onyx** transforms your OpenWrt router into a modern, centralized network command center. It unifies **AdGuard Home DNS filtering**, **Linux kernel firewall (`fw4`/`nftables`)**, and **per-device client access telemetry** into a single sleek, responsive LuCI interface that adapts dynamically to dark and light themes.

<br/>

[🌟 Key Highlights](#-key-highlights) • [📱 Features by Tab](#-control-center-tabs) • [📦 Installation (APK)](#-installation-apk) • [💡 Pro Tips](#-pro-tips--workflows) • [🛠️ Technical Docs](EXTENDED_README.md)

</div>

---

## 🌟 Key Highlights

* **📱 Per-Device App & Service Blocker**: Restrict YouTube, TikTok, Roblox, Steam, Instagram, Discord, Netflix, and 130+ platforms on specific devices with 1 click without affecting the rest of your household.
* **⚡ Quick Domain Whitelist / Blacklist Manager**: Add game bypasses (like BGMI / PUBG), banking exceptions, or ad-blocking rules directly inside LuCI without opening the AdGuard console.
* **⏸️ 1-Click Internet Pause / Resume**: Temporarily freeze external internet access for any smartphone, gaming console, or smart TV using hardware-level `nftables` DROP rules.
* **📊 Comprehensive Client Telemetry**: Live Wi-Fi PHY bitrates (e.g. `⚡ 1.2 Gbps`), 5GHz/2.4GHz bands, RSSI signal strength (dBm), conntrack connection sessions, and total download/upload volume.
* **📌 1-Click Static DHCP Leases**: Lock dynamic clients to permanent static reservations directly from the table without opening DHCP settings.
* **🏷️ Custom Device Nicknames**: Name devices (*"Living Room Apple TV"*, *"Dad's Phone"*) with persistent aliases stored permanently on your router.
* **🌓 Zero-Config Theme Blending**: Automatically matches your favorite LuCI theme (Argon, Bootstrap, Material, Aurora) with zero external CDNs and 100% offline air-gap reliability.

---

## 🗂️ Control Center Tabs

### 1. Connected Clients & Access Control (Default Landing)

Everything you need to monitor and manage every device connected to your Wi-Fi or LAN ports.

| Feature | What It Does | User Benefit |
|---|---|---|
| **Overview Metric Cards** | Live summaries of discovered devices, 5GHz vs 2.4GHz Wi-Fi breakdown, wired LAN counts, total data volume, and session counters. | Instant network health check at a single glance. |
| **🛡️ App & Service Blocker** | Restrict access to **YouTube, TikTok, Netflix, Roblox, Steam, Instagram, Discord, Tinder**, etc. per client. | Precise parental control and distraction blocking per child/device. |
| **⏸️ Internet Pause / Resume** | 1-click **Pause Internet** immediately drops outbound WAN access via `fw4` / `nftables` hardware rules. | Instant access cutoff during study hours or dinner time. |
| **🏷️ Friendly Nicknames** | Assign friendly labels (e.g. *"Work Laptop"*, *"Son's iPad"*) stored safely in `/etc/config/guardian`. | Never guess which device belongs to whom by MAC address. |
| **📌 Static IP Reservation** | 1-click **+ Reserve IP** turns dynamic leases into permanent static DHCP reservations. | Keep IP addresses constant for NAS, servers, and smart devices. |
| **⚡ Live PHY Speed & Signal** | Wi-Fi PHY rates (`⚡ 866 Mbps`), connection uptime (`⏱️ 4h 12m`), and signal strength indicators. | Instantly identify weak Wi-Fi spots and network bottlenecks. |
| **🔍 Direct DNS Query Audit** | **DNS Logs ↗** button opens AdGuard Home's live query log pre-filtered for that specific device. | Investigate suspicious queries or domain lookups instantly. |

---

### 2. AdGuard Home Core Engine

Monitor, configure, and fine-tune your network-wide DNS ad-blocking and privacy engine directly from LuCI.

| Feature | Description |
|---|---|
| **Instance Health Banner** | Displays live host, port, upstream latency, engine version, and active status (`Connected & Active` vs `Protection Paused`). |
| **1-Click Protection Toggle** | Instantly pause or resume AdGuard Home DNS protection network-wide without stopping background services. |
| **⚡ Custom Filtering Rules** | Add domain **Whitelists (`@@||domain^`)** or **Blacklists (`||domain^`)** directly with a 1-click rule deletion button. |
| **24h Analytics KPIs** | View total DNS queries, blocked ads & trackers, SafeBrowsing malware stops, and parental protection counts. |
| **Real-Time Query Inspector** | Direct 1-click link to jump straight into AdGuard Home's live query log inspector. |
| **AdGuard Web UI Shortcut** | 1-click launcher to open the full AdGuard Home Web UI in a new browser tab. |

---

### 3. OpenWrt Firewall Engine

Transparent visibility and active control over Linux kernel packet filtering, DoS defenses, and socket connections.

| Feature | Description |
|---|---|
| **🛡️ Perimeter Hardening Shields** | 1-click toggles for **SYN Flood protection**, **Drop Invalid Packets**, **WAN Ping Stealth**, **TCP MSS Clamping**, and **Full-Cone NAT** with built-in explanatory guides. |
| **⚡ Live Conntrack Sessions Inspector** | Real-time active socket telemetry across all devices with client identity mapping, protocol filters (TCP, UDP, Established, External WAN), and well-known port hints (`:443 HTTPS`, `:53 DNS`, etc.). |
| **Firewall Security Zones** | Clear breakdown of `lan`, `wan`, and custom zones with policy badges (`ACCEPT`, `DROP`, `REJECT`). |
| **Port Forwarding (DNAT)** | Full inspector for active WAN-to-LAN port redirects and NAT configurations. |
| **1-Click Firewall Reload** | Safely flush and reload the firewall ruleset (`fw4 reload`) with live feedback. |

---

### 4. Settings & Auto-Discovery

Effortless connection between LuCI and your AdGuard Home instance.

| Feature | Description |
|---|---|
| **Configurable Endpoints** | Custom AdGuard Host IP and Web UI Port (e.g. `127.0.0.1:8080`, `192.168.1.1:3000`). |
| **⚡ Retrieve from File** | 1-click auto-discovery reads stored credentials directly from `/etc/guardian_credentials.json` or `adguardhome.yaml`. |
| **Live Connection Test** | Verify API connectivity and ping response times before saving. |
| **🚀 Built-in Update Detection** | 1-click check for updates against GitHub Releases with release notes, copyable SSH command, and direct LuCI in-app update. |
| **Secure UCI Storage** | Settings are saved directly to `/etc/config/guardian` with restricted permissions (`chmod 0600`). |

---

## 📦 Installation (APK)

> **Notice**: Guardian Onyx is packaged exclusively as an **OpenWrt APK package** for the modern OpenWrt package manager introduced in **OpenWrt 24.10+** and **ImmortalWrt 25.12+**.

### 1. Prerequisites
Ensure the lightweight core utilities are installed on your router:
```sh
apk update && apk add curl ca-bundle jq
```

### 2. Download & Install the APK
Download and install the official package directly on your router via SSH:

```sh
# Download the latest v1.4.1 release
wget -O /tmp/luci-app-guardian-onyx-1.4.1.apk https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.4.1/luci-app-guardian-onyx-1.4.1.apk

# Install the package
apk add --allow-untrusted /tmp/luci-app-guardian-onyx-1.4.1.apk
```

### 3. Access Guardian Onyx
Once installed, open your browser and navigate to:
```
http://192.168.1.1/cgi-bin/luci/admin/guardian
```
*(Or navigate via LuCI Menu: **Guardian Onyx**)*

---

## 💡 Pro Tips & Workflows

### 🎮 How to Bypass Games (BGMI, PUBG, Steam) Stuck on Loading
If an online game or banking app fails to connect due to aggressive ad-block lists:
1. Open the **AdGuard Home** tab.
2. Scroll to **Custom Filtering Rules (Whitelist / Blacklist)**.
3. In the input box, type the whitelist rule (e.g. `@@||globh.com^` for BGMI/PUBG).
4. Click **+ Add Whitelist Rule**. The rule takes effect across your network immediately!

### 🛡️ How to Block Social Media on a Specific Device
1. Open the **Connected Clients** tab.
2. Find the target device (e.g., your child's tablet) and click **🛡️ Block Apps**.
3. Use category quick-filters like **Social** or **Video** to select platforms like **YouTube**, **TikTok**, or **Roblox**.
4. Click **Apply Changes**. Only that device is restricted; other devices remain unaffected.

### ⏸️ How to Freeze a Device's Internet Temporarily
1. In the **Connected Clients** tab, locate the device.
2. Click **Pause Internet**. External WAN internet is instantly dropped at the firewall level.
3. When ready, click **Resume Internet** to restore full connection without rebooting.

---

## 🛠️ Technical & Developer Documentation

Looking for advanced CLI commands, UCI configuration schemas, or codebase details?

👉 **[Read the Extended Technical Documentation (EXTENDED_README.md)](EXTENDED_README.md)**

* **Backend CLI Reference**: Detailed manual for `/usr/libexec/guardian-action.sh` commands (`clients`, `client_block`, `adguard_add_rule`, `adguard_set_client_services`, etc.).
* **UCI Configuration Schema**: Complete specification of `/etc/config/guardian`.
* **Repository Architecture**: Explanation of the source layout and rpcd security model.
* **Developer Guide**: Instructions for live SSH/SCP deployment and local testing.

---

## 📄 License

Distributed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

Developed with ❤️ for the **OpenWrt** & **ImmortalWrt** community.
