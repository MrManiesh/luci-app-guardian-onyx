# Release v1.2.1

## Guardian Onyx Security Suite for OpenWrt

Unified Security, AdGuard Home DNS filtering & Firewall Dashboard for OpenWrt & ImmortalWrt (24.10+ / 25.12+).

### What's New in v1.2.1:
- **Redesigned Sleek Connected Clients Table**:
  - Replaced crowded 7-column layout with a spacious, balanced 5-column design (Device Identity, Connection & Link, Traffic & Volume, Status, Quick Actions).
  - Unifies device avatar, friendly alias, hardware vendor, IP (with 1-click copy), MAC, and static lease status in one harmonious identity card.
  - Generous row padding, responsive typography, and soft visual tinting for paused devices.
- **Client Internet Pause & Resume (Parental / Access Control)**:
  - 1-click **Pause Internet** button per client row immediately drops external WAN internet access via kernel `fw4` / `nftables` DROP rules.
  - 1-click **Resume Internet** button restores access instantly without rebooting.
  - Dedicated **⛔ Paused** filter pill to quickly view all currently blocked devices.
- **Custom Client Nicknames (Device Aliases)**:
  - Assign friendly, persistent aliases (e.g., "Dad's Phone", "Living Room TV") stored safely in `/etc/config/guardian`.
  - Prominent display with `(Alias)` badge and inline modal editor.
- **1-Click Static DHCP Lease Reservation**:
  - Convert any dynamic client into a permanent static DHCP reservation (`+ Reserve IP`) with automatic dnsmasq reload.
  - Devices with static leases display a `📌 Static` badge with 1-click release support.
- **Real-Time Bandwidth & PHY Link Telemetry**:
  - Tracks total data transferred per device (Download ⬇️ and Upload ⬆️).
  - Wi-Fi PHY Link Rate (e.g., `⚡ 2.1 Gbps`, `⚡ 480 Mbps`) and active connection uptime (e.g., `⏱️ 1h 56m`).
  - Active conntrack connection sessions count and aggregated network bandwidth in top KPI cards.
- **Streamlined 4-Tab Architecture (Connected Clients First)**:
  - Default landing tab is now **Connected Clients**, followed by **AdGuard Home**, **Firewall**, and **Settings**.
- **Cleaner AdGuard Home Experience**:
  - Removed "Configured Filter Lists & Rule Status" card to prioritize operational monitoring.
  - Direct 1-click link to native AdGuard Home query log (`http://<adguard-host>:<port>/#logs?response_status=all`).
  - True two-way 1-click **"Pause Protection"** / **"Start Protection"** button for immediate full rule bypass.

### Installation via APK:
```sh
apk add /path/to/luci-app-guardian-onyx-1.2.1.apk
```
Or directly from URL:
```sh
apk add --allow-untrusted https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.2.1/luci-app-guardian-onyx-1.2.1.apk
```
