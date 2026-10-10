# Release v1.0.2

## Guardian Onyx Security Suite for OpenWrt

Unified Security, AdGuard Home DNS filtering & Firewall Dashboard for OpenWrt & ImmortalWrt (24.10+ / 25.12+).

### What's New in v1.0.2:
- **Streamlined 4-Tab Architecture**:
  - Removed redundant Dashboard tab for a clean, non-repetitive layout.
  - Tabs: **AdGuard Home**, **Firewall**, **Connected Clients**, and **Settings**.
- **Cleaner AdGuard Home Experience**:
  - Removed "Configured Filter Lists & Rule Status" table to focus on daily telemetry and live query monitoring.
- **Native Live DNS Query Inspector Integration**:
  - Replaced internal query inspector table with direct, real-time links to AdGuard Home's native query log: `http://192.168.1.1:8080/#logs?response_status=all`
  - Includes 1-click shortcuts for All Queries, Blocked Queries Only, and Allowed Queries with full protocol decoding and instant rule overrides.
- **True AdGuard Protection Toggle**:
  - 1-click **"Pause Protection"** and **"Start Protection"** button.
  - When paused, AdGuard Home disables all filtering rules immediately (bypass mode).
  - Instant UI reflection: banner switches between `Connected & Active` and `Protection Paused (Bypass Mode)` and button updates immediately.
- **Native APK Packaging**:
  - Standardized APK builds for OpenWrt 24.10+ and ImmortalWrt 25.12+ `apk` package manager.

### Installation via APK:
```sh
apk add /path/to/luci-app-guardian-onyx-1.0.2-r1.apk
```
Or directly from URL:
```sh
apk add --allow-untrusted https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.0.2/luci-app-guardian-onyx-1.0.2-r1.apk
```
