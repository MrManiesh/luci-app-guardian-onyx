# Release v1.0.1

## Guardian Onyx Security Suite for OpenWrt

Unified Security, AdGuard Home DNS filtering & Firewall Dashboard for OpenWrt & ImmortalWrt (24.10+ / 25.12+).

### Highlights:
- **5-Tab Unified Security Control Center**:
  - **Dashboard**: High-craft telemetry overview, 24h block rates, query latency, and 1-click protection toggle.
  - **AdGuard Home**: Live query inspector, blocklist rules & refresh, engine telemetry.
  - **Firewall**: Real-time conntrack counters, active security zones (`ACCEPT`/`DROP`/`REJECT`), port forwarding rules, and 1-click reload.
  - **Connected Clients**: ARP device discovery, hostname identification, and risk auditing.
  - **Settings**: Configurable AdGuard host/port/credentials, live test connection, and **"Retrieve from File"** 1-click credential recovery.
- **Adaptive Onyx Design System**:
  - Automatically adapts to light and dark themes (Argon, Bootstrap, Aurora, Material, Proton2025).
  - Self-contained SVG icons and typography with zero CDN dependencies for offline and air-gapped routers.
- **Modern APK Packaging**:
  - Packaged natively for OpenWrt 24.10+ and ImmortalWrt 25.12+ `apk` package manager.

### Installation via APK:
```sh
apk add /path/to/luci-app-guardian-onyx-1.0.1-r1.apk
```
Or directly from URL:
```sh
apk add --allow-untrusted https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.0.1/luci-app-guardian-onyx-1.0.1-r1.apk
```
