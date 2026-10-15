# Release v1.4.2

## Guardian Onyx Security Suite for OpenWrt

Unified Security, AdGuard Home DNS Filtering & Firewall Dashboard for OpenWrt & ImmortalWrt (23.05 / 24.10+ / 25.12+).

---

### What's New in v1.4.2:

#### 🐛 Bug Fix: Clean Offline State & Fresh Install Initialization
- **Fixed `TypeError: can't access property "length", self.adguardFilters is undefined`**: Resolved an issue that crashed the LuCI dashboard on routers where AdGuard Home was not yet installed, offline, or awaiting credentials configuration.
- **Robust Fallback Data Parser**: Ensures all dashboard tabs (Connected Clients, Firewall Hardening, Conntrack Sessions Inspector, and Settings) load and render seamlessly even if backend AdGuard Home services are temporarily offline or unreachable.
- **Rules & Services Pre-loader**: Properly initialises initial rule sets and service blocking definitions at startup.

---

### Previous Highlights from v1.4.1:
- **🚀 GitHub Update Detection & 1-Click LuCI Updater**: Real-time update check in header and settings with 1-click update and copyable terminal command.
- **🛡️ Router Perimeter Hardening Shields**: 1-click toggles for SYN Flood protection, Drop Invalid packets, Stealth Mode, and TCP MSS Clamping.
- **⚡ Live Conntrack Sessions Inspector**: Real-time socket connections with friendly client identity mapping.

---

### Installation (APK for OpenWrt 24.10+ / ImmortalWrt 25.x):
```sh
# Download and install the package
wget -O /tmp/luci-app-guardian-onyx-1.4.2.apk https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.4.2/luci-app-guardian-onyx-1.4.2.apk
apk add --allow-untrusted /tmp/luci-app-guardian-onyx-1.4.2.apk
```
