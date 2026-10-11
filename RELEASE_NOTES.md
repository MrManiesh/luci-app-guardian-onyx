# Release v1.4.1

## Guardian Onyx Security Suite for OpenWrt

Unified Security, AdGuard Home DNS Filtering & Firewall Dashboard for OpenWrt & ImmortalWrt (23.05 / 24.10+ / 25.12+).

---

### What's New in v1.4.1:

#### 🚀 GitHub Update Detection & 1-Click LuCI Updater
- **Automated Update Detection**: Periodically or manually checks GitHub Releases for new package builds.
- **Top Header & Settings Access**: Quick-access `🔄 Check Update` button in the header alongside version badge and dedicated updates card in Settings.
- **1-Click LuCI In-App Update**: Downloads release APK, runs `apk add --allow-untrusted`, clears LuCI cache, and reloads services automatically.
- **Copyable SSH Terminal Command**: Generates complete `wget` + `apk add` commands with 1-click clipboard copy for manual SSH terminal execution.
- **Resilient Fallback**: Uses router backend `curl` with automatic browser-side `fetch()` fallback if router internet access is restricted.

#### 🛡️ Router Perimeter Hardening Shields (Firewall Tab)
- **1-Click Kernel Hardening Toggles**: Active controls for OpenWrt `fw4` / `nftables` defense systems.
- **SYN Flood Protection**: Guards router against DoS connection starvation attacks using SYN cookies.
- **Drop Invalid Packets**: Discards malformed TCP/UDP packets and out-of-order sequence attacks at the PREROUTING phase.
- **WAN Ping Stealth Mode**: Drops unsolicited ICMP echo requests from the internet to make router invisible to automated port scans.
- **TCP MSS Clamping (`mtu_fix`)**: Automatically clamps maximum segment size to prevent packet fragmentation over PPPoE / WAN.
- **Full-Cone NAT**: Lowers NAT filtering barriers for gaming and peer-to-peer applications.
- **Built-in Educational Guides**: Embedded help tooltips explaining what each hardening option does and when to use it.

#### ⚡ Live Conntrack Sessions Inspector (Firewall Tab)
- **Real-Time Active Connection Telemetry**: Direct streaming from kernel `/proc/net/nf_conntrack`.
- **Client Identity Resolution**: Translates raw internal IPs to friendly device names and MAC addresses.
- **Well-Known Port Hints**: Automatic detection of protocol services (`:443 HTTPS`, `:80 HTTP`, `:53 DNS`, `:22 SSH`, etc.).
- **Live Search & Protocol Filters**: Instantly filter sockets by protocol (All, TCP, UDP, ICMP), state (Established), or External WAN only.
- **Session Quota & Bandwidth Counters**: Displays live packet count and total byte volume per session.

---

### Installation (APK for OpenWrt 24.10+ / ImmortalWrt 25.x):
```sh
# Download and install the package
wget -O /tmp/luci-app-guardian-onyx-1.4.1.apk https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.4.1/luci-app-guardian-onyx-1.4.1.apk
apk add --allow-untrusted /tmp/luci-app-guardian-onyx-1.4.1.apk
```
