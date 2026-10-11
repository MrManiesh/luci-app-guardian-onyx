# Release v1.3.1

## Guardian Onyx Security Suite for OpenWrt

Unified Security, AdGuard Home DNS Filtering & Firewall Dashboard for OpenWrt & ImmortalWrt (23.05 / 24.10+ / 25.12+).

---

### What's New in v1.3.1:

#### 📱 Per-Device App & Service Blocker (Parental & Productivity Control)
- **Granular Client-Specific Enforcement**: Restrict platforms individually per device without affecting the rest of your network.
- **130+ Supported Services**: Control access to **YouTube, TikTok, Netflix, Roblox, Discord, Steam, Instagram, Spotify, Tinder, Twitch, Telegram**, and many more.
- **Category Quick Filters & Real-Time Search**: Filter services by category (**Social, Video Streaming, Gaming, Adult Content**) or instantly search across all 136 AdGuard-supported services.
- **Intuitive UI Badges**: Connected clients table displays live `🛡️ X Blocked` badges for any client with active restrictions.
- **Seamless Modal Editor**: 1-click `🛡️ Block Apps` button on each client row opens an interactive selection modal that saves and applies changes immediately.

#### ⚡ Quick Domain Whitelist & Blacklist Manager (AdGuard Tab)
- **Native Custom Filtering Rules Table**: Manage AdGuard Home user rules directly inside LuCI without needing to open the external AdGuard Web UI.
- **Live Rule List with Badges**: View all active custom rules categorized with clean visual tags (**ALLOW**, **BLOCK**, **CUSTOM**).
- **Fast Quick-Add Bar**: Easily add domain exceptions (such as game bypasses like `@@||globh.com^` for BGMI/PUBG) or blocklists (`||bad-domain.com^`).
- **1-Click Rule Deletion**: Remove rules instantly with real-time feedback and AdGuard configuration reload.

#### 📖 Documentation & Architecture Overhaul
- **Modern Scannable README**: Redesigned documentation with clear visual matrices for all dashboard tabs.
- **Comprehensive Backend CLI Reference**: Full documentation for `/usr/libexec/guardian-action.sh` commands (`status`, `clients`, `client_block`, `client_unblock`, `adguard_toggle`, `adguard_add_rule`, `adguard_delete_rule`, `adguard_set_client_services`, `firewall_reload`).
- **Complete UCI Configuration Guide**: Detailed guide for `/etc/config/guardian` options.

---

### Installation (APK for OpenWrt 24.10+ / ImmortalWrt 25.x):
```sh
# Download and install the package
wget -O /tmp/luci-app-guardian-onyx-1.3.1.apk https://github.com/MrManiesh/luci-app-guardian-onyx/releases/download/v1.3.1/luci-app-guardian-onyx-1.3.1.apk
apk add --allow-untrusted /tmp/luci-app-guardian-onyx-1.3.1.apk
```
