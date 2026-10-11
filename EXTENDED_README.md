<div align="center">

# 🛠️ Guardian Onyx — Technical Reference & Architecture

### Backend CLI Reference, UCI Configuration, Architecture & Developer Guide

[![Release](https://img.shields.io/github/v/release/MrManiesh/luci-app-guardian-onyx?color=6366f1&style=flat-square)](https://github.com/MrManiesh/luci-app-guardian-onyx/releases)
[![Package](https://img.shields.io/badge/package-APK-blueviolet?style=flat-square)](https://github.com/MrManiesh/luci-app-guardian-onyx/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)

[← Back to Main README](README.md) • [Backend CLI](#️-backend-cli-reference) • [Configuration Reference](#️-uci-configuration-reference) • [Repository Structure](#-repository-structure) • [Security & ACL](#-security--rpcd-acls)

</div>

---

## 🛠️ Backend CLI Reference

The helper controller [`/usr/libexec/guardian-action.sh`](root/usr/libexec/guardian-action.sh) handles all low-level communication between LuCI, AdGuard Home REST APIs, the Linux kernel firewall (`nftables` / `fw4`), DHCP leases, and wireless interfaces.

It can be run directly from an SSH terminal or invoked by automation scripts:

```sh
/usr/libexec/guardian-action.sh <action> [arguments]
```

### Complete Command Matrix

| Command | Arguments | Output | Description |
|---|---|---|---|
| `status` | — | JSON Object | Comprehensive system health check (AdGuard status, firewall backend, active client count, service PID). |
| `clients` | — | JSON Array | Aggregates ARP table, DHCP leases, active Wi-Fi associations, conntrack sessions, and AdGuard blocked services per client. |
| `client_block` | `<mac> [ip]` | JSON (`{"result":"ok"}`) | Drops outbound internet access for the specified MAC/IP using `fw4` / `nftables` hardware filter rules. |
| `client_unblock` | `<mac>` | JSON (`{"result":"ok"}`) | Removes firewall drop rule and restores full WAN internet connectivity. |
| `set_nickname` | `<mac> <name>` | JSON (`{"result":"ok"}`) | Saves or updates a persistent friendly device alias in `/etc/config/guardian`. Pass empty name `""` to clear. |
| `reserve_ip` | `<mac> <ip> [host]` | JSON (`{"result":"ok"}`) | Creates a permanent static DHCP reservation in `/etc/config/dhcp` and reloads `dnsmasq`. |
| `unreserve_ip` | `<mac>` | JSON (`{"result":"ok"}`) | Removes the static lease reservation from `/etc/config/dhcp` and reloads `dnsmasq`. |
| `adguard_rules` | — | JSON Array | Retrieves user custom filtering rules from AdGuard Home `/control/filtering/status`. |
| `adguard_add_rule` | `<rule> [type]` | JSON (`{"result":"ok"}`) | Appends a custom rule (`@@||domain^` for allow or `||domain^` for block) to AdGuard Home. |
| `adguard_delete_rule` | `<rule>` | JSON (`{"result":"ok"}`) | Deletes an exact rule line from AdGuard Home custom rules list. |
| `adguard_services_list`| — | JSON Array | Returns all 136 supported blockable service definitions from AdGuard Home. |
| `adguard_client_services`| `<ip> <mac>` | JSON Array | Retrieves the list of currently blocked services assigned to a specific client. |
| `adguard_set_client_services`| `<ip> <mac> <name> <json_services>` | JSON (`{"result":"ok"}`) | Sets blocked services for a specific client (e.g. `'["youtube","roblox"]'`) in AdGuard Home client registry. |
| `adguard_stats` | — | JSON Object | Returns DNS analytics from AdGuard Home `/control/stats` (total queries, blocked ads, etc.). |
| `adguard_toggle` | — | JSON (`{"result":"ok"}`) | Toggles global AdGuard DNS protection on or off via `/control/dns_config`. |
| `firewall_rules` | — | JSON Array | Dumps active firewall rules from OpenWrt `fw4` / `nftables` subsystem. |
| `firewall_zones` | — | JSON Array | Inspects configured UCI firewall zones, interfaces, and default forwarding policies. |
| `firewall_reload` | — | JSON (`{"result":"ok"}`) | Flushes and safely reloads the system firewall ruleset (`fw4 reload` or `fw3 reload`). |
| `firewall_hardening` | — | JSON Object | Returns status of kernel defenses (`synflood_protect`, `drop_invalid`, `stealth_mode`, `mtu_fix`, `fullcone`). |
| `firewall_hardening_set` | `<key> <val>` | JSON Object | Toggles kernel hardening defense in UCI and applies immediately to `fw4`. |
| `conntrack_sessions` | `[max]` | JSON Object | Returns real-time active socket connection telemetry from kernel `/proc/net/nf_conntrack`. |
| `check_update` | — | JSON Object | Queries GitHub Releases API for the latest release tag, release notes, and `.apk` assets. |
| `update_now` | `<download_url>` | JSON (`{"result":"ok"}`) | Downloads release `.apk` to `/tmp`, installs via `apk add --allow-untrusted`, clears LuCI cache, and reloads `rpcd`. |

---

### Command Examples & Sample Outputs

#### 1. Device Threat & Discovery Scan (`clients`)
```sh
/usr/libexec/guardian-action.sh clients | jq .[0]
```
```json
{
  "ip": "192.168.1.165",
  "mac": "a0:b0:00:0b:0a:ab",
  "hostname": "Samsung Smart TV",
  "custom_name": "Living Room TV",
  "iface": "br-lan",
  "conn_type": "wifi",
  "wifi_band": "5GHz",
  "wifi_signal": "-56 dBm",
  "sessions": 6,
  "rx_bytes": 2802528,
  "tx_bytes": 22224937,
  "tx_rate": "480.3 MBit/s",
  "rx_rate": "6.0 MBit/s",
  "conn_time": 9806,
  "is_blocked": false,
  "is_static": true,
  "blocked_services": ["youtube", "tiktok"]
}
```

#### 2. Managing Custom Filtering Rules
```sh
# Add whitelist bypass for game domains
/usr/libexec/guardian-action.sh adguard_add_rule "@@||globh.com^"

# Add ad/tracker blacklist
/usr/libexec/guardian-action.sh adguard_add_rule "||adservice.google.com^"

# Delete a rule
/usr/libexec/guardian-action.sh adguard_delete_rule "@@||globh.com^"
```

#### 3. Restricting Apps & Services on a Specific Device
```sh
# Block YouTube and Roblox on IP 192.168.1.165 (MAC: a0:b0:00:0b:0a:ab)
/usr/libexec/guardian-action.sh adguard_set_client_services "192.168.1.165" "a0:b0:00:0b:0a:ab" "Kids iPad" '["youtube","roblox"]'

# Clear all service blocks for this device
/usr/libexec/guardian-action.sh adguard_set_client_services "192.168.1.165" "a0:b0:00:0b:0a:ab" "Kids iPad" '[]'
```

#### 4. Pausing / Resuming External Internet Access
```sh
# Block internet for specific device
/usr/libexec/guardian-action.sh client_block "a0:b0:00:0b:0a:ab" "192.168.1.165"

# Restore internet access
/usr/libexec/guardian-action.sh client_unblock "a0:b0:00:0b:0a:ab"
```

---

## ⚙️ UCI Configuration Reference

Guardian Onyx uses OpenWrt's native **UCI (Unified Configuration Interface)** stored in [`/etc/config/guardian`](root/etc/config/guardian).

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
    option mac '0a:00:bb:cc:dd:ee'
    option name 'OnePlus 12'

config alias
    option mac 'a0:b0:00:0b:0a:ab'
    option name 'Living Room Apple TV'
```

### Main Section Options (`config guardian 'main'`)

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `1` | Master switch for the Guardian daemon service. |
| `adguard_enabled` | boolean | `1` | Enables live AdGuard Home REST API integration. |
| `adguard_host` | string | `127.0.0.1` | IP address or hostname where AdGuard Home Web UI is reachable. |
| `adguard_port` | integer | `8080` | Port of the AdGuard Home Web UI / API (e.g. `8080`, `3000`). |
| `adguard_user` | string | `""` | Username for AdGuard Home HTTP Basic Authentication. |
| `adguard_password` | string | `""` | Password for AdGuard Home HTTP Basic Authentication. |
| `threat_scan_interval`| integer | `60` | Background monitoring interval in seconds. |
| `log_level` | string | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`). |

### Alias Section Options (`config alias`)

Each friendly nickname saved in the Connected Clients tab is stored as an individual `alias` block:

| Option | Type | Required | Description |
|---|---|---|---|
| `mac` | string | **Yes** | Lowercase hardware MAC address of the device (e.g. `0a:00:bb:cc:dd:ee`). |
| `name` | string | **Yes** | Friendly human-readable label (e.g. `Office Workstation`, `Kids iPad`). |

### Modifying via UCI CLI

```sh
# Change AdGuard Home host & port
uci set guardian.main.adguard_host='192.168.1.1'
uci set guardian.main.adguard_port='3000'
uci commit guardian

# Reload configuration daemon
/etc/init.d/guardian restart
```

---

## 📁 Repository Structure

```text
luci-app-guardian-onyx/
├── Makefile                                       # Universal OpenWrt build recipe
├── README.md                                      # Main user documentation & quickstart
├── EXTENDED_README.md                             # Technical reference, CLI & architecture guide
├── RELEASE_NOTES.md                               # Release changelogs & version notes
├── LICENSE                                        # Apache 2.0 open-source license
├── .github/
│   ├── scripts/
│   │   └── package-apk.sh                         # Lightweight Alpine container APK packager
│   └── workflows/
│       └── build.yml                              # Automated GitHub Actions APK release builder
├── htdocs/
│   └── luci-static/
│       └── resources/
│           └── view/
│               └── guardian/
│                   └── index.js                   # LuCI client Single-Page Application (Vanilla JS)
└── root/
    ├── etc/
    │   ├── config/
    │   │   └── guardian                           # Default UCI configuration template
    │   └── init.d/
    │       └── guardian                           # Procd system init daemon script
    └── usr/
        ├── libexec/
        │   └── guardian-action.sh                 # Router controller CLI backend
        └── share/
            ├── luci/
            │   └── menu.d/
            │       └── luci-app-guardian-onyx.json# LuCI navigation menu definition
            └── rpcd/
                └── acl.d/
                    └── luci-app-guardian-onyx.json# rpcd ACL security access rules
```

---

## 🔐 Security & rpcd ACLs

Guardian Onyx enforces strict OpenWrt rpcd security boundaries defined in [`/usr/share/rpcd/acl.d/luci-app-guardian-onyx.json`](root/usr/share/rpcd/acl.d/luci-app-guardian-onyx.json):

* **Execution Isolation**: Frontend JavaScript never executes arbitrary shell commands. All actions flow through `/usr/libexec/guardian-action.sh` via the `file.exec` RPC provider with fixed whitelist arguments.
* **Credential Protection**: `/etc/config/guardian` is maintained with `0600` permissions to protect stored AdGuard credentials from unauthorized local users.
* **Air-Gap Safe**: Operates 100% locally on your LAN with zero telemetry, analytics, or external CDN dependencies.

---

## 🔨 Development & Live Testing

To test modifications directly on a running OpenWrt router during development:

```sh
# 1. Sync updated files to the router
scp root/usr/libexec/guardian-action.sh root@192.168.1.1:/usr/libexec/
scp htdocs/luci-static/resources/view/guardian/index.js root@192.168.1.1/www/luci-static/resources/view/guardian/

# 2. Set executable permissions and flush LuCI cache
ssh root@192.168.1.1 "chmod +x /usr/libexec/guardian-action.sh && \
  /etc/init.d/rpcd restart && \
  rm -rf /tmp/luci-indexcache /tmp/luci-modulecache"
```
