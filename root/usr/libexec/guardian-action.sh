#!/bin/sh
# guardian-action.sh - Backend script for luci-app-guardian-onyx
# Handles AdGuard Home API, firewall queries, and client scanning

ACTION="${1}"
ADGUARD_STATE=/tmp/adguard_stats.json
GUARDIAN_STATE=/tmp/guardian_state.json
EVENTS_FILE=/etc/guardian_events.json
LOCK_FILE=/tmp/guardian.lock

get_config() {
    local key="$1"
    local default="$2"
    val=$(uci -q get "guardian.main.${key}" 2>/dev/null)
    echo "${val:-$default}"
}

adguard_api() {
    local path="$1"
    local method="${2:-GET}"
    local data="$3"
    local host=$(get_config adguard_host "127.0.0.1")
    local port=$(get_config adguard_port "8080")
    local user=$(get_config adguard_user "")
    local pass=$(get_config adguard_password "")

    # Check saved credentials file if UCI config is empty
    if [ -z "$user" ] && [ -f "/etc/guardian_credentials.json" ]; then
        user=$(jsonfilter -i "/etc/guardian_credentials.json" -e '@.user' 2>/dev/null)
        pass=$(jsonfilter -i "/etc/guardian_credentials.json" -e '@.password' 2>/dev/null)
    fi

    local auth_args=""
    if [ -n "$user" ] || [ -n "$pass" ]; then
        auth_args="-u ${user}:${pass}"
    fi

    if [ -n "$data" ]; then
        curl -s -f -m 5 $auth_args \
            -X "${method}" \
            -H "Content-Type: application/json" \
            -d "${data}" \
            "http://${host}:${port}/control/${path}" 2>/dev/null
    else
        curl -s -f -m 5 $auth_args \
            "http://${host}:${port}/control/${path}" 2>/dev/null
    fi
}

cmd_status() {
    local enabled=$(get_config enabled "0")
    local adguard_enabled=$(get_config adguard_enabled "0")
    local adguard_host=$(get_config adguard_host "127.0.0.1")
    local adguard_port=$(get_config adguard_port "8080")

    # AdGuard Home connectivity check
    local ag_status="offline"
    local ag_protection="true"
    local ag_version="N/A"
    local ag_stats="{}"
    if [ "$adguard_enabled" = "1" ]; then
        local ag_info
        ag_info=$(adguard_api "status")
        if [ -n "$ag_info" ]; then
            ag_status="online"
            ag_protection=$(echo "$ag_info" | jsonfilter -e '@.protection_enabled' 2>/dev/null || echo "true")
            [ -z "$ag_protection" ] && ag_protection="true"
            ag_version=$(echo "$ag_info" | jsonfilter -e '@.version' 2>/dev/null || echo "N/A")
            local ag_raw
            ag_raw=$(adguard_api "stats")
            if [ -n "$ag_raw" ]; then
                ag_stats="$ag_raw"
            else
                ag_stats="{}"
            fi
        fi
    fi

    # Firewall status
    local fw_running=0
    if command -v nft >/dev/null 2>&1; then
        nft list ruleset >/dev/null 2>&1 && fw_running=1
    elif command -v iptables >/dev/null 2>&1; then
        iptables -L >/dev/null 2>&1 && fw_running=1
    fi

    # Connected clients count
    local clients=0
    clients=$(cat /proc/net/arp 2>/dev/null | grep -v "IP address" | grep -c "0x2\|0x6" 2>/dev/null || echo 0)

    # Build state JSON
    cat > "$GUARDIAN_STATE" <<ENDJSON
{
    "enabled": $enabled,
    "timestamp": $(date +%s),
    "adguard": {
        "enabled": $adguard_enabled,
        "status": "$ag_status",
        "protection_enabled": $ag_protection,
        "version": "$ag_version",
        "host": "$adguard_host",
        "port": $adguard_port,
        "stats": $ag_stats
    },
    "firewall": {
        "running": $fw_running
    },
    "clients": {
        "count": $clients
    }
}
ENDJSON

    cat "$GUARDIAN_STATE"
}

cmd_adguard_stats() {
    local stats
    stats=$(adguard_api "stats")
    if [ -n "$stats" ]; then
        echo "$stats"
    else
        echo "{}"
    fi
}

cmd_adguard_toggle() {
    local ag_info=$(adguard_api "status")
    local current=$(echo "$ag_info" | jsonfilter -e '@.protection_enabled' 2>/dev/null)
    if [ "$current" = "true" ]; then
        adguard_api "protection" "POST" '{"enabled":false}' >/dev/null 2>&1
        echo '{"result":"ok","protection_enabled":false}'
    else
        adguard_api "protection" "POST" '{"enabled":true}' >/dev/null 2>&1
        echo '{"result":"ok","protection_enabled":true}'
    fi
}

cmd_firewall_rules() {
    if command -v nft >/dev/null 2>&1; then
        nft -j list ruleset 2>/dev/null || echo '{"nftables":[]}'
    else
        echo '{"error":"nft not available"}'
    fi
}

cmd_firewall_zones() {
    local result="["
    local first=1
    uci show firewall 2>/dev/null | grep "=zone" | while IFS= read -r line; do
        local section=$(echo "$line" | cut -d= -f1 | cut -d. -f2)
        local name=$(uci -q get "firewall.${section}.name" 2>/dev/null)
        local input=$(uci -q get "firewall.${section}.input" 2>/dev/null)
        local output=$(uci -q get "firewall.${section}.output" 2>/dev/null)
        local forward=$(uci -q get "firewall.${section}.forward" 2>/dev/null)
        if [ -n "$name" ]; then
            [ $first -eq 0 ] && result="${result},"
            result="${result}{\"name\":\"${name}\",\"input\":\"${input}\",\"output\":\"${output}\",\"forward\":\"${forward}\"}"
            first=0
        fi
    done
    echo "${result}]"
}

cmd_clients() {
    local wl_file="/tmp/guardian_wl.$$"
    local stat_file="/tmp/guardian_stat.$$"
    local blocked_file="/tmp/guardian_blocked.$$"
    local alias_file="/tmp/guardian_alias.$$"
    local static_file="/tmp/guardian_static.$$"
    local ct_file="/tmp/guardian_ct.$$"
    local ag_file="/tmp/guardian_ag.$$"

    touch "$wl_file" "$stat_file" "$blocked_file" "$alias_file" "$static_file" "$ct_file" "$ag_file"

    # 1. Pre-collect wireless associations (iwinfo)
    if command -v iwinfo >/dev/null 2>&1; then
        for wdev in $(iw dev 2>/dev/null | grep Interface | awk '{print $2}'); do
            local band="2.4GHz"
            echo "$wdev" | grep -q "phy1" && band="5GHz"
            iwinfo "$wdev" assoclist 2>/dev/null | grep -iE '^[0-9a-f]{2}:' | while read -r mac sig; do
                local m=$(echo "$mac" | tr 'A-Z' 'a-z')
                local s=$(echo "$sig" | awk '{print $1, $2}')
                echo "${m}|${band}|${s}" >> "$wl_file"
            done
        done
    fi

    # 2. Pre-collect wireless station stats (bytes, bitrates, uptime)
    for wdev in $(iw dev 2>/dev/null | grep Interface | awk '{print $2}'); do
        iw dev "$wdev" station dump 2>/dev/null
    done | awk '
    /^Station / {
        mac = tolower($2);
        next;
    }
    /rx bytes:/ { rx[mac] = $3; }
    /tx bytes:/ { tx[mac] = $3; }
    /tx bitrate:/ { tx_rate[mac] = $3 " " $4; }
    /rx bitrate:/ { rx_rate[mac] = $3 " " $4; }
    /connected time:/ { conn_time[mac] = $3; }
    END {
        for (m in rx) {
            print m "|" rx[m] "|" tx[m] "|" tx_rate[m] "|" rx_rate[m] "|" conn_time[m];
        }
    }' > "$stat_file" 2>/dev/null

    # 3. Pre-collect blocked MACs from firewall
    uci show firewall 2>/dev/null | grep -i "\.name='Guardian_Block_" | cut -d. -f2 | cut -d= -f1 | while read -r sec; do
        uci -q get "firewall.${sec}.src_mac" 2>/dev/null | tr 'A-Z' 'a-z' >> "$blocked_file"
    done

    # 4. Pre-collect custom nicknames from guardian config
    uci show guardian 2>/dev/null | grep "=alias" | cut -d. -f2 | cut -d= -f1 | while read -r sec; do
        local m=$(uci -q get "guardian.${sec}.mac" 2>/dev/null | tr 'A-Z' 'a-z')
        local n=$(uci -q get "guardian.${sec}.name" 2>/dev/null)
        [ -n "$m" ] && [ -n "$n" ] && echo "${m}|${n}" >> "$alias_file"
    done

    # 5. Pre-collect static DHCP lease MACs
    uci show dhcp 2>/dev/null | grep -i "\.mac=" | cut -d"'" -f2 | tr 'A-Z' 'a-z' >> "$static_file"

    # 6. Pre-collect conntrack session counts and bytes per IP
    awk '{
        ip = ""; b1 = 0; b2 = 0;
        for (i=1; i<=NF; i++) {
            if ($i ~ /^src=/) {
                sub(/^src=/, "", $i);
                if (ip == "") ip = $i;
            } else if ($i ~ /^bytes=/) {
                sub(/^bytes=/, "", $i);
                if (b1 == 0) b1 = $i + 0;
                else if (b2 == 0) b2 = $i + 0;
            }
        }
        if (ip != "") {
            ct_cnt[ip]++;
            ct_tx[ip] += b1;
            ct_rx[ip] += b2;
        }
    } END {
        for (ip in ct_cnt) {
            print ip "|" ct_cnt[ip] "|" ct_tx[ip] "|" ct_rx[ip];
        }
    }' /proc/net/nf_conntrack > "$ct_file" 2>/dev/null

    # 7. Pre-collect AdGuard Home client blocked services
    local ag_raw=$(adguard_api "clients" 2>/dev/null)
    if [ -n "$ag_raw" ]; then
        echo "$ag_raw" | jq -r '
            (.clients // [])[] |
            . as $c |
            ($c.blocked_services // []) as $bs |
            if ($bs | length) > 0 then
                ($c.ids // [])[] |
                "\((. | ascii_downcase))|\($bs | tojson)"
            else empty end
        ' 2>/dev/null >> "$ag_file"
    fi

    local result="["
    local first=1

    # Parse ARP table
    while IFS= read -r line; do
        echo "$line" | grep -qE "^[0-9]" || continue
        local ip=$(echo "$line" | awk '{print $1}')
        local mac=$(echo "$line" | awk '{print $4}' | tr 'A-Z' 'a-z')
        local iface=$(echo "$line" | awk '{print $6}')
        [ "$mac" = "00:00:00:00:00:00" ] && continue

        # Exclude WAN interfaces from local clients view
        [ "$iface" = "wan" ] && continue

        # Get hostname from DHCP leases
        local hostname=$(grep -i "$mac" /tmp/dhcp.leases 2>/dev/null | awk '{print $4}' | head -1)
        [ -z "$hostname" ] || [ "$hostname" = "*" ] && hostname="Unknown"

        # Check wireless info
        local conn_type="wired"
        local wifi_band=""
        local wifi_signal=""
        local wl_entry=$(grep -i "^${mac}|" "$wl_file" 2>/dev/null | head -1)
        if [ -n "$wl_entry" ]; then
            conn_type="wifi"
            wifi_band=$(echo "$wl_entry" | cut -d'|' -f2)
            wifi_signal=$(echo "$wl_entry" | cut -d'|' -f3)
        fi

        # Station stats
        local rx_bytes=0
        local tx_bytes=0
        local tx_rate=""
        local rx_rate=""
        local conn_time=0
        local st_entry=$(grep -i "^${mac}|" "$stat_file" 2>/dev/null | head -1)
        if [ -n "$st_entry" ]; then
            rx_bytes=$(echo "$st_entry" | cut -d'|' -f2)
            tx_bytes=$(echo "$st_entry" | cut -d'|' -f3)
            tx_rate=$(echo "$st_entry" | cut -d'|' -f4)
            rx_rate=$(echo "$st_entry" | cut -d'|' -f5)
            conn_time=$(echo "$st_entry" | cut -d'|' -f6)
        fi

        # Conntrack
        local sessions=0
        local ct_entry=$(grep "^${ip}|" "$ct_file" 2>/dev/null | head -1)
        if [ -n "$ct_entry" ]; then
            sessions=$(echo "$ct_entry" | cut -d'|' -f2)
            if [ "$conn_type" = "wired" ]; then
                tx_bytes=$(echo "$ct_entry" | cut -d'|' -f3)
                rx_bytes=$(echo "$ct_entry" | cut -d'|' -f4)
            fi
        fi
        [ -z "$sessions" ] && sessions=0

        # Blocked check
        local is_blocked="false"
        grep -qi "^${mac}$" "$blocked_file" 2>/dev/null && is_blocked="true"

        # Alias check
        local custom_name=""
        local al_entry=$(grep -i "^${mac}|" "$alias_file" 2>/dev/null | head -1)
        [ -n "$al_entry" ] && custom_name=$(echo "$al_entry" | cut -d'|' -f2-)

        # Static lease check
        local is_static="false"
        grep -qi "^${mac}$" "$static_file" 2>/dev/null && is_static="true"

        # AdGuard blocked services for this client
        local blocked_services="[]"
        if [ -s "$ag_file" ]; then
            local ag_match=$(grep -i "^${mac}|" "$ag_file" 2>/dev/null | head -1 | cut -d'|' -f2-)
            [ -z "$ag_match" ] && ag_match=$(grep -i "^${ip}|" "$ag_file" 2>/dev/null | head -1 | cut -d'|' -f2-)
            [ -n "$ag_match" ] && blocked_services="$ag_match"
        fi

        [ $first -eq 0 ] && result="${result},"
        result="${result}{\"ip\":\"${ip}\",\"mac\":\"${mac}\",\"hostname\":\"${hostname}\",\"custom_name\":\"${custom_name}\",\"iface\":\"${iface}\",\"conn_type\":\"${conn_type}\",\"wifi_band\":\"${wifi_band}\",\"wifi_signal\":\"${wifi_signal}\",\"sessions\":${sessions},\"rx_bytes\":${rx_bytes:-0},\"tx_bytes\":${tx_bytes:-0},\"tx_rate\":\"${tx_rate}\",\"rx_rate\":\"${rx_rate}\",\"conn_time\":${conn_time:-0},\"is_blocked\":${is_blocked},\"is_static\":${is_static},\"blocked_services\":${blocked_services}}"
        first=0
    done < /proc/net/arp

    rm -f "$wl_file" "$stat_file" "$blocked_file" "$alias_file" "$static_file" "$ct_file" "$ag_file"
    echo "${result}]"
}

cmd_client_block() {
    local mac="$2"
    local ip="$3"
    [ -z "$mac" ] && echo '{"error":"missing mac"}' && return
    local smac=$(echo "$mac" | tr -d ':' | tr 'A-Z' 'a-z')
    local sname="guardian_block_${smac}"

    uci set firewall."$sname"=rule
    uci set firewall."$sname".name="Guardian_Block_${mac}"
    uci set firewall."$sname".src="lan"
    uci set firewall."$sname".dest="wan"
    uci set firewall."$sname".src_mac="$mac"
    [ -n "$ip" ] && uci set firewall."$sname".src_ip="$ip"
    uci set firewall."$sname".target="DROP"
    uci set firewall."$sname".enabled="1"
    uci commit firewall
    if command -v fw4 >/dev/null 2>&1; then
        fw4 reload >/dev/null 2>&1
    elif command -v fw3 >/dev/null 2>&1; then
        fw3 reload >/dev/null 2>&1
    elif [ -x /etc/init.d/firewall ]; then
        /etc/init.d/firewall reload >/dev/null 2>&1
    fi
    echo '{"result":"ok","blocked":true}'
}

cmd_client_unblock() {
    local mac="$2"
    [ -z "$mac" ] && echo '{"error":"missing mac"}' && return
    local smac=$(echo "$mac" | tr -d ':' | tr 'A-Z' 'a-z')
    local sname="guardian_block_${smac}"

    uci delete firewall."$sname" 2>/dev/null
    for s in $(uci show firewall 2>/dev/null | grep -i "Guardian_Block_${mac}" | cut -d. -f2 | cut -d= -f1); do
        uci delete firewall."$s" 2>/dev/null
    done
    uci commit firewall
    if command -v fw4 >/dev/null 2>&1; then
        fw4 reload >/dev/null 2>&1
    elif command -v fw3 >/dev/null 2>&1; then
        fw3 reload >/dev/null 2>&1
    elif [ -x /etc/init.d/firewall ]; then
        /etc/init.d/firewall reload >/dev/null 2>&1
    fi
    echo '{"result":"ok","blocked":false}'
}

cmd_set_nickname() {
    local mac="$2"
    local name="$3"
    [ -z "$mac" ] && echo '{"error":"missing mac"}' && return
    local smac=$(echo "$mac" | tr -d ':' | tr 'A-Z' 'a-z')
    local sname="alias_${smac}"

    if [ -z "$name" ]; then
        uci delete guardian."$sname" 2>/dev/null
    else
        uci set guardian."$sname"=alias
        uci set guardian."$sname".mac="$mac"
        uci set guardian."$sname".name="$name"
    fi
    uci commit guardian
    echo '{"result":"ok"}'
}

cmd_reserve_ip() {
    local mac="$2"
    local ip="$3"
    local name="$4"
    [ -z "$mac" ] || [ -z "$ip" ] && echo '{"error":"missing mac or ip"}' && return

    # Clean previous reservation for this mac to avoid duplicates
    for s in $(uci show dhcp 2>/dev/null | grep -i "\.mac='${mac}'" | cut -d. -f2 | cut -d= -f1); do
        uci delete dhcp."$s" 2>/dev/null
    done

    uci add dhcp host >/dev/null
    uci set dhcp.@host[-1].mac="$mac"
    uci set dhcp.@host[-1].ip="$ip"
    [ -n "$name" ] && [ "$name" != "Unknown" ] && uci set dhcp.@host[-1].name="$name"
    uci set dhcp.@host[-1].dns="1"
    uci commit dhcp
    /etc/init.d/dnsmasq reload >/dev/null 2>&1
    echo '{"result":"ok","is_static":true}'
}

cmd_unreserve_ip() {
    local mac="$2"
    [ -z "$mac" ] && echo '{"error":"missing mac"}' && return
    for s in $(uci show dhcp 2>/dev/null | grep -i "\.mac='${mac}'" | cut -d. -f2 | cut -d= -f1); do
        uci delete dhcp."$s" 2>/dev/null
    done
    uci commit dhcp
    /etc/init.d/dnsmasq reload >/dev/null 2>&1
    echo '{"result":"ok","is_static":false}'
}

cmd_adguard_query_log() {
    adguard_api "querylog?limit=50" || echo '{"data":[]}'
}

cmd_adguard_filter_status() {
    adguard_api "filtering/status" || echo '{"filters":[]}'
}

cmd_adguard_filter_refresh() {
    adguard_api "filtering/refresh" "POST" '{"whitelist":false}' || echo '{"error":"failed"}'
}

cmd_test_connection() {
    local host="${2:-$(get_config adguard_host '127.0.0.1')}"
    local port="${3:-$(get_config adguard_port '8080')}"
    local user="${4:-$(get_config adguard_user 'admin')}"
    local pass="${5:-$(get_config adguard_password '')}"

    local res=""
    if [ -n "$user" ] || [ -n "$pass" ]; then
        res=$(curl -s -f -m 5 -u "${user}:${pass}" "http://${host}:${port}/control/status" 2>/dev/null)
    else
        res=$(curl -s -f -m 5 "http://${host}:${port}/control/status" 2>/dev/null)
    fi

    if [ -n "$res" ]; then
        echo "$res"
    else
        echo '{"error":"Connection failed. Check Host, Port, Username, and Password."}'
    fi
}

cmd_firewall_reload() {
    if command -v fw4 >/dev/null 2>&1; then
        fw4 reload >/dev/null 2>&1
    elif command -v fw3 >/dev/null 2>&1; then
        fw3 reload >/dev/null 2>&1
    elif [ -x /etc/init.d/firewall ]; then
        /etc/init.d/firewall reload >/dev/null 2>&1
    fi
    echo '{"result":"ok"}'
}

cmd_daemon() {
    # Background daemon - periodic state refresh
    while true; do
        cmd_status > /dev/null 2>&1
        sleep 30
    done
}

cmd_stop() {
    pkill -f "guardian-action.sh daemon" 2>/dev/null
}

cmd_save_credentials() {
    local u="$2"
    local p="$3"
    cat > /etc/guardian_credentials.json <<ENDJSON
{
    "user": "$u",
    "password": "$p"
}
ENDJSON
    chmod 0600 /etc/guardian_credentials.json 2>/dev/null
    echo '{"result":"ok"}'
}

cmd_retrieve_credentials() {
    local user=""
    local password=""
    local source="none"

    # 1. Dedicated credentials file
    if [ -f "/etc/guardian_credentials.json" ]; then
        user=$(jsonfilter -i "/etc/guardian_credentials.json" -e '@.user' 2>/dev/null)
        password=$(jsonfilter -i "/etc/guardian_credentials.json" -e '@.password' 2>/dev/null)
        if [ -n "$user" ] || [ -n "$password" ]; then
            source="/etc/guardian_credentials.json"
        fi
    fi

    # 2. Check UCI config guardian
    if [ -z "$user" ] && [ -z "$password" ]; then
        user=$(uci -q get guardian.main.adguard_user 2>/dev/null)
        password=$(uci -q get guardian.main.adguard_password 2>/dev/null)
        if [ -n "$user" ] || [ -n "$password" ]; then
            source="/etc/config/guardian"
        fi
    fi

    # 3. Check /etc/config/adguardhome (if present)
    if [ -z "$user" ] && [ -z "$password" ] && [ -f "/etc/config/adguardhome" ]; then
        user=$(uci -q get adguardhome.config.username 2>/dev/null || uci -q get adguardhome.adguardhome.username 2>/dev/null)
        password=$(uci -q get adguardhome.config.password 2>/dev/null || uci -q get adguardhome.adguardhome.password 2>/dev/null)
        if [ -n "$user" ] || [ -n "$password" ]; then
            source="/etc/config/adguardhome"
        fi
    fi

    # 4. Check AdGuardHome.yaml for configured username
    local yaml_file=""
    if [ -f "/etc/adguardhome/adguardhome.yaml" ]; then
        yaml_file="/etc/adguardhome/adguardhome.yaml"
    elif [ -f "/etc/AdGuardHome.yaml" ]; then
        yaml_file="/etc/AdGuardHome.yaml"
    elif [ -f "/etc/adguardhome.yaml" ]; then
        yaml_file="/etc/adguardhome.yaml"
    fi

    if [ -n "$yaml_file" ] && [ -z "$user" ]; then
        user=$(grep -A 4 -i "^users:" "$yaml_file" 2>/dev/null | grep -i "name:" | head -n 1 | awk '{print $NF}' | tr -d '"'\'' ')
        if [ -n "$user" ]; then
            source="$yaml_file"
        fi
    fi

    local found="false"
    if [ -n "$user" ] || [ -n "$password" ]; then
        found="true"
    fi

    cat <<ENDJSON
{
    "found": $found,
    "user": "$user",
    "password": "$password",
    "source": "$source"
}
ENDJSON
}

cmd_adguard_rules() {
    local status=$(adguard_api "filtering/status")
    if [ -n "$status" ]; then
        echo "$status" | jq -c '{result: "ok", rules: (.user_rules // [])}' 2>/dev/null || echo '{"result":"ok","rules":[]}'
    else
        echo '{"result":"error","error":"AdGuard unreachable","rules":[]}'
    fi
}

cmd_adguard_add_rule() {
    local input="$2"
    local rtype="$3"
    [ -z "$input" ] && echo '{"result":"error","error":"Empty rule"}' && return
    local rule="$input"
    if ! echo "$rule" | grep -q '\^' && ! echo "$rule" | grep -q '^\['; then
        rule=$(echo "$rule" | sed -e 's|^https*://||' -e 's|/.*$||')
        if [ "$rtype" = "whitelist" ] || [ "$rtype" = "allow" ]; then
            rule="@@||${rule}^"
        else
            rule="||${rule}^"
        fi
    fi

    local status=$(adguard_api "filtering/status")
    [ -z "$status" ] && echo '{"result":"error","error":"AdGuard unreachable"}' && return

    local payload=$(echo "$status" | jq -c --arg r "$rule" '{rules: (((.user_rules // []) + [$r]) | unique)}' 2>/dev/null)
    if [ -n "$payload" ]; then
        adguard_api "filtering/set_rules" "POST" "$payload" >/dev/null 2>&1
        echo "{\"result\":\"ok\",\"rule\":\"$rule\"}"
    else
        echo '{"result":"error","error":"Failed to build payload"}'
    fi
}

cmd_adguard_delete_rule() {
    local rule="$2"
    [ -z "$rule" ] && echo '{"result":"error","error":"Empty rule"}' && return
    local status=$(adguard_api "filtering/status")
    [ -z "$status" ] && echo '{"result":"error","error":"AdGuard unreachable"}' && return

    local payload=$(echo "$status" | jq -c --arg r "$rule" '{rules: ((.user_rules // []) - [$r])}' 2>/dev/null)
    if [ -n "$payload" ]; then
        adguard_api "filtering/set_rules" "POST" "$payload" >/dev/null 2>&1
        echo "{\"result\":\"ok\",\"rule\":\"$rule\"}"
    else
        echo '{"result":"error","error":"Failed to build payload"}'
    fi
}

cmd_adguard_services_list() {
    local all=$(adguard_api "blocked_services/all")
    if [ -n "$all" ]; then
        echo "$all" | jq -c '{result: "ok", services: (.blocked_services // [])}' 2>/dev/null || echo '{"result":"ok","services":[]}'
    else
        echo '{"result":"error","error":"AdGuard unreachable","services":[]}'
    fi
}

cmd_adguard_client_services() {
    local ip="$2"
    local mac="$3"
    local clients_raw=$(adguard_api "clients")
    if [ -z "$clients_raw" ]; then
        echo '{"result":"error","error":"AdGuard unreachable"}'
        return
    fi

    local client_info=$(echo "$clients_raw" | jq -c --arg ip "$ip" --arg mac "$mac" '
        (.clients // [])[] | select(
            (.ids // []) | any(
                . == $ip or (. | ascii_upcase) == ($mac | ascii_upcase)
            )
        )
    ' 2>/dev/null | head -n 1)

    if [ -n "$client_info" ]; then
        echo "$client_info" | jq -c '{
            result: "ok",
            found: true,
            name: .name,
            blocked_services: (.blocked_services // [])
        }'
    else
        echo '{"result":"ok","found":false,"blocked_services":[]}'
    fi
}

cmd_adguard_set_client_services() {
    local ip="$2"
    local mac="$3"
    local name="$4"
    local services_json="$5"

    [ -z "$name" ] && name="$ip"
    [ -z "$services_json" ] && services_json="[]"

    local clients_raw=$(adguard_api "clients")
    [ -z "$clients_raw" ] && echo '{"result":"error","error":"AdGuard unreachable"}' && return

    local existing_name=$(echo "$clients_raw" | jq -r --arg ip "$ip" --arg mac "$mac" '
        ((.clients // [])[] | select(
            (.ids // []) | any(
                . == $ip or (. | ascii_upcase) == ($mac | ascii_upcase)
            )
        ).name) // empty
    ' 2>/dev/null | head -n 1)

    if [ -n "$existing_name" ]; then
        local payload=$(echo "$clients_raw" | jq -c --arg ename "$existing_name" --argjson svcs "$services_json" '
            {
                name: $ename,
                data: (((.clients // [])[] | select(.name == $ename)) + {
                    blocked_services: $svcs,
                    use_global_blocked_services: false
                })
            }
        ' 2>/dev/null)
        adguard_api "clients/update" "POST" "$payload" >/dev/null 2>&1
        echo "{\"result\":\"ok\",\"action\":\"updated\",\"client\":\"$existing_name\"}"
    else
        local ids_json="[\"$ip\"]"
        [ -n "$mac" ] && ids_json="[\"$ip\",\"$mac\"]"
        local payload=$(jq -nc --arg name "$name" --argjson ids "$ids_json" --argjson svcs "$services_json" '{
            name: $name,
            ids: $ids,
            blocked_services: $svcs,
            use_global_blocked_services: false,
            filtering_enabled: true
        }')
        adguard_api "clients/add" "POST" "$payload" >/dev/null 2>&1
        echo "{\"result\":\"ok\",\"action\":\"added\",\"client\":\"$name\"}"
    fi
}

case "$ACTION" in
    status)                     cmd_status ;;
    adguard_stats)              cmd_adguard_stats ;;
    adguard_toggle)             cmd_adguard_toggle ;;
    adguard_log)                cmd_adguard_query_log ;;
    adguard_filters)            cmd_adguard_filter_status ;;
    adguard_filter_refresh)     cmd_adguard_filter_refresh ;;
    adguard_rules)              cmd_adguard_rules ;;
    adguard_add_rule)           cmd_adguard_add_rule "$@" ;;
    adguard_delete_rule)        cmd_adguard_delete_rule "$@" ;;
    adguard_services_list)      cmd_adguard_services_list ;;
    adguard_client_services)    cmd_adguard_client_services "$@" ;;
    adguard_set_client_services) cmd_adguard_set_client_services "$@" ;;
    test_connection)            cmd_test_connection "$@" ;;
    save_credentials)           cmd_save_credentials "$@" ;;
    retrieve_credentials)       cmd_retrieve_credentials ;;
    firewall_rules)             cmd_firewall_rules ;;
    firewall_zones)             cmd_firewall_zones ;;
    firewall_reload)            cmd_firewall_reload ;;
    clients)                    cmd_clients ;;
    client_block)               cmd_client_block "$@" ;;
    client_unblock)             cmd_client_unblock "$@" ;;
    set_nickname)               cmd_set_nickname "$@" ;;
    reserve_ip)                 cmd_reserve_ip "$@" ;;
    unreserve_ip)               cmd_unreserve_ip "$@" ;;
    daemon)                     cmd_daemon ;;
    stop)                       cmd_stop ;;
    *)
        echo '{"error":"unknown action"}'
        exit 1
        ;;
esac

