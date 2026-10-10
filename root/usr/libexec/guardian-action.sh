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
    local ag_version="N/A"
    local ag_stats="{}"
    if [ "$adguard_enabled" = "1" ]; then
        local ag_info
        ag_info=$(adguard_api "status")
        if [ -n "$ag_info" ]; then
            ag_status="online"
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
    local current=$(adguard_api "status" | jsonfilter -e '@.protection_enabled' 2>/dev/null)
    if [ "$current" = "true" ]; then
        adguard_api "protection" "POST" '{"enabled":false}'
    else
        adguard_api "protection" "POST" '{"enabled":true}'
    fi
    echo '{"result":"ok"}'
}

cmd_test_connection() {
    local host="${2:-$(get_config adguard_host "127.0.0.1")}"
    local port="${3:-$(get_config adguard_port "8080")}"
    local user="${4:-$(get_config adguard_user "admin")}"
    local pass="${5:-$(get_config adguard_password "")}"

    local res
    res=$(curl -s -f -m 5 -u "${user}:${pass}" "http://${host}:${port}/control/status" 2>/dev/null)
    if [ -n "$res" ]; then
        echo "$res"
    else
        echo "{\"error\":\"Unable to connect to AdGuard Home at http://${host}:${port}. Check host, port, or credentials.\"}"
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

cmd_clients() {
    local result="["
    local first=1
    # Parse ARP table
    while IFS= read -r line; do
        echo "$line" | grep -qE "^[0-9]" || continue
        local ip=$(echo "$line" | awk '{print $1}')
        local mac=$(echo "$line" | awk '{print $4}')
        local iface=$(echo "$line" | awk '{print $6}')
        [ "$mac" = "00:00:00:00:00:00" ] && continue
        # Get hostname from DHCP leases
        local hostname=$(grep -i "$mac" /tmp/dhcp.leases 2>/dev/null | awk '{print $4}' | head -1)
        [ -z "$hostname" ] || [ "$hostname" = "*" ] && hostname="Unknown"
        [ $first -eq 0 ] && result="${result},"
        result="${result}{\"ip\":\"${ip}\",\"mac\":\"${mac}\",\"hostname\":\"${hostname}\",\"iface\":\"${iface}\"}"
        first=0
    done < /proc/net/arp
    echo "${result}]"
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

case "$ACTION" in
    status)                 cmd_status ;;
    adguard_stats)          cmd_adguard_stats ;;
    adguard_toggle)         cmd_adguard_toggle ;;
    adguard_log)            cmd_adguard_query_log ;;
    adguard_filters)        cmd_adguard_filter_status ;;
    adguard_filter_refresh) cmd_adguard_filter_refresh ;;
    test_connection)        cmd_test_connection "$@" ;;
    save_credentials)       cmd_save_credentials "$@" ;;
    retrieve_credentials)   cmd_retrieve_credentials ;;
    firewall_rules)         cmd_firewall_rules ;;
    firewall_zones)         cmd_firewall_zones ;;
    firewall_reload)        cmd_firewall_reload ;;
    clients)                cmd_clients ;;
    daemon)                 cmd_daemon ;;
    stop)                   cmd_stop ;;
    *)
        echo '{"error":"unknown action"}'
        exit 1
        ;;
esac

