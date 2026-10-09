#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2034 # Platform configuration and state mappings consumed across net-tap scripts
#
# lib/platform_darwin.sh - macOS Darwin / XNU Platform Implementation (Profile 2: Tactical Lab Discovery)
# Part of Net-Tap Carrier-Grade Passive Monitor & Telemetry Suite.
#

set -euo pipefail

platform_verify_dependencies() {
    local missing=()
    for cmd in tcpdump awk grep sed find df du mktemp gzip sysctl stat date python3 ifconfig netstat; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_err "Missing required macOS dependencies: ${missing[*]}"
        exit 1
    fi
    if ! command -v pfctl >/dev/null 2>&1; then
        log_warn "pfctl not found. Packet Filter egress drop rules cannot be configured."
    fi
    if ! command -v flock >/dev/null 2>&1; then
        log_info "util-linux flock not found; net-tap will use atomic directory session locking."
    fi
}

platform_detect_port_status() {
    local target_iface="$1"
    local if_out
    if_out=$(ifconfig "${target_iface}" 2>/dev/null || true)
    if [[ -z "${if_out}" ]]; then
        echo "INACTIVE|N/A|N/A|down"
        return
    fi

    local status="INACTIVE"
    local operstate="down"
    local speed="N/A"
    local duplex="N/A"

    if echo "${if_out}" | grep -q "status: active"; then
        status="ACTIVE"
    fi
    if echo "${if_out}" | grep -qE "flags=[0-9a-f]+<.*UP.*>"; then
        operstate="up"
    fi

    local media_line
    media_line=$(echo "${if_out}" | awk -F': ' '/media:/ {print $2}')
    if [[ -n "${media_line}" ]]; then
        if [[ "${media_line}" =~ ([0-9]+(\.[0-9]+)?[a-zA-Z]*base[A-Za-z0-9-]+) ]]; then
            local raw_speed="${BASH_REMATCH[1]}"
            case "${raw_speed}" in
                10base*)   speed="10Mb/s" ;;
                100base*)  speed="100Mb/s" ;;
                1000base*) speed="1000Mb/s" ;;
                2500base*|2.5Gbase*) speed="2500Mb/s" ;;
                5000base*|5Gbase*)   speed="5000Mb/s" ;;
                10Gbase*)  speed="10000Mb/s" ;;
                25Gbase*)  speed="25000Mb/s" ;;
                40Gbase*)  speed="40000Mb/s" ;;
                100Gbase*) speed="100000Mb/s" ;;
                *) speed="${raw_speed}" ;;
            esac
        fi
        if [[ "${media_line}" =~ full-duplex ]]; then
            duplex="Full"
        elif [[ "${media_line}" =~ half-duplex ]]; then
            duplex="Half"
        fi
    fi

    if [[ "${status}" == "ACTIVE" ]]; then
        echo "ACTIVE|${speed}|${duplex}|${operstate}"
    else
        echo "INACTIVE|N/A|N/A|${operstate}"
    fi
}

darwin_enable_pf_drop() {
    local iface="$1"
    if command -v pfctl >/dev/null 2>&1; then
        pfctl -E 2>/dev/null || true
        printf "block drop out quick on %s all\n" "${iface}" | pfctl -a "net_tap_${iface}" -f - 2>/dev/null || {
            log_warn "Failed to apply PF egress block anchor for '${iface}'."
        }
        log_ok "PF egress block anchor enabled on '${iface}' (best-effort host silencing)."
    fi
}

darwin_disable_pf_drop() {
    local iface="$1"
    if command -v pfctl >/dev/null 2>&1; then
        pfctl -a "net_tap_${iface}" -F all 2>/dev/null || true
    fi
}

platform_restore_interface_state() {
    local iface="$1"
    darwin_disable_pf_drop "${iface}"
    ifconfig "${iface}" -promisc 2>/dev/null || true
}

platform_stat_owner() {
    local target="$1"
    local res
    res=$(stat -f "%u" "${target}" 2>/dev/null || true)
    if [[ -n "${res}" && "${res}" =~ ^[0-9]+$ ]]; then
        echo "${res}"
        return
    fi
    python3 -c "import os, sys; print(os.stat(sys.argv[1]).st_uid)" "${target}" 2>/dev/null || echo "-1"
}

platform_stat_perm() {
    local target="$1"
    local p=""
    p=$(stat -f "%OLp" "${target}" 2>/dev/null || true)
    p="${p#0}"
    if [[ -n "$p" && "$p" =~ ^[0-7]+$ ]]; then
        echo "$p"
        return
    fi
    p=$(python3 -c "import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])" "${target}" 2>/dev/null || echo "777")
    echo "${p:-777}"
}

platform_stat_nlinks() {
    local target="$1"
    local res
    res=$(stat -f "%l" "${target}" 2>/dev/null || true)
    if [[ -n "${res}" && "${res}" =~ ^[0-9]+$ ]]; then
        echo "${res}"
        return
    fi
    python3 -c "import os, sys; print(os.stat(sys.argv[1]).st_nlink)" "${target}" 2>/dev/null || echo "0"
}

platform_stat_mtime() {
    local target="$1"
    local res
    res=$(stat -f "%m" "${target}" 2>/dev/null || true)
    if [[ -n "${res}" && "${res}" =~ ^[0-9]+$ ]]; then
        echo "${res}"
        return
    fi
    python3 -c "import os, sys; print(int(os.path.getmtime(sys.argv[1])))" "${target}" 2>/dev/null || echo "0"
}

platform_proc_starttime() {
    local pid="$1"
    [[ -z "${pid}" ]] && return 0
    ps -p "${pid}" -o lstart= 2>/dev/null | tr -s ' ' || echo ""
}

platform_proc_comm() {
    local pid="$1"
    [[ -z "${pid}" ]] && return 0
    ps -p "${pid}" -o comm= 2>/dev/null | xargs basename 2>/dev/null || echo ""
}

platform_proc_cmdline() {
    local pid="$1"
    [[ -z "${pid}" ]] && return 0
    ps -p "${pid}" -o command= 2>/dev/null || echo ""
}

# --- Darwin Exec Platform Hooks ---

darwin_setup_exec_pf_group() {
    local iface="$1"
    local group_name="${2:-_nettap_active}"
    local vlan_if="${3:-}"

    if ! command -v pfctl >/dev/null 2>&1; then
        return 0
    fi

    local iface_list="${iface}"
    if [[ -n "${vlan_if}" ]]; then
        iface_list="{ ${iface}, ${vlan_if} }"
    fi

    # Synthesize pass rules for active net-tap TOS 0x38 and GID, and drop everything else
    local pf_rules
    pf_rules=$(printf "pass out quick on %s proto { tcp, udp, icmp, icmp6 } tos 0x38\npass out quick on %s proto { tcp, udp, icmp, icmp6 } group %s\nblock drop out quick on %s all\n" \
               "${iface_list}" "${iface_list}" "${group_name}" "${iface}")

    echo "${pf_rules}" | pfctl -a "net_tap_${iface}" -f - 2>/dev/null || {
        log_warn "Failed to apply PF anchor rules for group ${group_name} on ${iface}."
    }
}

darwin_teardown_exec_pf_group() {
    local iface="$1"
    if command -v pfctl >/dev/null 2>&1; then
        # Restore default active-session drop rules
        darwin_enable_pf_drop "${iface}"
    fi
}

darwin_setup_exec_vlan() {
    local iface="$1"
    local vlan="$2"
    local vlan_if="vlan${vlan}"

    ifconfig "${vlan_if}" create 2>/dev/null || true
    ifconfig "${vlan_if}" vlan "${vlan}" vlandev "${iface}" 2>/dev/null || true
    ifconfig "${vlan_if}" up 2>/dev/null || true

    echo "${vlan_if}"
}

darwin_teardown_exec_vlan() {
    local vlan_if="$1"
    if [[ -n "${vlan_if}" ]]; then
        ifconfig "${vlan_if}" destroy 2>/dev/null || true
    fi
}

darwin_adjust_baby_giant_mtu() {
    local iface="$1"
    local overhead="${2:-4}"
    local cur_mtu
    cur_mtu=$(ifconfig "${iface}" 2>/dev/null | awk '/mtu / {print $NF}' || echo "1500")

    local required_mtu=$((1500 + overhead))
    if [[ "${cur_mtu}" =~ ^[0-9]+$ && "${cur_mtu}" -lt "${required_mtu}" ]]; then
        ifconfig "${iface}" mtu "${required_mtu}" 2>/dev/null || true
        echo "${cur_mtu}"
    else
        echo ""
    fi
}

darwin_restore_baby_giant_mtu() {
    local iface="$1"
    local orig_mtu="$2"
    if [[ -n "${orig_mtu}" && "${orig_mtu}" =~ ^[0-9]+$ ]]; then
        ifconfig "${iface}" mtu "${orig_mtu}" 2>/dev/null || true
    fi
}
