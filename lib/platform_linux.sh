#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2034 # Platform configuration and state mappings consumed across net-tap scripts
#
# lib/platform_linux.sh - Linux Platform Implementation (Profile 1: Carrier-Grade Stealth Engine)
# Part of Net-Tap Carrier-Grade Passive Monitor & Telemetry Suite.
#

set -euo pipefail

platform_verify_dependencies() {
    local missing=()
    for cmd in ip tc tcpdump ethtool awk dmesg grep sed find ss df du mktemp readlink gzip flock sysctl stat date python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_err "Missing required dependencies: ${missing[*]}"
        exit 1
    fi
}

platform_detect_port_status() {
    local target_iface="$1"
    local carrier_file="/sys/class/net/${target_iface}/carrier"
    local operstate_file="/sys/class/net/${target_iface}/operstate"
    local carrier="0"
    local operstate="down"
    local ethtool_link="no"
    local speed="N/A"
    local duplex="N/A"

    if cmd_netns test -f "${carrier_file}"; then
        carrier=$(cmd_netns cat "${carrier_file}" 2>/dev/null || echo "0")
    fi
    if cmd_netns test -f "${operstate_file}"; then
        operstate=$(cmd_netns cat "${operstate_file}" 2>/dev/null || echo "unknown")
    fi

    if command -v ethtool &>/dev/null; then
        local eth_out
        eth_out=$(cmd_netns ethtool "${target_iface}" 2>/dev/null || true)
        if echo "${eth_out}" | grep -q "Link detected: yes"; then
            ethtool_link="yes"
        fi
        speed=$(echo "${eth_out}" | awk -F': ' '/Speed:/ {print $2}')
        duplex=$(echo "${eth_out}" | awk -F': ' '/Duplex:/ {print $2}')
        speed="${speed:-N/A}"
        duplex="${duplex:-N/A}"
    fi

    # Evaluate Combined Port State
    if [[ "${carrier}" == "1" || "${ethtool_link}" == "yes" ]]; then
        echo "ACTIVE|${speed}|${duplex}|${operstate}"
    else
        echo "INACTIVE|N/A|N/A|${operstate}"
    fi
}

platform_stat_owner() {
    stat -c "%u" "$1" 2>/dev/null || echo "-1"
}

platform_stat_perm() {
    stat -c "%a" "$1" 2>/dev/null || echo "777"
}

platform_stat_nlinks() {
    stat -c "%h" "$1" 2>/dev/null || echo "0"
}

platform_stat_mtime() {
    stat -c "%Y" "$1" 2>/dev/null || echo "0"
}

platform_proc_starttime() {
    local pid="$1"
    [[ -z "${pid}" || ! -d "/proc/${pid}" ]] && return 0
    awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null || echo ""
}

platform_proc_comm() {
    local pid="$1"
    [[ -z "${pid}" || ! -d "/proc/${pid}" ]] && return 0
    cat "/proc/${pid}/comm" 2>/dev/null || echo ""
}

platform_proc_cmdline() {
    local pid="$1"
    [[ -z "${pid}" || ! -d "/proc/${pid}" ]] && return 0
    tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo ""
}

# --- Linux Exec Platform Hooks ---

linux_setup_exec_cgroup() {
    local session_id="$1"
    local user_uid="${2:-0}"
    local user_gid="${3:-0}"
    local cgroup_base="/sys/fs/cgroup"
    local cgroup_dir="${cgroup_base}/net-tap/${session_id}"

    if [[ ! -f "${cgroup_base}/cgroup.controllers" ]]; then
        return 0
    fi

    mkdir -p "${cgroup_dir}" 2>/dev/null || return 0
    if [[ "${user_uid}" -ne 0 ]]; then
        chown "${user_uid}:${user_gid}" "${cgroup_dir}/cgroup.procs" 2>/dev/null || true
    fi
    echo "${cgroup_dir}"
}

linux_teardown_exec_cgroup() {
    local session_id="$1"
    local cgroup_dir="/sys/fs/cgroup/net-tap/${session_id}"

    [[ ! -d "${cgroup_dir}" ]] && return 0

    # 1. Freeze remaining processes in cgroup
    if [[ -f "${cgroup_dir}/cgroup.freeze" ]]; then
        echo "1" > "${cgroup_dir}/cgroup.freeze" 2>/dev/null || true
    fi

    # 2. Terminate any residual orphaned processes
    if [[ -f "${cgroup_dir}/cgroup.procs" ]]; then
        while read -r pid; do
            if [[ -n "$pid" ]]; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        done < "${cgroup_dir}/cgroup.procs"
    fi

    # 3. Unfreeze to allow kernel to reap zombies
    if [[ -f "${cgroup_dir}/cgroup.freeze" ]]; then
        echo "0" > "${cgroup_dir}/cgroup.freeze" 2>/dev/null || true
    fi

    rmdir "${cgroup_dir}" 2>/dev/null || true
}

linux_setup_exec_netfilter() {
    local iface="$1"
    local session_id="$2"
    local mark="${3:-0x7a9}"
    local dscp="${4:-CS7}"
    local chain="NETTAP_EXEC_${session_id}"

    # 1. Raw table: Bypass raw output drop rule for session cgroup
    iptables -t raw -I OUTPUT 1 -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j ACCEPT 2>/dev/null || true
    ip6tables -t raw -I OUTPUT 1 -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j ACCEPT 2>/dev/null || true

    # 2. Mangle table: Setup isolated chain for session fwmark and DSCP tagging
    iptables -t mangle -N "${chain}" 2>/dev/null || iptables -t mangle -F "${chain}" 2>/dev/null || true
    iptables -t mangle -A "${chain}" -j MARK --set-mark "${mark}" 2>/dev/null || true
    if [[ -n "${dscp}" ]]; then
        iptables -t mangle -A "${chain}" -j DSCP --set-dscp-class "${dscp}" 2>/dev/null || true
    fi
    iptables -t mangle -I OUTPUT 1 -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j "${chain}" 2>/dev/null || true

    ip6tables -t mangle -N "${chain}" 2>/dev/null || ip6tables -t mangle -F "${chain}" 2>/dev/null || true
    ip6tables -t mangle -A "${chain}" -j MARK --set-mark "${mark}" 2>/dev/null || true
    if [[ -n "${dscp}" ]]; then
        ip6tables -t mangle -A "${chain}" -j DSCP --set-dscp-class "${dscp}" 2>/dev/null || true
    fi
    ip6tables -t mangle -I OUTPUT 1 -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j "${chain}" 2>/dev/null || true
}

linux_teardown_exec_netfilter() {
    local iface="$1"
    local session_id="$2"
    local chain="NETTAP_EXEC_${session_id}"

    # 1. Remove raw bypass rules
    iptables -t raw -D OUTPUT -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j ACCEPT 2>/dev/null || true
    ip6tables -t raw -D OUTPUT -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j ACCEPT 2>/dev/null || true

    # 2. Unlink and flush mangle chains
    iptables -t mangle -D OUTPUT -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j "${chain}" 2>/dev/null || true
    iptables -t mangle -F "${chain}" 2>/dev/null || true
    iptables -t mangle -X "${chain}" 2>/dev/null || true

    ip6tables -t mangle -D OUTPUT -o "${iface}" -m cgroup --path "net-tap/${session_id}" -j "${chain}" 2>/dev/null || true
    ip6tables -t mangle -F "${chain}" 2>/dev/null || true
    ip6tables -t mangle -X "${chain}" 2>/dev/null || true
}

linux_setup_exec_vlan_netns() {
    local iface="$1"
    local vlan="$2"
    local session_id="$3"
    local ip_cidr="${4:-}"
    local ip6_cidr="${5:-}"
    local netns="nettap_exec_${session_id}_$$"

    ip netns add "${netns}"
    ip link add link "${iface}" name "${iface}.${vlan}" type vlan id "${vlan}"
    ip link set "${iface}.${vlan}" netns "${netns}"
    ip -n "${netns}" link set lo up
    ip -n "${netns}" link set "${iface}.${vlan}" up

    if [[ -n "${ip_cidr}" ]]; then
        ip -n "${netns}" addr add "${ip_cidr}" dev "${iface}.${vlan}" 2>/dev/null || true
    fi
    if [[ -n "${ip6_cidr}" ]]; then
        ip -n "${netns}" addr add "${ip6_cidr}" dev "${iface}.${vlan}" 2>/dev/null || true
    fi

    echo "${netns}"
}

linux_teardown_exec_vlan_netns() {
    local netns="$1"
    if [[ -n "${netns}" ]]; then
        ip netns del "${netns}" 2>/dev/null || true
    fi
}

linux_setup_exec_vlan_tc() {
    local iface="$1"
    local vlan="$2"
    local pcp="${3:-7}"
    local mark="${4:-0x7a9}"
    local s_tag="${5:-}"
    local c_tag="${6:-}"

    if [[ -n "${s_tag}" && -n "${c_tag}" ]]; then
        # QinQ double-tagging action chain
        tc filter add dev "${iface}" egress pref 5 protocol all handle "${mark}" fw \
            action vlan push id "${s_tag}" protocol 802.1ad priority "${pcp}" \
            action vlan push id "${c_tag}" protocol 802.1q priority "${pcp}" \
            action pass 2>/dev/null || true
        tc filter add dev "${iface}" ingress pref 5 protocol 802.1ad basic \
            match 'vlan id '"${s_tag}" action vlan pop action vlan pop action pass 2>/dev/null || true
    else
        # Single 802.1Q tagging action
        tc filter add dev "${iface}" egress pref 5 protocol all handle "${mark}" fw \
            action vlan push id "${vlan}" priority "${pcp}" action pass 2>/dev/null || true
        tc filter add dev "${iface}" ingress pref 5 protocol 802.1q basic \
            match 'vlan id '"${vlan}" action vlan pop action pass 2>/dev/null || true
    fi
}

linux_teardown_exec_vlan_tc() {
    local iface="$1"
    local mark="${2:-0x7a9}"
    tc filter del dev "${iface}" egress pref 5 handle "${mark}" fw 2>/dev/null || true
    tc filter del dev "${iface}" ingress pref 5 2>/dev/null || true
}

linux_adjust_baby_giant_mtu() {
    local iface="$1"
    local overhead="${2:-4}"
    local cur_mtu
    cur_mtu=$(ip -j link show dev "${iface}" 2>/dev/null | jq -r '.[0].mtu' 2>/dev/null || cat "/sys/class/net/${iface}/mtu" 2>/dev/null || echo "1500")

    local required_mtu=$((1500 + overhead))
    if [[ "${cur_mtu}" =~ ^[0-9]+$ && "${cur_mtu}" -lt "${required_mtu}" ]]; then
        ip link set dev "${iface}" mtu "${required_mtu}" 2>/dev/null || true
        echo "${cur_mtu}"
    else
        echo ""
    fi
}

linux_restore_baby_giant_mtu() {
    local iface="$1"
    local orig_mtu="$2"
    if [[ -n "${orig_mtu}" && "${orig_mtu}" =~ ^[0-9]+$ ]]; then
        ip link set dev "${iface}" mtu "${orig_mtu}" 2>/dev/null || true
    fi
}
