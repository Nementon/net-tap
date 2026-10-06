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
