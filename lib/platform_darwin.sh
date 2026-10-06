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

platform_stat_owner() {
    local target="$1"
    stat -f "%u" "${target}" 2>/dev/null || python3 -c "import os, sys; print(os.stat(sys.argv[1]).st_uid)" "${target}" 2>/dev/null || echo "-1"
}

platform_stat_perm() {
    local target="$1"
    local p=""
    p=$(stat -f "%OLp" "${target}" 2>/dev/null || true)
    p="${p#0}"
    if [[ -z "$p" ]]; then
        p=$(python3 -c "import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])" "${target}" 2>/dev/null || echo "777")
    fi
    echo "${p:-777}"
}

platform_stat_nlinks() {
    local target="$1"
    stat -f "%l" "${target}" 2>/dev/null || python3 -c "import os, sys; print(os.stat(sys.argv[1]).st_nlink)" "${target}" 2>/dev/null || echo "0"
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
