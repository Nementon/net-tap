#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2317,SC2015,SC1091,SC2086

# --- Function: Comprehensive Physical Link Detection ---
detect_port_status() {
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

# --- Helper: Unified Interface State Restorer ---
restore_interface_state() {
    local iface="$1"
    # 1. Down interface first to eliminate packet leaks during re-configuration
    cmd_netns ip link set dev "${iface}" down 2>/dev/null || true

    cmd_netns ip link set dev "${iface}" promisc "${ORIG_PROMISC[$iface]:-off}" 2>/dev/null || true
    cmd_netns ip link set dev "${iface}" arp "${ORIG_ARP[$iface]:-on}" 2>/dev/null || true

    if [[ -n "${ORIG_MTU[$iface]:-}" ]]; then
        cmd_netns ip link set dev "${iface}" mtu "${ORIG_MTU[$iface]}" 2>/dev/null || true
    fi

    cmd_netns ip link set dev "${iface}" txqueuelen "${ORIG_TXQLEN[$iface]:-1000}" 2>/dev/null || true

    if [[ -n "${ORIG_RX_RING[$iface]:-}" ]]; then
        cmd_netns ethtool -G "${iface}" rx "${ORIG_RX_RING[$iface]}" 2>/dev/null || true
    fi

    for feat in gro lro tso gso rx rxvlan rx-vlan-filter rx-all; do
        local var_feat="ORIG_${feat^^}"
        var_feat="${var_feat//-/_}"
        local -n map_ref="${var_feat}"
        local val="${map_ref[$iface]:-}"
        if [[ -n "${val}" ]]; then
            cmd_netns ethtool -K "${iface}" "${feat}" "${val}" 2>/dev/null || true
        fi
    done

    cmd_netns ethtool -A "${iface}" autoneg "${ORIG_PAUSE_AUTONEG[$iface]:-on}" rx "${ORIG_PAUSE_RX[$iface]:-on}" tx "${ORIG_PAUSE_TX[$iface]:-on}" 2>/dev/null || true
    cmd_netns ethtool --set-eee "${iface}" eee "${ORIG_EEE[$iface]:-on}" 2>/dev/null || true
    cmd_netns ethtool --set-priv-flags "${iface}" disable-fw-lldp off 2>/dev/null || true

    # Non-destructive IPv6 & IPv4 sysctl restoration
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.keep_addr_on_down=${ORIG_IPV6_KEEP_ADDR[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.disable_ipv6=${ORIG_IPV6_DISABLE[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.router_solicitations=${ORIG_IPV6_RS[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_dad=${ORIG_IPV6_DAD[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.dad_transmits=${ORIG_IPV6_DADT[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_ra=${ORIG_IPV6_RA[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.autoconf=${ORIG_IPV6_AUTOCONF[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.addr_gen_mode=${ORIG_IPV6_ADDR_GEN[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.use_tempaddr=${ORIG_IPV6_TEMP[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.enhanced_dad=${ORIG_IPV6_EDAD[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.ndisc_notify=${ORIG_IPV6_NDISC[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_redirects=${ORIG_IPV6_REDIR[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.mldv1_unsolicited_report_interval=${ORIG_MLDV1_INTVAL[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.mldv2_unsolicited_report_interval=${ORIG_MLDV2_INTVAL[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.force_mld_version=${ORIG_MLD_VER[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.drop_unsolicited_na=${ORIG_DROP_UNA[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_untracked_na=${ORIG_ACCEPT_UNA[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.forwarding=${ORIG_IPV6_FWD[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.mc_forwarding=${ORIG_IPV6_MC_FWD[$iface]:-0}" 2>/dev/null || true

    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_ignore=${ORIG_ARP_IGNORE[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_announce=${ORIG_ARP_ANNOUNCE[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_filter=${ORIG_ARP_FILTER[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_notify=${ORIG_ARP_NOTIFY[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.drop_gratuitous_arp=${ORIG_DROP_GARP[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_accept=${ORIG_ARP_ACCEPT[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.proxy_arp=${ORIG_PROXY_ARP[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.proxy_arp_pvlan=${ORIG_PROXY_ARP_PVLAN[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.send_redirects=${ORIG_SEND_REDIRECTS[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.accept_redirects=${ORIG_ACCEPT_REDIRECTS[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.secure_redirects=${ORIG_SECURE_REDIRECTS[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.drop_unicast_in_l2_multicast=${ORIG_DROP_UNICAST_L2M[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.igmpv2_unsolicited_report_interval=${ORIG_IGMPV2_INTVAL[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.igmpv3_unsolicited_report_interval=${ORIG_IGMPV3_INTVAL[$iface]:-1}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.force_igmp_version=${ORIG_IGMP_VER[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.forwarding=${ORIG_IPV4_FWD[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.mc_forwarding=${ORIG_IPV4_MC_FWD[$iface]:-0}" 2>/dev/null || true
    cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.bc_forwarding=${ORIG_IPV4_BC_FWD[$iface]:-0}" 2>/dev/null || true

    # Clean up conntrack NOTRACK and raw OUTPUT drop rules
    if command -v iptables >/dev/null 2>&1; then
        cmd_netns iptables -t raw -D PREROUTING -i "${iface}" -j NOTRACK 2>/dev/null || true
        cmd_netns iptables -t raw -D OUTPUT -o "${iface}" -j NOTRACK 2>/dev/null || true
        cmd_netns iptables -t raw -D OUTPUT -o "${iface}" -j DROP 2>/dev/null || true
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        cmd_netns ip6tables -t raw -D PREROUTING -i "${iface}" -j NOTRACK 2>/dev/null || true
        cmd_netns ip6tables -t raw -D OUTPUT -o "${iface}" -j NOTRACK 2>/dev/null || true
        cmd_netns ip6tables -t raw -D OUTPUT -o "${iface}" -j DROP 2>/dev/null || true
    fi

    # Restore NetworkManager management if we unmanaged it
    if [[ "${ORIG_NM_MANAGED[$iface]:-}" == "unmanaged" ]] && command -v nmcli >/dev/null 2>&1; then
        cmd_netns nmcli device set "${iface}" managed yes 2>/dev/null || true
    fi

    if [[ "${HW_TYPE:-}" == "sfp" ]]; then
        cmd_netns ethtool -s "${iface}" autoneg on 2>/dev/null || true
    fi

    # Zero-Egress Hardening: Interface is kept DOWN to eliminate temporal packet emission
    cmd_netns ip link set dev "${iface}" down 2>/dev/null || true
    # Remove egress drop qdisc ONLY after interface is down and settings restored
    cmd_netns tc qdisc del dev "${iface}" clsact 2>/dev/null || true
    log_warn "Interface '${iface}' has been restored and left DOWN to prevent packet emission onto the monitored link."
}

# --- Background Worker Functions (Prevents subshell crashes under set -e) ---
_autoshutdown_worker() {
    local dur="$1" ifc="$2" ns="${3:-}" script="${4:-$(readlink -f "$0")}" stfile="$5"
    local sleep_pid=""
    trap '[[ -n "${sleep_pid}" ]] && kill -TERM "${sleep_pid}" 2>/dev/null || true; exit 0' TERM INT HUP EXIT
    for fd_path in /proc/self/fd/*; do
        local fd="${fd_path##*/}"
        if [[ "$fd" =~ ^[0-9]+$ ]] && [[ "$fd" -ge 3 ]]; then
            eval "exec ${fd}>&-" 2>/dev/null || true
        fi
    done
    sleep "${dur}" &
    sleep_pid=$!
    wait "${sleep_pid}" 2>/dev/null || true
    if [[ -f "${stfile}" ]]; then
        if command -v logger >/dev/null 2>&1; then logger -t net-tap "Auto-shutdown triggered for ${ifc}"; fi
        local netns_cmd=()
        if [[ -n "${ns}" ]]; then netns_cmd=(-n "${ns}"); fi
        "${script}" off -i "${ifc}" "${netns_cmd[@]}" >/dev/null 2>&1 || true
    fi
}

_disk_watchdog_worker() {
    local thresh="$1" outdir="$2" ifc="$3" ns="${4:-}" script="${5:-$(readlink -f "$0")}" stfile="$6" rot_count="${7:-10}" capture_pids="${8:-}"
    local sleep_pid=""
    trap '[[ -n "${sleep_pid}" ]] && kill -TERM "${sleep_pid}" 2>/dev/null || true; exit 0' TERM INT HUP EXIT
    for fd_path in /proc/self/fd/*; do
        local fd="${fd_path##*/}"
        if [[ "$fd" =~ ^[0-9]+$ ]] && [[ "$fd" -ge 3 ]]; then
            eval "exec ${fd}>&-" 2>/dev/null || true
        fi
    done
    while [[ -f "${stfile}" ]]; do
        sleep 2 &
        sleep_pid=$!
        wait "${sleep_pid}" 2>/dev/null || true

        # Ring-buffer retention enforcement for compressed and uncompressed chunks:
        # Prevents unbound accumulation of rotated files when using -z gzip
        IFS=',' read -ra ifc_arr <<< "${ifc}"
        for dev in "${ifc_arr[@]}"; do
            local chunk_files=()
            while IFS= read -r f; do
                [[ -f "$f" ]] && chunk_files+=("$f")
            done < <(ls -1t "${outdir}"/*_"${dev}"_trace.pcap* 2>/dev/null || true)
            if [[ ${#chunk_files[@]} -gt ${rot_count} ]]; then
                for ((idx=rot_count; idx<${#chunk_files[@]}; idx++)); do
                    rm -f "${chunk_files[$idx]}" 2>/dev/null || true
                done
            fi
        done

        # Monitor tcpdump process liveness if PIDs are provided
        if [[ -n "${capture_pids}" ]]; then
            local any_alive=0
            for tpid in ${capture_pids}; do
                if kill -0 "${tpid}" 2>/dev/null && grep -q "tcpdump" "/proc/${tpid}/comm" 2>/dev/null; then
                    any_alive=1
                    break
                fi
            done
            if [[ ${any_alive} -eq 0 ]]; then
                if command -v logger >/dev/null 2>&1; then logger -t net-tap "CRITICAL: All capture processes for ${ifc} terminated unexpectedly. Triggering emergency teardown."; fi
                local netns_cmd=()
                if [[ -n "${ns}" ]]; then netns_cmd=(-n "${ns}"); fi
                "${script}" off -i "${ifc}" "${netns_cmd[@]}" >/dev/null 2>&1 || true
                break
            fi
        fi

        local df_stats current_usage avail_mb
        df_stats=$(df -Pm "${outdir}" 2>/dev/null | awk 'NR==2 {gsub(/%/, "", $5); print $5, $4}')
        read -r current_usage avail_mb <<< "${df_stats:-0 999999}"
        if [[ "${current_usage}" -ge "${thresh}" ]] || [[ "${avail_mb}" -le 1024 ]]; then
            if command -v logger >/dev/null 2>&1; then logger -t net-tap "CRITICAL: Storage threshold reached (${current_usage}% >= ${thresh}% or ${avail_mb}MB <= 1024MB). Triggering emergency shutdown for ${ifc}."; fi
            local netns_cmd=()
            if [[ -n "${ns}" ]]; then netns_cmd=(-n "${ns}"); fi
            "${script}" off -i "${ifc}" "${netns_cmd[@]}" >/dev/null 2>&1 || true
            break
        fi
    done
}

# --- Function: Enable Silent Tap Mode ---
start_tap() {
    require_root
    verify_dependencies

    if [[ -z "${IFACE}" ]]; then
        log_err "Interface (-i <interface>) is required."
        exit 1
    fi

    acquire_lock "${IFACE}"

    if [[ -f "${STATE_FILE}" ]]; then
        log_warn "A monitoring session is already active for ${IFACE}."
        release_lock
        exit 1
    fi

    local tmp_state=""
    local SETUP_SUCCESS=0
    local STATE_FILE_CREATED=0
    local -a IFACES_ARR=()
    local -a CONFIGURED_IFACES=()
    
    local -A ORIG_PROMISC=() ORIG_ARP=() ORIG_MTU=() ORIG_TXQLEN=() ORIG_RX_RING=() ORIG_GRO=() ORIG_LRO=() ORIG_TSO=() ORIG_GSO=() ORIG_RX=() ORIG_RXVLAN=() ORIG_RX_VLAN_FILTER=() ORIG_RX_ALL=()
    local -A ORIG_IPV6_DISABLE=() ORIG_IPV6_KEEP_ADDR=() ORIG_IPV6_ADDR_GEN=() ORIG_IPV6_DAD=() ORIG_IPV6_DADT=() ORIG_IPV6_RA=() ORIG_IPV6_RS=() ORIG_IPV6_AUTOCONF=() ORIG_IPV6_TEMP=() ORIG_IPV6_EDAD=() ORIG_IPV6_NDISC=() ORIG_IPV6_REDIR=()
    local -A ORIG_MLDV1_INTVAL=() ORIG_MLDV2_INTVAL=() ORIG_MLD_VER=() ORIG_DROP_UNA=() ORIG_ACCEPT_UNA=() ORIG_IPV6_FWD=() ORIG_IPV6_MC_FWD=()
    local -A ORIG_ARP_IGNORE=() ORIG_ARP_ANNOUNCE=() ORIG_ARP_FILTER=() ORIG_ARP_NOTIFY=() ORIG_DROP_GARP=() ORIG_ARP_ACCEPT=() ORIG_PROXY_ARP=() ORIG_PROXY_ARP_PVLAN=() ORIG_SEND_REDIRECTS=() ORIG_ACCEPT_REDIRECTS=() ORIG_SECURE_REDIRECTS=() ORIG_DROP_UNICAST_L2M=()
    local -A ORIG_IGMPV2_INTVAL=() ORIG_IGMPV3_INTVAL=() ORIG_IGMP_VER=() ORIG_IPV4_FWD=() ORIG_IPV4_MC_FWD=() ORIG_IPV4_BC_FWD=() ORIG_OPERSTATE=()
    local -A ORIG_PAUSE_AUTONEG=() ORIG_PAUSE_RX=() ORIG_PAUSE_TX=() ORIG_EEE=() ORIG_NM_MANAGED=()

    local PIDS_TCPDUMP=()
    local PIDS_DMESG=()
    local PIDS_IPMON=()
    local PCAP_FILES=()
    local DMESG_LOGS=()
    local LINK_LOGS=()
    local TCPDUMP_ERRS=()
    local PID_AUTOSHUTDOWN=""
    local PID_WATCHDOG=""

    cleanup_on_fail() {
        if [[ ${SETUP_SUCCESS} -eq 0 ]]; then
            log_warn "Setup failed halfway! Rolling back interface state to prevent disruption..."
            for iface in "${CONFIGURED_IFACES[@]:-}"; do
                [[ -n "${iface}" ]] && restore_interface_state "${iface}"
            done
            [[ -n "${tmp_state}" ]] && rm -f "${tmp_state}" 2>/dev/null || true
            if [[ ${STATE_FILE_CREATED} -eq 1 ]]; then
                rm -f "${STATE_FILE}" 2>/dev/null || true
            fi
            for pid in "${PIDS_TCPDUMP[@]:-}"; do [[ -n "$pid" ]] && safe_kill "$pid" "tcpdump" "tcpdump"; done
            for pid in "${PIDS_DMESG[@]:-}"; do [[ -n "$pid" ]] && safe_kill "$pid" "dmesg" "dmesg"; done
            for pid in "${PIDS_IPMON[@]:-}"; do [[ -n "$pid" ]] && safe_kill "$pid" "ip" "ip.*monitor"; done
            [[ -n "${PID_AUTOSHUTDOWN}" ]] && safe_kill "${PID_AUTOSHUTDOWN}" "bash|net-tap|net-tap.sh" "_autoshutdown_worker"
            [[ -n "${PID_WATCHDOG}" ]] && safe_kill "${PID_WATCHDOG}" "bash|net-tap|net-tap.sh" "_disk_watchdog_worker"
            release_lock
        fi
    }
    trap cleanup_on_fail EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP

    if [[ -n "${NETNS}" ]] && ! ip netns list | grep -qw "${NETNS}"; then
        log_err "Network namespace '${NETNS}' does not exist."
        exit 1
    fi

    IFS=',' read -ra IFACES_ARR <<< "${IFACE}"
    for iface in "${IFACES_ARR[@]}"; do
        if ! cmd_netns ip link show dev "${iface}" &>/dev/null; then
            log_err "Interface '${iface}' does not exist (in target namespace)."
            exit 1
        fi
        if cmd_netns test -d "/sys/class/net/${iface}/master"; then
            local master_dev
            master_dev=$(cmd_netns basename "$(cmd_netns readlink "/sys/class/net/${iface}/master" 2>/dev/null || echo "master")")
            log_err "Interface '${iface}' is enslaved to master '${master_dev}'!"
            log_err "Tapping an enslaved port causes bridge/bond emissions (STP/LACP). Detach with: sudo ip link set dev ${iface} nomaster"
            exit 1
        fi
    done

    verify_disk_space "${OUT_DIR}" "${#IFACES_ARR[@]}"
    
    if [[ -n "${BPF_FILTER}" ]]; then
        log_info "Validating BPF filter syntax..."
        local first_if="${IFACES_ARR[0]}"
        local bpf_err
        if ! bpf_err=$(tcpdump -y EN10MB -d -- "${BPF_FILTER}" 2>&1 >/dev/null); then
            if echo "${bpf_err}" | grep -qiE "unknown data link type|invalid option|usage"; then
                if ! cmd_netns tcpdump -i "${first_if}" -d -- "${BPF_FILTER}" >/dev/null 2>&1; then
                    log_err "Invalid BPF filter provided: '${BPF_FILTER}'"
                    exit 1
                fi
            else
                log_err "Invalid BPF filter provided: '${BPF_FILTER}'"
                exit 1
            fi
        fi
        log_ok "BPF filter is valid."
    fi

    mkdir -p "${STATE_DIR}"
    chmod 755 "${STATE_DIR}"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

    log_info "Configuring ${C_BOLD}${IFACE}${C_RESET} into full silent capture mode..."

    for iface in "${IFACES_ARR[@]}"; do
        # 1. Capture current interface parameters
        if command -v nmcli >/dev/null 2>&1 && cmd_netns nmcli device status 2>/dev/null | grep -qw "${iface}"; then
            ORIG_NM_MANAGED[$iface]="unmanaged"
            cmd_netns nmcli device set "${iface}" managed no 2>/dev/null || true
        fi

        ORIG_OPERSTATE[$iface]=$(cmd_netns cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "up")
        local link_dump
        link_dump=$(cmd_netns ip -d link show dev "${iface}" 2>/dev/null || true)
        if [[ "${link_dump}" =~ promiscuity\ [1-9] ]]; then
            ORIG_PROMISC[$iface]="on"
        else
            ORIG_PROMISC[$iface]="off"
        fi
        if [[ "${link_dump}" =~ NOARP ]]; then
            ORIG_ARP[$iface]="off"
        else
            ORIG_ARP[$iface]="on"
        fi
        ORIG_MTU[$iface]=$(cmd_netns cat "/sys/class/net/${iface}/mtu" 2>/dev/null || echo "1500")
        ORIG_TXQLEN[$iface]=$(cmd_netns cat "/sys/class/net/${iface}/tx_queue_len" 2>/dev/null || echo "1000")
        ORIG_RX_RING[$iface]=$(cmd_netns ethtool -g "${iface}" 2>/dev/null | awk '/Current hardware settings:/,/RX:/' | awk '/RX:/{print $2; exit}' || echo "")

        ORIG_PAUSE_AUTONEG[$iface]=$(cmd_netns ethtool -a "${iface}" 2>/dev/null | awk '/Autonegotiate:/{print $2; exit}' || echo "on")
        ORIG_PAUSE_RX[$iface]=$(cmd_netns ethtool -a "${iface}" 2>/dev/null | awk '/RX:/{print $2; exit}' || echo "on")
        ORIG_PAUSE_TX[$iface]=$(cmd_netns ethtool -a "${iface}" 2>/dev/null | awk '/TX:/{print $2; exit}' || echo "on")
        ORIG_EEE[$iface]=$(cmd_netns ethtool --show-eee "${iface}" 2>/dev/null | grep -qi "EEE status: enabled" && echo "on" || echo "off")

        ORIG_GRO[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/generic-receive-offload:/{print $2}' || echo "on")
        ORIG_LRO[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/large-receive-offload:/{print $2}' || echo "off")
        ORIG_TSO[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/tcp-segmentation-offload:/{print $2}' || echo "on")
        ORIG_GSO[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/generic-segmentation-offload:/{print $2}' || echo "on")
        ORIG_RX[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/rx-checksumming:/{print $2}' || echo "on")
        ORIG_RXVLAN[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/rx-vlan-offload:/{print $2}' || echo "on")
        ORIG_RX_VLAN_FILTER[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/rx-vlan-filter:/{print $2}' || echo "on")
        ORIG_RX_ALL[$iface]=$(cmd_netns ethtool -k "${iface}" 2>/dev/null | awk '/rx-all:/{print $2}' || echo "off")

        ORIG_IPV6_DISABLE[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.disable_ipv6" 2>/dev/null || echo "0")
        ORIG_IPV6_KEEP_ADDR[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.keep_addr_on_down" 2>/dev/null || echo "0")
        ORIG_IPV6_ADDR_GEN[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.addr_gen_mode" 2>/dev/null || echo "0")
        ORIG_IPV6_DAD[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.accept_dad" 2>/dev/null || echo "1")
        ORIG_IPV6_DADT[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.dad_transmits" 2>/dev/null || echo "1")
        ORIG_IPV6_RA[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.accept_ra" 2>/dev/null || echo "1")
        ORIG_IPV6_RS[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.router_solicitations" 2>/dev/null || echo "1")
        ORIG_IPV6_AUTOCONF[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.autoconf" 2>/dev/null || echo "1")
        ORIG_IPV6_TEMP[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.use_tempaddr" 2>/dev/null || echo "0")
        ORIG_IPV6_EDAD[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.enhanced_dad" 2>/dev/null || echo "1")
        ORIG_IPV6_NDISC[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.ndisc_notify" 2>/dev/null || echo "0")
        ORIG_IPV6_REDIR[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.accept_redirects" 2>/dev/null || echo "1")
        ORIG_MLDV1_INTVAL[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.mldv1_unsolicited_report_interval" 2>/dev/null || echo "1")
        ORIG_MLDV2_INTVAL[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.mldv2_unsolicited_report_interval" 2>/dev/null || echo "1")
        ORIG_MLD_VER[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.force_mld_version" 2>/dev/null || echo "0")
        ORIG_DROP_UNA[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.drop_unsolicited_na" 2>/dev/null || echo "0")
        ORIG_ACCEPT_UNA[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.accept_untracked_na" 2>/dev/null || echo "0")
        ORIG_IPV6_FWD[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.forwarding" 2>/dev/null || echo "0")
        ORIG_IPV6_MC_FWD[$iface]=$(cmd_netns sysctl -n "net.ipv6.conf.${iface}.mc_forwarding" 2>/dev/null || echo "0")

        ORIG_ARP_IGNORE[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.arp_ignore" 2>/dev/null || echo "0")
        ORIG_ARP_ANNOUNCE[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.arp_announce" 2>/dev/null || echo "0")
        ORIG_ARP_FILTER[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.arp_filter" 2>/dev/null || echo "0")
        ORIG_ARP_NOTIFY[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.arp_notify" 2>/dev/null || echo "0")
        ORIG_DROP_GARP[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.drop_gratuitous_arp" 2>/dev/null || echo "0")
        ORIG_ARP_ACCEPT[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.arp_accept" 2>/dev/null || echo "0")
        ORIG_PROXY_ARP[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.proxy_arp" 2>/dev/null || echo "0")
        ORIG_PROXY_ARP_PVLAN[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.proxy_arp_pvlan" 2>/dev/null || echo "0")
        ORIG_SEND_REDIRECTS[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.send_redirects" 2>/dev/null || echo "1")
        ORIG_ACCEPT_REDIRECTS[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.accept_redirects" 2>/dev/null || echo "1")
        ORIG_SECURE_REDIRECTS[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.secure_redirects" 2>/dev/null || echo "1")
        ORIG_DROP_UNICAST_L2M[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.drop_unicast_in_l2_multicast" 2>/dev/null || echo "0")
        ORIG_IGMPV2_INTVAL[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.igmpv2_unsolicited_report_interval" 2>/dev/null || echo "1")
        ORIG_IGMPV3_INTVAL[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.igmpv3_unsolicited_report_interval" 2>/dev/null || echo "1")
        ORIG_IGMP_VER[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.force_igmp_version" 2>/dev/null || echo "0")
        ORIG_IPV4_FWD[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.forwarding" 2>/dev/null || echo "0")
        ORIG_IPV4_MC_FWD[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.mc_forwarding" 2>/dev/null || echo "0")
        ORIG_IPV4_BC_FWD[$iface]=$(cmd_netns sysctl -n "net.ipv4.conf.${iface}.bc_forwarding" 2>/dev/null || echo "0")

        # 2. Down interface first to eliminate temporal emission windows during reconfiguration
        cmd_netns ip link set dev "${iface}" down 2>/dev/null || true
        cmd_netns ip link set dev "${iface}" txqueuelen 0 2>/dev/null || true

        # Disable hardware flow control (PAUSE frames), EEE & firmware LLDP to prevent network pushback
        cmd_netns ethtool -A "${iface}" autoneg off rx off tx off 2>/dev/null || true
        cmd_netns ethtool --set-eee "${iface}" eee off 2>/dev/null || true
        cmd_netns ethtool --set-priv-flags "${iface}" disable-fw-lldp on 2>/dev/null || true

        # Non-destructive stealth: Suppress spontaneous ICMPv6/MLD/ARP emissions without wiping IPv6 addresses
        if cmd_netns test -d "/proc/sys/net/ipv6/conf/${iface}"; then
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.keep_addr_on_down=1" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.addr_gen_mode=1" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.router_solicitations=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_dad=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.dad_transmits=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_ra=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.autoconf=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.use_tempaddr=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.enhanced_dad=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.ndisc_notify=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_redirects=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.mldv1_unsolicited_report_interval=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.mldv2_unsolicited_report_interval=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.force_mld_version=2" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.drop_unsolicited_na=1" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.accept_untracked_na=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.forwarding=0" 2>/dev/null || true
            cmd_netns sysctl -q -w "net.ipv6.conf.${iface}.mc_forwarding=0" 2>/dev/null || true
        fi
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_ignore=8" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_announce=2" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_filter=1" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_notify=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.drop_gratuitous_arp=1" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.arp_accept=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.proxy_arp=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.proxy_arp_pvlan=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.send_redirects=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.accept_redirects=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.secure_redirects=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.drop_unicast_in_l2_multicast=1" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.igmpv2_unsolicited_report_interval=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.igmpv3_unsolicited_report_interval=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.force_igmp_version=3" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.forwarding=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.mc_forwarding=0" 2>/dev/null || true
        cmd_netns sysctl -q -w "net.ipv4.conf.${iface}.bc_forwarding=0" 2>/dev/null || true
        cmd_netns ip link set dev "${iface}" arp off 2>/dev/null || true

        # 3. Conntrack isolation & Netfilter RAW OUTPUT drop rules
        if command -v iptables >/dev/null 2>&1; then
            cmd_netns iptables -t raw -I PREROUTING -i "${iface}" -j NOTRACK 2>/dev/null || true
            cmd_netns iptables -t raw -I OUTPUT -o "${iface}" -j NOTRACK 2>/dev/null || true
            cmd_netns iptables -t raw -I OUTPUT -o "${iface}" -j DROP 2>/dev/null || true
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            cmd_netns ip6tables -t raw -I PREROUTING -i "${iface}" -j NOTRACK 2>/dev/null || true
            cmd_netns ip6tables -t raw -I OUTPUT -o "${iface}" -j NOTRACK 2>/dev/null || true
            cmd_netns ip6tables -t raw -I OUTPUT -o "${iface}" -j DROP 2>/dev/null || true
        fi

        # 4. Attach egress matchall drop filter across all protocols WHILE DOWN with priority 1
        cmd_netns tc qdisc del dev "${iface}" clsact 2>/dev/null || true
        if ! cmd_netns tc qdisc add dev "${iface}" clsact 2>/dev/null || \
           ! cmd_netns tc filter add dev "${iface}" egress pref 1 protocol all matchall action drop 2>/dev/null; then
            log_err "CRITICAL: Failed to attach zero-egress tc clsact drop filter to ${iface}!"
            log_err "Aborting capture startup to prevent unshielded packet emission onto the wire."
            exit 1
        fi
        log_ok "Egress packet drop filter active on ${iface}."

        # 5. Offload & MTU tuning: Disable coalescing to guarantee raw frame timing & raise MTU for 802.1Q/QinQ/VXLAN
        for feat in gro lro tso gso rx rxvlan rx-vlan-filter; do
            cmd_netns ethtool -K "${iface}" "${feat}" off 2>/dev/null || true
        done
        cmd_netns ethtool -K "${iface}" rx-all on 2>/dev/null || true

        local max_mtu
        max_mtu=$(cmd_netns cat "/sys/class/net/${iface}/max_mtu" 2>/dev/null || echo "1500")
        local target_mtu=1500
        if [[ "${max_mtu}" =~ ^[0-9]+$ ]]; then
            if [[ "${max_mtu}" -ge 9216 ]]; then
                target_mtu=9216
            elif [[ "${max_mtu}" -ge 9000 ]]; then
                target_mtu=9000
            elif [[ "${max_mtu}" -gt 1500 ]]; then
                target_mtu="${max_mtu}"
            fi
        fi
        cmd_netns ip link set dev "${iface}" mtu "${target_mtu}" 2>/dev/null || true

        # Performance tuning: Maximize NIC Rx ring buffers
        local rx_max
        rx_max=$(cmd_netns ethtool -g "${iface}" 2>/dev/null | grep -A 4 "Pre-set maximums" | grep "RX:" | awk '{print $2}' || true)
        if [[ -n "${rx_max}" && "${rx_max}" =~ ^[0-9]+$ ]]; then
            cmd_netns ethtool -G "${iface}" rx "${rx_max}" 2>/dev/null || true
        else
            cmd_netns ethtool -G "${iface}" rx 4096 2>/dev/null || true
        fi

        if [[ "${HW_TYPE}" == "sfp" ]]; then
            log_info "Analyzing SFP/SFP+ transceiver characteristics for ${iface}..."
            if cmd_netns ethtool -m "${iface}" &>/dev/null; then
                cmd_netns ethtool -m "${iface}" > "${OUT_DIR}/${TIMESTAMP}_${iface}_sfp_ddm.txt" 2>&1
                log_ok "Dumped optical transceiver DDM metrics for ${iface}."
            fi
            if [[ -n "${SPEED}" ]]; then
                log_info "Forcing transceiver speed to ${SPEED} Mbps (autoneg off) for ${iface}..."
                cmd_netns ethtool -s "${iface}" speed "${SPEED}" duplex full autoneg off 2>/dev/null || true
            fi
        fi

        # 6. Bring interface up into promiscuous mode now that egress drop and sysctls are active
        cmd_netns ip link set dev "${iface}" promisc on
        cmd_netns ip link set dev "${iface}" up
        CONFIGURED_IFACES+=("${iface}")

        local PCAP_FILE="${OUT_DIR}/${TIMESTAMP}_${iface}_trace.pcap"
        local DMESG_LOG="${OUT_DIR}/${TIMESTAMP}_${iface}_dmesg.log"
        local LINK_LOG="${OUT_DIR}/${TIMESTAMP}_${iface}_link_events.log"
        local TCPDUMP_ERR="${OUT_DIR}/${TIMESTAMP}_${iface}_tcpdump.log"

        _close_lock_fds() {
            for lfd in "${HELD_LOCK_FDS[@]:-}"; do
                [[ -n "${lfd}" ]] && eval "exec ${lfd}>&-" 2>/dev/null || true
            done
        }

        ( _close_lock_fds; exec dmesg -wT ) > "${DMESG_LOG}" 2>&1 &
        local PID_DMESG=$!
        PIDS_DMESG+=("${PID_DMESG}")

        if [[ -n "${NETNS}" ]]; then
            ( _close_lock_fds; exec ip netns exec "${NETNS}" ip monitor link dev "${iface}" ) > "${LINK_LOG}" 2>&1 &
        else
            ( _close_lock_fds; exec ip monitor link dev "${iface}" ) > "${LINK_LOG}" 2>&1 &
        fi
        local PID_IPMON=$!
        PIDS_IPMON+=("${PID_IPMON}")

        # 7. Spawn tcpdump with argument delimiter '--'
        local TCPDUMP_CMD=(
            tcpdump
            -Z root
            -i "${iface}"
            -B 65536
            -s 0
            -C "${ROTATE_SIZE}"
            -W "${ROTATE_COUNT}"
            -w "${PCAP_FILE}"
        )
        if tcpdump --time-stamp-precision nano -h >/dev/null 2>&1; then
            TCPDUMP_CMD+=("--time-stamp-precision" "nano")
        fi
        if [[ "${COMPRESS_PCAPS}" -eq 1 ]]; then
            TCPDUMP_CMD+=("-z" "gzip")
        fi
        if [[ -n "${BPF_FILTER}" ]]; then
            TCPDUMP_CMD+=("--" "${BPF_FILTER}")
        fi

        if [[ -n "${NETNS}" ]]; then
            ( _close_lock_fds; exec ip netns exec "${NETNS}" "${TCPDUMP_CMD[@]}" ) > "${TCPDUMP_ERR}" 2>&1 &
        else
            ( _close_lock_fds; exec "${TCPDUMP_CMD[@]}" ) > "${TCPDUMP_ERR}" 2>&1 &
        fi
        local PID_TCPDUMP=$!
        PIDS_TCPDUMP+=("${PID_TCPDUMP}")

        # Poll liveness up to 5 seconds
        local wait_tcpdump=0
        local tcpdump_alive=0
        while [[ $wait_tcpdump -lt 50 ]]; do
            if kill -0 "${PID_TCPDUMP}" 2>/dev/null && grep -q "tcpdump" "/proc/${PID_TCPDUMP}/comm" 2>/dev/null; then
                tcpdump_alive=1
                break
            fi
            sleep 0.1
            wait_tcpdump=$((wait_tcpdump + 1))
        done

        if [[ ${tcpdump_alive} -eq 0 ]]; then
            log_err "tcpdump failed to start or exited unexpectedly for ${iface}. Check: ${TCPDUMP_ERR}"
            exit 1
        fi

        PCAP_FILES+=("${PCAP_FILE}")
        DMESG_LOGS+=("${DMESG_LOG}")
        LINK_LOGS+=("${LINK_LOG}")
        TCPDUMP_ERRS+=("${TCPDUMP_ERR}")
    done

    if cmd_netns ss -0 -p 2>/dev/null | grep -qEi 'lldpd|wpa_supplicant' || cmd_netns ss -ulpn 2>/dev/null | grep -qEi 'avahi|dhclient'; then
        log_warn "Host daemons (avahi, lldpd, etc.) are active in this namespace and may attempt to transmit."
        log_warn "Egress filters will block them, but they may cause interrupt load. Consider stopping them."
    fi

    SCRIPT_PATH="${SCRIPT_PATH:-$(readlink -f "$0")}"
    if [[ -n "${DURATION}" ]] && [[ "${DURATION}" =~ ^[0-9]+$ ]]; then
        log_info "Scheduling auto-shutdown in ${DURATION} seconds..."
        _autoshutdown_worker "${DURATION}" "${IFACE}" "${NETNS}" "${SCRIPT_PATH}" "${STATE_FILE}" >/dev/null 2>&1 9>&- &
        PID_AUTOSHUTDOWN=$!
    fi

    local THRESH="${DISK_THRESH:-85}"
    log_info "Starting background disk watchdog (threshold: ${THRESH}%)..."
    _disk_watchdog_worker "${THRESH}" "${OUT_DIR}" "${IFACE}" "${NETNS}" "${SCRIPT_PATH}" "${STATE_FILE}" "${ROTATE_COUNT}" "${PIDS_TCPDUMP[*]}" >/dev/null 2>&1 9>&- &
    PID_WATCHDOG=$!

    # 8. Secure atomic state serialization
    tmp_state=$(mktemp "${STATE_DIR}/.state.XXXXXX")
    chmod 644 "${tmp_state}"
    {
        declare -p IFACE HW_TYPE TIMESTAMP NETNS ROTATE_SIZE ROTATE_COUNT OUT_DIR
        declare -p PIDS_TCPDUMP PIDS_DMESG PIDS_IPMON PCAP_FILES DMESG_LOGS LINK_LOGS TCPDUMP_ERRS CONFIGURED_IFACES
        declare -p ORIG_PROMISC ORIG_ARP ORIG_IPV6_DISABLE ORIG_IPV6_KEEP_ADDR ORIG_IPV6_ADDR_GEN ORIG_IPV6_DAD ORIG_IPV6_DADT ORIG_IPV6_RA ORIG_IPV6_RS ORIG_IPV6_AUTOCONF ORIG_IPV6_TEMP ORIG_IPV6_EDAD ORIG_IPV6_NDISC ORIG_IPV6_REDIR
        declare -p ORIG_MLDV1_INTVAL ORIG_MLDV2_INTVAL ORIG_MLD_VER ORIG_DROP_UNA ORIG_ACCEPT_UNA ORIG_IPV6_FWD ORIG_IPV6_MC_FWD
        declare -p ORIG_MTU ORIG_TXQLEN ORIG_RX_RING ORIG_GRO ORIG_LRO ORIG_TSO ORIG_GSO ORIG_RX ORIG_RXVLAN ORIG_RX_VLAN_FILTER ORIG_RX_ALL
        declare -p ORIG_ARP_IGNORE ORIG_ARP_ANNOUNCE ORIG_ARP_FILTER ORIG_ARP_NOTIFY ORIG_DROP_GARP ORIG_ARP_ACCEPT ORIG_PROXY_ARP ORIG_PROXY_ARP_PVLAN ORIG_SEND_REDIRECTS ORIG_ACCEPT_REDIRECTS ORIG_SECURE_REDIRECTS ORIG_DROP_UNICAST_L2M
        declare -p ORIG_IGMPV2_INTVAL ORIG_IGMPV3_INTVAL ORIG_IGMP_VER ORIG_IPV4_FWD ORIG_IPV4_MC_FWD ORIG_IPV4_BC_FWD ORIG_OPERSTATE
        declare -p ORIG_PAUSE_AUTONEG ORIG_PAUSE_RX ORIG_PAUSE_TX ORIG_EEE ORIG_NM_MANAGED
        declare -p PID_WATCHDOG PID_AUTOSHUTDOWN
    } > "${tmp_state}"
    mv -f "${tmp_state}" "${STATE_FILE}"
    chmod 644 "${STATE_FILE}"
    STATE_FILE_CREATED=1

    SETUP_SUCCESS=1
    trap - EXIT INT TERM HUP ERR
    release_lock

    [[ -t 1 ]] && clear || true
    render_status_dashboard
}

# --- Function: Render Dashboard ---
render_status_dashboard() {
    echo -e "${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}        PASSIVE PROMISCUOUS MONITORING ENGINE: ACTIVE${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}"
    
    IFS=',' read -ra IFACES_ARR <<< "${IFACE}"
    for iface in "${IFACES_ARR[@]}"; do
        local port_info status speed duplex operstate
        port_info=$(detect_port_status "${iface}")
        IFS='|' read -r status speed duplex operstate <<< "${port_info}"

        printf "%-22s: %s\n" "Monitored Interface" "${iface} ${NETNS:+(netns: ${NETNS})}"
        printf "%-22s: %s\n" "Interface Hardware" "${HW_TYPE}"
        if [[ "${status}" == "ACTIVE" ]]; then
            printf "%-22s: %b\n" "Physical Port State" "${C_GREEN}${C_BOLD}ACTIVE (Link Detected / Carrier Up)${C_RESET}"
            printf "%-22s: %s (%s)\n" "Negotiated Parameters" "${speed}" "${duplex}"
        else
            printf "%-22s: %b\n" "Physical Port State" "${C_YELLOW}${C_BOLD}INACTIVE (No Carrier / Unplugged / No Light)${C_RESET}"
        fi
        echo -e "${C_BOLD}----------------------------------------------------------------------${C_RESET}"
    done
    printf "%-22s: %s\n" "Egress Protection" "ACTIVE (tc clsact: 100% outbound traffic dropped)"
    printf "%-22s: %s\n" "Dual-Stack Stealth" "ACTIVE (IPv4/IPv6 silent, conntrack NOTRACK enabled)"
    printf "%-22s: %s\n" "Session Start Time" "${TIMESTAMP}"
    if [[ -n "${DURATION}" ]]; then
        printf "%-22s: %s\n" "Auto-Shutdown" "Active (in ${DURATION} seconds)"
    fi
    echo -e "${C_BOLD}----------------------------------------------------------------------${C_RESET}"
    echo -e "Ready for cable attachment or TAP traffic inspection."
    local netns_arg=""
    if [[ -n "${NETNS}" ]]; then netns_arg="-n ${NETNS}"; fi
    echo -e "Stop capture: ${C_CYAN}sudo $0 off -i ${IFACE} ${netns_arg}${C_RESET}"
    
    local first_iface="${IFACES_ARR[0]}"
    local pcap_dir
    pcap_dir=$(dirname "${OUT_DIR}/${TIMESTAMP}_${first_iface}_trace.pcap")
    echo -e "Run deep profiling: ${C_CYAN}$0 analyze -d ${pcap_dir}${C_RESET}\n"
}

# --- Function: Stop Tap & Reset Interface ---
stop_tap() {
    require_root

    if [[ -z "${IFACE}" ]]; then
        log_err "Interface (-i <interface>) is required."
        exit 1
    fi

    acquire_lock "${IFACE}"

    declare -g -A ORIG_PROMISC=() ORIG_ARP=() ORIG_MTU=() ORIG_TXQLEN=() ORIG_RX_RING=() ORIG_GRO=() ORIG_LRO=() ORIG_TSO=() ORIG_GSO=() ORIG_RX=() ORIG_RXVLAN=() ORIG_RX_VLAN_FILTER=() ORIG_RX_ALL=()
    declare -g -A ORIG_IPV6_RS=() ORIG_IPV6_DAD=() ORIG_IPV6_DADT=() ORIG_IPV6_ADDR_GEN=() ORIG_DROP_UNICAST_L2M=()
    declare -g -A ORIG_IPV6_DISABLE=() ORIG_IPV6_KEEP_ADDR=() ORIG_IPV6_RA=() ORIG_IPV6_AUTOCONF=() ORIG_IPV6_TEMP=() ORIG_IPV6_EDAD=() ORIG_IPV6_NDISC=() ORIG_IPV6_REDIR=()
    declare -g -A ORIG_MLDV1_INTVAL=() ORIG_MLDV2_INTVAL=() ORIG_MLD_VER=() ORIG_DROP_UNA=() ORIG_ACCEPT_UNA=() ORIG_IPV6_FWD=() ORIG_IPV6_MC_FWD=()
    declare -g -A ORIG_ARP_IGNORE=() ORIG_ARP_ANNOUNCE=() ORIG_ARP_FILTER=() ORIG_ARP_NOTIFY=() ORIG_DROP_GARP=() ORIG_ARP_ACCEPT=() ORIG_PROXY_ARP=() ORIG_PROXY_ARP_PVLAN=() ORIG_SEND_REDIRECTS=() ORIG_ACCEPT_REDIRECTS=() ORIG_SECURE_REDIRECTS=()
    declare -g -A ORIG_IGMPV2_INTVAL=() ORIG_IGMPV3_INTVAL=() ORIG_IGMP_VER=() ORIG_IPV4_FWD=() ORIG_IPV4_MC_FWD=() ORIG_IPV4_BC_FWD=() ORIG_OPERSTATE=()
    declare -g -A ORIG_PAUSE_AUTONEG=() ORIG_PAUSE_RX=() ORIG_PAUSE_TX=() ORIG_EEE=() ORIG_NM_MANAGED=()
    declare -g -a PCAP_FILES=() PIDS_TCPDUMP=() PIDS_DMESG=() PIDS_IPMON=() CONFIGURED_IFACES=()

    IFS=',' read -ra IFACES_ARR <<< "${IFACE}"

    cleanup_on_interrupt() {
        log_err "Received interrupt signal! Forcing emergency interface reset..."
        for iface in "${IFACES_ARR[@]}"; do
            restore_interface_state "${iface}"
        done
        for pid in "${PIDS_TCPDUMP[@]:-}"; do [[ -n "$pid" ]] && safe_kill "$pid" "tcpdump" "tcpdump"; done
        for pid in "${PIDS_DMESG[@]:-}"; do [[ -n "$pid" ]] && safe_kill "$pid" "dmesg" "dmesg"; done
        for pid in "${PIDS_IPMON[@]:-}"; do [[ -n "$pid" ]] && safe_kill "$pid" "ip" "ip.*monitor"; done
        [[ -n "${PID_AUTOSHUTDOWN:-}" ]] && safe_kill "${PID_AUTOSHUTDOWN}" "bash|net-tap|net-tap.sh" "_autoshutdown_worker"
        [[ -n "${PID_WATCHDOG:-}" ]] && safe_kill "${PID_WATCHDOG}" "bash|net-tap|net-tap.sh" "_disk_watchdog_worker"
        rm -f "${STATE_FILE}" 2>/dev/null || true
        release_lock
        exit 130
    }
    trap cleanup_on_interrupt INT TERM HUP EXIT

    if [[ ! -f "${STATE_FILE}" ]]; then
        log_warn "No active state file found for ${IFACE}. Running fallback interface reset..."
        for iface in "${IFACES_ARR[@]}"; do
            restore_interface_state "${iface}"
        done
        trap - EXIT INT TERM HUP
        release_lock
        exit 0
    fi

    if ! load_state_file "${STATE_FILE}"; then
        log_err "State file '${STATE_FILE}' failed security verification or is corrupted."
        log_warn "Performing fallback emergency teardown for ${IFACE} to prevent network lockup..."
        for iface in "${IFACES_ARR[@]}"; do
            restore_interface_state "${iface}"
        done
        rm -f "${STATE_FILE}" 2>/dev/null || true
        trap - EXIT INT TERM HUP
        release_lock
        exit 1
    fi
    log_info "Tearing down background capture processes..."

    NETNS="${NETNS:-}"

    if [[ -n "${PID_WATCHDOG:-}" && "${PID_WATCHDOG}" -ne $$ && "${PID_WATCHDOG}" -ne "${PPID}" ]]; then
        safe_kill "${PID_WATCHDOG}" "bash|net-tap|net-tap.sh" "_disk_watchdog_worker"
    fi
    if [[ -n "${PID_AUTOSHUTDOWN:-}" && "${PID_AUTOSHUTDOWN}" -ne $$ && "${PID_AUTOSHUTDOWN}" -ne "${PPID}" ]]; then
        safe_kill "${PID_AUTOSHUTDOWN}" "bash|net-tap|net-tap.sh" "_autoshutdown_worker"
    fi

    # Send SIGTERM in parallel to all capture processes to minimize Tx/Rx capture skew
    for pid in "${PIDS_TCPDUMP[@]:-}"; do
        [[ -z "${pid}" ]] && continue
        if kill -0 "${pid}" 2>/dev/null; then
            kill -SIGTERM "${pid}" 2>/dev/null || true
        fi
    done
    for pid in "${PIDS_TCPDUMP[@]:-}"; do
        [[ -z "${pid}" ]] && continue
        safe_kill "${pid}" "tcpdump" "tcpdump"
    done
    log_ok "tcpdump flushed and closed cleanly."

    for pid in "${PIDS_DMESG[@]:-}"; do [[ -n "$pid" ]] && safe_kill "${pid}" "dmesg" "dmesg"; done
    for pid in "${PIDS_IPMON[@]:-}"; do [[ -n "$pid" ]] && safe_kill "${pid}" "ip" "ip.*monitor"; done

    local drop_stats=0
    for iface in "${IFACES_ARR[@]}"; do
        local ds
        ds=$(cmd_netns tc -s filter show dev "${iface}" egress 2>/dev/null | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
        drop_stats=$((drop_stats + ds))
        restore_interface_state "${iface}"
    done

    local tcpdump_dropped=0
    for t_err in "${TCPDUMP_ERRS[@]:-}"; do
        if [[ -f "${t_err}" ]]; then
            local d_cnt
            d_cnt=$(grep -oE '[0-9]+ packets dropped by kernel' "${t_err}" | awk '{print $1}' | tail -n 1 || echo "0")
            tcpdump_dropped=$((tcpdump_dropped + d_cnt))
        fi
    done
    if [[ "${tcpdump_dropped}" -gt 0 ]]; then
        log_warn "tcpdump reported ${tcpdump_dropped} dropped packets during capture session!"
    fi

    log_ok "Promiscuous mode, ARP, MTU, offloads, and IPv4/IPv6 kernel stack restored."

    local all_pcaps=()
    local TOTAL_SIZE="0 B"
    local FILE_COUNT=0
    
    if [[ ${#PCAP_FILES[@]} -gt 0 ]]; then
        for base_pcap in "${PCAP_FILES[@]}"; do
            [[ -z "${base_pcap}" ]] && continue
            if compgen -G "${base_pcap}*" > /dev/null; then
                for f in "${base_pcap}"*; do
                    [[ -e "$f" ]] && all_pcaps+=("$f")
                done
            fi
        done
    fi

    if [[ ${#all_pcaps[@]} -gt 0 ]]; then
        TOTAL_SIZE=$(du -csh "${all_pcaps[@]}" 2>/dev/null | awk '/total$/ {print $1}')
        FILE_COUNT=${#all_pcaps[@]}
    fi

    # Merge PCAPs if mergecap is installed
    local merge_msg=""
    if [[ ${#all_pcaps[@]} -gt 1 ]] && command -v mergecap >/dev/null 2>&1; then
        local pcap_dir
        pcap_dir=$(dirname "${all_pcaps[0]}")
        local merged_file="${pcap_dir}/${TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}_merged_trace.pcap"
        # Check disk space before merging: require at least 1.5x total PCAP size
        local total_pcap_kb avail_kb
        total_pcap_kb=$(du -ck "${all_pcaps[@]}" 2>/dev/null | awk '/total$/ {print $1}')
        avail_kb=$(df -Pk "${pcap_dir}" 2>/dev/null | awk 'NR==2 {print $4}')
        local req_kb=$(( ${total_pcap_kb:-0} * 3 / 2 ))
        if [[ -n "${avail_kb}" && "${avail_kb}" -gt "${req_kb}" ]]; then
            log_info "Merging ${#all_pcaps[@]} PCAP files into ${merged_file}..."
            mergecap -w "${merged_file}" "${all_pcaps[@]}" 2>/dev/null || true
            if [[ -f "${merged_file}" ]]; then
                merge_msg="(Merged into ${merged_file})"
                TOTAL_SIZE=$(du -sh "${merged_file}" | awk '{print $1}')
                FILE_COUNT=1
            fi
        else
            log_warn "Insufficient disk space to safely merge PCAPs (Required: $((req_kb/1024))MB, Available: $((avail_kb/1024))MB). Keeping separate chunks."
            merge_msg="(Skipped merge due to disk headroom constraints)"
        fi
    elif [[ ${#all_pcaps[@]} -gt 1 ]]; then
        merge_msg="(mergecap not installed, left as separate files)"
    fi

    rm -f "${STATE_FILE}"
    trap - EXIT INT TERM HUP
    release_lock

    echo -e "\n${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}          CAPTURE STOPPED & INTERFACE RETURNED TO DEFAULT${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}"
    printf "%-22s: %s\n" "Interfaces" "${IFACE} ${NETNS:+(netns: ${NETNS})}"
    printf "%-22s: %s %s\n" "PCAP Files" "${FILE_COUNT} file(s)" "${merge_msg}"
    printf "%-22s: %s\n" "Total Disk Captured" "${TOTAL_SIZE}"
    printf "%-22s: %s\n" "Egress Drops Blocked" "${drop_stats} packet(s)"
    echo -e "${C_BOLD}======================================================================${C_RESET}"
    
    local inspect_dir
    if [[ ${#all_pcaps[@]} -gt 0 ]]; then
        inspect_dir=$(dirname "${all_pcaps[0]}")
    else
        inspect_dir="${OUT_DIR}"
    fi
    echo -e "Run deep inspection on this session:\n  ${C_CYAN}$0 analyze -d ${inspect_dir}${C_RESET}\n"
}

# --- Function: Inspect Running State ---
status_tap() {
    verify_dependencies

    if [[ -z "${IFACE}" ]]; then
        log_err "Interface (-i <interface>) is required."
        exit 1
    fi

    IFS=',' read -ra IFACES_ARR <<< "${IFACE}"
    for iface in "${IFACES_ARR[@]}"; do
        local port_info status speed duplex operstate
        port_info=$(detect_port_status "${iface}")
        IFS='|' read -r status speed duplex operstate <<< "${port_info}"

        echo -e "${C_BOLD}Port Status for ${iface} ${NETNS:+(netns: ${NETNS})}:${C_RESET}"
        if [[ "${status}" == "ACTIVE" ]]; then
            echo -e "  Physical Link : ${C_GREEN}${C_BOLD}ACTIVE${C_RESET} (${speed}, ${duplex}, state: ${operstate})"
        else
            echo -e "  Physical Link : ${C_YELLOW}${C_BOLD}INACTIVE${C_RESET} (No carrier signal / unplugged)"
        fi
        
        if command -v ethtool >/dev/null 2>&1; then
            local drops
            drops=$(cmd_netns ethtool -S "${iface}" 2>/dev/null | grep -iE '^\s*(rx_dropped|rx_missed_errors|rx_fifo_errors|discard)' | awk '{$1=$1;print}' | paste -sd, - || true)
            if [[ -n "${drops}" ]]; then
                echo -e "  NIC Counters  : ${C_MAGENTA}${drops}${C_RESET}"
            fi
        fi
    done

    declare -g -a PCAP_FILES=()
    if [[ -f "${STATE_FILE}" ]]; then
        load_state_file "${STATE_FILE}" || true
        
        local all_pcaps=()
        local TOTAL_SIZE="0 B"
        local FILE_COUNT=0
        
        if [[ ${#PCAP_FILES[@]} -gt 0 ]]; then
            for base_pcap in "${PCAP_FILES[@]}"; do
                [[ -z "${base_pcap}" ]] && continue
                if compgen -G "${base_pcap}*" > /dev/null; then
                    for f in "${base_pcap}"*; do
                        [[ -e "$f" ]] && all_pcaps+=("$f")
                    done
                fi
            done
        fi

        if [[ ${#all_pcaps[@]} -gt 0 ]]; then
            TOTAL_SIZE=$(du -csh "${all_pcaps[@]}" 2>/dev/null | awk '/total$/ {print $1}')
            FILE_COUNT=${#all_pcaps[@]}
        fi
        
        local running_pids=()
        for pid in "${PIDS_TCPDUMP[@]:-}"; do
            [[ -z "${pid}" ]] && continue
            if [[ -d "/proc/${pid}" ]] && grep -q "tcpdump" "/proc/${pid}/comm" 2>/dev/null; then
                running_pids+=("${pid}")
            fi
        done
        
        local tcpdump_status="STOPPED"
        if [[ ${#running_pids[@]} -gt 0 ]]; then
            tcpdump_status="RUNNING"
        fi
        
        echo -e "\n${C_BOLD}Active Tap Engine Session:${C_RESET}"
        printf "  %-18s: %s\n" "Session Started" "${TIMESTAMP:-N/A}"
        printf "  %-18s: %s (PIDs: %s)\n" "tcpdump Status" "${tcpdump_status}" "${running_pids[*]:-N/A}"
        printf "  %-18s: %s (%d files, %s total)\n" "Capture Files" "${FILE_COUNT} files" "${FILE_COUNT}" "${TOTAL_SIZE}"
    else
        echo -e "\n  Tap Engine    : Not running."
    fi
}
