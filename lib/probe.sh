#!/usr/bin/env bash
# shellcheck shell=bash

# lib/probe.sh - Orchestration wrapper for Net-Tap active probing

run_probe() {
    require_root

    if [[ -z "${IFACE:-}" ]]; then
        log_err "Interface (-i) is required for probe command."
        exit 1
    fi

    if [[ "${IFACE}" == *","* ]]; then
        log_err "Probe command only supports a single interface at a time."
        exit 1
    fi

    if [[ -z "${PROBE_TYPE:-}" ]]; then
        log_err "A probe type must be specified (e.g., --arp-scan, --ndp-scan, --dhcp-discover, --dhcp-discover6, --icmp-pmtu, --tcp-syn, --eapol-check, --snmp-probe, --dns-probe, --nbns-probe)."
        exit 1
    fi

    STATE_DIR="${STATE_DIR:-/var/run/net-tap}"
    local safe_iface="${IFACE//\//_}"
    local raw_netns="${NETNS:-}"
    local safe_netns="${raw_netns//\//_}"
    local sfile="${STATE_FILE:-}"
    if [[ -z "${sfile}" ]]; then
        sfile="${STATE_DIR}/${safe_iface}.state"
        if [[ -n "${safe_netns}" ]]; then
            sfile="${STATE_DIR}/${safe_netns}__${safe_iface}.state"
        fi
    fi

    if [[ ! -f "${sfile}" ]]; then
        log_err "No active net-tap session found on '${IFACE}'."
        log_err "Please start capture first: sudo net-tap on -i ${IFACE} --mode active"
        exit 1
    fi

    if ! load_state_file "${sfile}"; then
        log_err "Failed to load state file '${sfile}'."
        exit 1
    fi

    if [[ "${MODE:-passive}" != "active" ]]; then
        log_err "Tap session on '${IFACE}' is running in PASSIVE mode (zero-egress stealth)."
        log_err "Please stop and restart net-tap with '--mode active' to permit audit probing."
        exit 1
    fi

    acquire_lock "${IFACE}"
    trap 'release_lock' EXIT INT TERM

    local audit_id="${PROBE_AUDIT_ID:-probe_$(date +%s)_$$}"
    local out_dir="${OUT_DIR:-/tmp}"
    local timestamp="${TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}"
    local audit_file="${out_dir}/${timestamp}_${safe_iface}_probe_audit.jsonl"

    local probe_vlans=""
    if [[ "${PROBE_AUTO_VLANS:-0}" -eq 1 ]]; then
        log_info "Auto-discovering active VLAN tags from capture ring buffer on ${IFACE}..."
        local discovered_vlans=""
        for pf in "${out_dir}"/*"${safe_iface}"*.pcap*; do
            [[ -f "${pf}" ]] || continue
            local v=""
            if [[ "${pf}" =~ \.gz$ ]]; then
                v=$(gzip -dc "${pf}" 2>/dev/null | tcpdump -nn -e -c 10000 -r - '(vlan or ether proto 0x88a8)' 2>/dev/null | grep -oE '\bvlan [0-9]+\b' | awk '{print $2}' || true)
            else
                v=$(tcpdump -nn -e -c 10000 -r "${pf}" '(vlan or ether proto 0x88a8)' 2>/dev/null | grep -oE '\bvlan [0-9]+\b' | awk '{print $2}' || true)
            fi
            if [[ -n "${v}" ]]; then
                discovered_vlans="${discovered_vlans}"$'\n'"${v}"
            fi
        done
        discovered_vlans=$(echo "${discovered_vlans}" | grep -v '^$' | sort -n -u | paste -sd, - || true)
        if [[ -n "${discovered_vlans}" ]]; then
            log_ok "Auto-discovered active VLAN(s) on link: ${discovered_vlans}"
            probe_vlans="${discovered_vlans}"
        else
            log_warn "No VLAN tags passively observed yet on '${IFACE}'. Falling back to untagged probing."
        fi
    elif [[ -n "${PROBE_VLAN:-}" ]]; then
        probe_vlans="${PROBE_VLAN}"
    fi

    local probe_py="${LIB_DIR}/probe.py"
    if [[ ! -f "${probe_py}" ]]; then
        probe_py="${SCRIPT_DIR}/../lib/probe.py"
    fi

    if [[ ! -f "${probe_py}" ]]; then
        log_err "Could not locate probe.py engine in ${LIB_DIR}!"
        release_lock
        trap - EXIT INT TERM
        exit 1
    fi

    local cmd=(python3 -B "${probe_py}" -i "${IFACE}" -t "${PROBE_TYPE}" --audit-file "${audit_file}" --audit-id "${audit_id}" --rate "${PROBE_RATE:-50}" --timeout "${PROBE_TIMEOUT:-5}")
    [[ -n "${PROBE_TARGET:-}" ]] && cmd+=(--target "${PROBE_TARGET}")
    [[ -n "${PROBE_PORTS:-}" ]] && cmd+=(--ports "${PROBE_PORTS}")
    [[ -n "${probe_vlans}" ]] && cmd+=(--vlans "${probe_vlans}")
    [[ -n "${PROBE_QINQ:-}" ]] && cmd+=(--qinq "${PROBE_QINQ}")
    [[ -n "${PROBE_SRC_IP:-}" ]] && cmd+=(--src-ip "${PROBE_SRC_IP}")
    [[ -n "${PROBE_SRC_IP6:-}" ]] && cmd+=(--src-ip6 "${PROBE_SRC_IP6}")
    [[ -n "${PROBE_SRC_MAC:-}" ]] && cmd+=(--src-mac "${PROBE_SRC_MAC}")
    [[ -n "${PROBE_COMMUNITY:-}" ]] && cmd+=(--community "${PROBE_COMMUNITY}")
    [[ -n "${PROBE_PCP:-}" ]] && cmd+=(--pcp "${PROBE_PCP}")
    [[ -n "${PROBE_DEI:-}" ]] && cmd+=(--dei "${PROBE_DEI}")
    [[ -n "${PROBE_QINQ_TPID:-}" ]] && cmd+=(--qinq-tpid "${PROBE_QINQ_TPID}")
    [[ -n "${PROBE_FALLBACK_MAC_MODE:-}" ]] && cmd+=(--fallback-mac-mode "${PROBE_FALLBACK_MAC_MODE}")

    log_info "Launching ${PROBE_TYPE^^} probe on ${IFACE} (rate: ${PROBE_RATE:-50} pps)..."
    local probe_rc=0
    cmd_netns "${cmd[@]}" || probe_rc=$?
    trap - EXIT INT TERM
    release_lock
    if [[ ${probe_rc} -ne 0 ]]; then
        log_err "Probe execution failed (exit code ${probe_rc})."
        return ${probe_rc}
    fi
    log_ok "Probe completed. Audit trail appended to: ${audit_file}"
}
