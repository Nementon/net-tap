#!/usr/bin/env bash

# shellcheck shell=bash
# shellcheck disable=SC2034,SC1091

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# Resolve the absolute path to the directory containing this script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Determine the library path (supports local repo, relative install, and FHS system paths)
if [[ -n "${NET_TAP_LIB_DIR:-}" && -f "${NET_TAP_LIB_DIR}/core.sh" ]]; then
    if [[ $EUID -eq 0 ]]; then
        lib_owner=$(stat -c "%u" "${NET_TAP_LIB_DIR}" 2>/dev/null || echo "-1")
        lib_perm=$(stat -c "%a" "${NET_TAP_LIB_DIR}" 2>/dev/null || echo "777")
        if [[ "${lib_owner}" -ne 0 ]] || [[ "${lib_perm: -1}" =~ [2367] ]]; then
            echo "ERROR: Untrusted NET_TAP_LIB_DIR '${NET_TAP_LIB_DIR}' must be owned by root and not writable by other users!" >&2
            exit 1
        fi
    fi
    LIB_DIR="${NET_TAP_LIB_DIR}"
elif [[ -f "${SCRIPT_DIR}/../lib/core.sh" ]]; then
    LIB_DIR="${SCRIPT_DIR}/../lib"
elif [[ -f "${SCRIPT_DIR}/../lib/net-tap/core.sh" ]]; then
    LIB_DIR="${SCRIPT_DIR}/../lib/net-tap"
elif [[ -f "/usr/local/lib/net-tap/core.sh" ]]; then
    LIB_DIR="/usr/local/lib/net-tap"
elif [[ -f "/usr/lib/net-tap/core.sh" ]]; then
    LIB_DIR="/usr/lib/net-tap"
else
    echo "ERROR: Could not locate net-tap libraries!" >&2
    exit 1
fi

source "${LIB_DIR}/core.sh"
source "${LIB_DIR}/orchestration.sh"
source "${LIB_DIR}/analyzer.sh"
source "${LIB_DIR}/probe.sh"

main() {
    # Check for help early
    if [[ "${1:-}" =~ ^(-h|--help|help)$ ]]; then
        usage 0
    fi

    # --- Parse Arguments ---
    ACTION="${1:-}"
    if [[ -z "${ACTION}" ]]; then
        usage 1
    fi
    shift

    # shellcheck disable=SC2034
    IFACE=""
    NETNS=""
    MODE="${DEFAULT_MODE:-passive}"
    HW_TYPE="${DEFAULT_HW_TYPE}"
    OUT_DIR="${DEFAULT_OUT_DIR}"
    SPEED="${DEFAULT_SPEED}"
    ROTATE_SIZE="${DEFAULT_ROTATE_SIZE}"
    ROTATE_COUNT="${DEFAULT_ROTATE_COUNT}"
    BPF_FILTER="${BPF_FILTER:-}"
    DURATION=""
    JSON_OUT="${JSON_OUT:-0}"
    COMPRESS_PCAPS="${COMPRESS_PCAPS:-0}"
    DISK_THRESH=85

    # Probe Parameters
    PROBE_TYPE=""
    PROBE_TARGET=""
    PROBE_PORTS="22,80,443"
    PROBE_VLAN=""
    PROBE_QINQ=""
    PROBE_AUTO_VLANS=0
    PROBE_RATE=50
    PROBE_TIMEOUT=5
    PROBE_AUDIT_ID=""

    SCRIPT_PATH=$(readlink -f "$0")

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                IFACE="$2"
                shift 2
                ;;
            -n|--netns)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                NETNS="$2"
                shift 2
                ;;
            -m|--mode)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                MODE="$(echo "$2" | tr '[:upper:]' '[:lower:]')"
                shift 2
                ;;
            -t|--type)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                HW_TYPE="$(echo "$2" | tr '[:upper:]' '[:lower:]')"
                shift 2
                ;;
            -o|--output-dir|-d|--dir)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                OUT_DIR="$2"
                shift 2
                ;;
            -s|--speed)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                SPEED="$2"
                shift 2
                ;;
            -C|--rotate-size)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                ROTATE_SIZE="$2"
                shift 2
                ;;
            -W|--rotate-count)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                ROTATE_COUNT="$2"
                shift 2
                ;;
            -f|--filter)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                BPF_FILTER="$2"
                shift 2
                ;;
            -D|--duration)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                DURATION="$2"
                shift 2
                ;;
            -z|--gzip)
                COMPRESS_PCAPS=1
                shift
                ;;
            -w|--watchdog-threshold)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                DISK_THRESH="$2"
                shift 2
                ;;
            -j|--json)
                JSON_OUT=1
                shift
                ;;
            --arp-scan)
                PROBE_TYPE="arp"
                if [[ $# -ge 2 ]] && [[ "$2" != -* ]]; then
                    PROBE_TARGET="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --ndp-scan)
                PROBE_TYPE="ndp"
                if [[ $# -ge 2 ]] && [[ "$2" != -* ]]; then
                    PROBE_TARGET="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --dhcp-discover)
                PROBE_TYPE="dhcp"
                shift
                ;;
            --icmp-pmtu)
                PROBE_TYPE="pmtu"
                if [[ $# -ge 2 ]] && [[ "$2" != -* ]]; then
                    PROBE_TARGET="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --tcp-syn)
                PROBE_TYPE="tcp_syn"
                if [[ $# -ge 2 ]] && [[ "$2" != -* ]]; then
                    PROBE_TARGET="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            -p|--ports)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_PORTS="$2"
                shift 2
                ;;
            --vlan)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_VLAN="$2"
                shift 2
                ;;
            --qinq)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_QINQ="$2"
                shift 2
                ;;
            --auto-vlans)
                PROBE_AUTO_VLANS=1
                shift
                ;;
            --rate)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_RATE="$2"
                shift 2
                ;;
            --timeout)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_TIMEOUT="$2"
                shift 2
                ;;
            --audit-id)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_AUDIT_ID="$2"
                shift 2
                ;;
            -h|--help)
                usage 0
                ;;
            *)
                log_err "Unknown argument: $1"
                usage 1
                ;;
        esac
    done

    if [[ -n "${NETNS}" ]]; then
        if [[ "${NETNS}" =~ ^- ]] || ! [[ "${NETNS}" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
            log_err "Invalid network namespace name format: '${NETNS}'"
            exit 1
        fi
    fi
    if [[ -n "${IFACE}" ]]; then
        if [[ "${IFACE}" =~ ^- ]] || ! [[ "${IFACE}" =~ ^[a-zA-Z0-9_.-]+(,[a-zA-Z0-9_.-]+)*$ ]]; then
            log_err "Invalid interface name format: '${IFACE}'"
            exit 1
        fi
        IFS=',' read -ra iface_check_arr <<< "${IFACE}"
        for c_if in "${iface_check_arr[@]}"; do
            if [[ "${c_if}" =~ ^- ]]; then
                log_err "Constituent interface name cannot start with a hyphen: '${c_if}'"
                exit 1
            fi
        done
        # Canonicalize multi-interface ordering (e.g. sfp1,sfp0 -> sfp0,sfp1)
        if [[ "${IFACE}" == *","* ]]; then
            IFACE=$(echo "${IFACE}" | tr ',' '\n' | sort -u | paste -sd, -)
        fi
    fi
    if [[ -n "${OUT_DIR}" ]]; then
        if [[ "${OUT_DIR}" =~ ^- ]]; then
            log_err "Output directory cannot start with a hyphen: '${OUT_DIR}'"
            exit 1
        fi
        OUT_DIR=$(readlink -m "${OUT_DIR}")
    fi
    if [[ -n "${SPEED}" ]] && ! [[ "${SPEED}" =~ ^[1-9][0-9]*$ ]]; then
        log_err "Speed must be a positive integer in Mbps."
        exit 1
    fi
    if ! [[ "${ROTATE_SIZE}" =~ ^[1-9][0-9]*$ ]] || ! [[ "${ROTATE_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
        log_err "Rotate size and count must be positive integers."
        exit 1
    fi
    if ! [[ "${DISK_THRESH}" =~ ^[0-9]+$ ]] || [[ "${DISK_THRESH}" -lt 1 ]] || [[ "${DISK_THRESH}" -gt 99 ]]; then
        log_err "Disk threshold must be an integer between 1 and 99."
        exit 1
    fi
    if [[ -n "${DURATION}" ]] && ! [[ "${DURATION}" =~ ^[1-9][0-9]*$ ]]; then
        log_err "Duration must be a positive integer in seconds."
        exit 1
    fi
    if [[ "${HW_TYPE}" != "ethernet" && "${HW_TYPE}" != "sfp" ]]; then
        log_err "Hardware type must be 'ethernet' or 'sfp'."
        exit 1
    fi
    if [[ "${MODE}" != "passive" && "${MODE}" != "active" ]]; then
        log_err "Operational mode must be 'passive' or 'active'."
        exit 1
    fi
    if [[ "${ACTION}" == "probe" ]]; then
        if [[ -z "${IFACE}" ]]; then
            log_err "Interface (-i) is required for probe command."
            exit 1
        fi
        if [[ -z "${PROBE_TYPE}" ]]; then
            log_err "A probe type must be specified (e.g., --arp-scan, --ndp-scan, --dhcp-discover, --icmp-pmtu, --tcp-syn)."
            exit 1
        fi
        if ! [[ "${PROBE_RATE}" =~ ^[1-9][0-9]*$ ]]; then
            log_err "Probe rate must be a positive integer."
            exit 1
        fi
        if ! [[ "${PROBE_TIMEOUT}" =~ ^[1-9][0-9]*$ ]]; then
            log_err "Probe timeout must be a positive integer in seconds."
            exit 1
        fi
        if [[ -n "${PROBE_VLAN}" ]]; then
            if ! [[ "${PROBE_VLAN}" =~ ^[0-9]+$ ]] || [[ "${PROBE_VLAN}" -lt 1 ]] || [[ "${PROBE_VLAN}" -gt 4094 ]]; then
                log_err "VLAN ID must be an integer between 1 and 4094."
                exit 1
            fi
        fi
        if [[ -n "${PROBE_QINQ}" ]] && ! [[ "${PROBE_QINQ}" =~ ^[0-9]+,[0-9]+$ ]]; then
            log_err "QinQ tags must be in format 's_tag,c_tag' (e.g., 100,200)."
            exit 1
        fi
    fi

    if [[ -n "${BPF_FILTER}" ]]; then
        # If user filter does not already explicitly reference vlan or mpls,
        # expand it so tagged / encapsulated frames are not silently dropped by BPF
        if ! echo "${BPF_FILTER}" | grep -qiE '\bvlan\b'; then
            BPF_FILTER="(${BPF_FILTER}) or (vlan and (${BPF_FILTER})) or (vlan and vlan and (${BPF_FILTER}))"
        fi
        if ! echo "${BPF_FILTER}" | grep -qiE '\bmpls\b'; then
            if tcpdump -y EN10MB -d -- "mpls and (${BPF_FILTER})" >/dev/null 2>&1; then
                BPF_FILTER="(${BPF_FILTER}) or (mpls and (${BPF_FILTER}))"
            fi
        fi
    fi

    local safe_iface="${IFACE//\//_}"
    local safe_netns="${NETNS//\//_}"

    STATE_FILE="${STATE_DIR}/${safe_iface}.state"
    if [[ -n "${safe_netns}" ]]; then
        STATE_FILE="${STATE_DIR}/${safe_netns}__${safe_iface}.state"
    elif [[ "${ACTION}" != "on" && -n "${safe_iface}" && ! -f "${STATE_FILE}" ]]; then
        # If netns was omitted, auto-discover if exactly one matching namespace state file exists
        local matching_ns_states=()
        for f in "${STATE_DIR}"/*__"${safe_iface}".state; do
            [[ -f "$f" ]] && matching_ns_states+=("$f")
        done
        if [[ ${#matching_ns_states[@]} -eq 1 ]]; then
            local matched_f="${matching_ns_states[0]}"
            local bname
            bname=$(basename "${matched_f}" .state)
            NETNS="${bname%%__*}"
            safe_netns="${NETNS//\//_}"
            STATE_FILE="${matched_f}"
        fi
    fi

    if [[ "${ACTION}" != "on" && -n "${safe_iface}" && ! -f "${STATE_FILE}" ]]; then
        # Search for multi-interface state files containing this interface or any constituent
        for f in "${STATE_DIR}"/*.state; do
            [[ -f "$f" ]] || continue
            local basename_f
            basename_f=$(basename "$f" .state)
            local parsed_netns=""
            local ifaces_part="$basename_f"
            
            if [[ "$basename_f" == *"__"* ]]; then
                parsed_netns="${basename_f%%__*}"
                ifaces_part="${basename_f#*__}"
            fi
            
            # Namespace filter if explicitly specified
            if [[ -n "${safe_netns}" && "${parsed_netns}" != "${safe_netns}" ]]; then
                continue
            fi
            
            IFS=',' read -ra if_arr <<< "$ifaces_part"
            IFS=',' read -ra req_if_arr <<< "$safe_iface"
            for req_i in "${req_if_arr[@]}"; do
                for i in "${if_arr[@]}"; do
                    if [[ "$i" == "$req_i" ]]; then
                        STATE_FILE="$f"
                        # Update IFACE to the full multi-interface list so stop/status affects the whole session
                        IFACE="$ifaces_part"
                        if [[ -z "${safe_netns}" && -n "${parsed_netns}" ]]; then
                            NETNS="${parsed_netns}"
                            safe_netns="${parsed_netns}"
                        fi
                        break 3
                    fi
                done
            done
        done
    fi

    # --- Main Dispatcher ---
    case "${ACTION}" in
        on)
            start_tap
            ;;
        off)
            stop_tap
            ;;
        status)
            status_tap
            ;;
        analyze)
            analyze_session
            ;;
        probe)
            run_probe
            ;;
        *)
            log_err "Unknown action: '${ACTION}'"
            usage
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
