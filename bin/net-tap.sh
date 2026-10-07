#!/usr/bin/env bash

# shellcheck shell=bash
# shellcheck disable=SC2034,SC1091 # Global CLI configuration consumed across sourced lib/*.sh modules; dynamic library paths


set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true
set +m

# Check GNU Bash version requirement
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    echo "ERROR: Bash version ${BASH_VERSION} is not supported. net-tap requires GNU Bash >= 4.3." >&2
    if [[ "$(uname -s)" == "Darwin"* ]]; then
        echo "On macOS, install modern Bash via Homebrew: brew install bash" >&2
        echo "Then run net-tap using: /opt/homebrew/bin/bash (or /usr/local/bin/bash)" >&2
    fi
    exit 1
fi

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Resolve the absolute path to the directory containing this script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Determine the library path (supports local repo, relative install, and FHS system paths)
if [[ -n "${NET_TAP_LIB_DIR:-}" && -f "${NET_TAP_LIB_DIR}/core.sh" ]]; then
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

_early_resolve_path() {
    local target="$1"
    local res=""
    if command -v realpath >/dev/null 2>&1; then
        if res=$(realpath "${target}" 2>/dev/null) && [[ -n "${res}" ]]; then
            echo "${res}"
            return 0
        fi
    fi
    if command -v greadlink >/dev/null 2>&1; then
        if res=$(greadlink -m "${target}" 2>/dev/null || greadlink -f "${target}" 2>/dev/null) && [[ -n "${res}" ]]; then
            echo "${res}"
            return 0
        fi
    elif command -v readlink >/dev/null 2>&1 && [[ "$(uname -s 2>/dev/null)" != "Darwin"* ]]; then
        if res=$(readlink -m "${target}" 2>/dev/null || readlink -f "${target}" 2>/dev/null) && [[ -n "${res}" ]]; then
            echo "${res}"
            return 0
        fi
    fi
    if command -v python3 >/dev/null 2>&1; then
        if res=$(python3 -c "import os, sys; print(os.path.realpath(sys.argv[1]))" "${target}" 2>/dev/null) && [[ -n "${res}" ]]; then
            echo "${res}"
            return 0
        fi
    fi
    if [[ "${target}" = /* ]]; then
        echo "${target}"
    else
        echo "${PWD}/${target#./}"
    fi
}

LIB_DIR=$(_early_resolve_path "${LIB_DIR}")

if [[ $EUID -eq 0 ]]; then
    if [[ "$(uname -s)" == "Darwin"* ]]; then
        lib_owner=$(stat -f "%u" "${LIB_DIR}" 2>/dev/null || echo "-1")
        lib_perm=$(stat -f "%OLp" "${LIB_DIR}" 2>/dev/null || echo "777")
        lib_perm="${lib_perm#0}"
        script_owner=$(stat -f "%u" "${SCRIPT_DIR}" 2>/dev/null || echo "-1")
    else
        lib_owner=$(stat -c "%u" "${LIB_DIR}" 2>/dev/null || echo "-1")
        lib_perm=$(stat -c "%a" "${LIB_DIR}" 2>/dev/null || echo "777")
        script_owner=$(stat -c "%u" "${SCRIPT_DIR}" 2>/dev/null || echo "-1")
    fi
    if [[ "${lib_owner}" -ne 0 && "${lib_owner}" -ne "${SUDO_UID:-0}" && "${lib_owner}" -ne "${script_owner}" && "${lib_owner}" -ne "${EUID}" ]] || [[ "${lib_perm: -1}" =~ [2367] ]]; then
        echo "ERROR: Untrusted library directory '${LIB_DIR}' must be owned by root (or invoking user) and not writable by other users!" >&2
        exit 1
    fi
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
    FORCE_CLEAN="${FORCE_CLEAN:-0}"

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
    PROBE_SRC_IP=""
    PROBE_SRC_IP6=""
    PROBE_SRC_MAC=""
    PROBE_COMMUNITY="public"
    PROBE_PCP=""
    PROBE_DEI=""
    PROBE_QINQ_TPID=""

    # Exec Parameters
    EXEC_CMD=()
    EXEC_VLAN=""
    EXEC_STATELESS_VLAN=0
    EXEC_QINQ=""
    EXEC_IP=""
    EXEC_IP6=""
    EXEC_GATEWAY=""
    EXEC_PCP="7"
    EXEC_DSCP="CS7"
    EXEC_MARK="0x7a9"
    EXEC_AUTO_BABY_GIANT=0
    EXEC_DROP_PRIVILEGES=1

    SCRIPT_PATH=$(resolve_path "$0")

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
            --dhcp-discover6|--dhcp6-discover)
                PROBE_TYPE="dhcp6"
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
            --eapol-check|--eapol-probe)
                PROBE_TYPE="eapol"
                shift
                ;;
            --snmp-probe)
                PROBE_TYPE="snmp"
                if [[ $# -ge 2 ]] && [[ "$2" != -* ]]; then
                    PROBE_TARGET="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --dns-probe)
                PROBE_TYPE="dns"
                if [[ $# -ge 2 ]] && [[ "$2" != -* ]]; then
                    PROBE_TARGET="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --nbns-probe)
                PROBE_TYPE="nbns"
                if [[ $# -ge 2 ]] && [[ "$2" != -* ]]; then
                    PROBE_TARGET="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --src-ip)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_SRC_IP="$2"
                shift 2
                ;;
            --src-ip6)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_SRC_IP6="$2"
                shift 2
                ;;
            --src-mac)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_SRC_MAC="$2"
                shift 2
                ;;
            --community)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_COMMUNITY="$2"
                shift 2
                ;;
            -p|--ports)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                if ! [[ "$2" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
                    log_err "Target ports must be a comma-separated list of positive integers."
                    exit 1
                fi
                PROBE_PORTS="$2"
                shift 2
                ;;
            --vlan)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_VLAN="$2"
                EXEC_VLAN="$2"
                shift 2
                ;;
            --qinq)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_QINQ="$2"
                EXEC_QINQ="$2"
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
            --pcp)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_PCP="$2"
                EXEC_PCP="$2"
                shift 2
                ;;
            --dei)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_DEI="$2"
                shift 2
                ;;
            --qinq-tpid)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                PROBE_QINQ_TPID="$2"
                shift 2
                ;;
            --fallback-mac-mode)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                if [[ "$2" != "multicast" && "$2" != "broadcast" ]]; then
                    log_err "Invalid --fallback-mac-mode '$2'. Must be 'multicast' or 'broadcast'."
                    exit 1
                fi
                PROBE_FALLBACK_MAC_MODE="$2"
                shift 2
                ;;
            --stateless-vlan|--raw)
                EXEC_STATELESS_VLAN=1
                shift
                ;;
            --auto-baby-giant)
                EXEC_AUTO_BABY_GIANT=1
                shift
                ;;
            --no-drop-privileges)
                EXEC_DROP_PRIVILEGES=0
                shift
                ;;
            --ip)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                EXEC_IP="$2"
                shift 2
                ;;
            --ip6)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                EXEC_IP6="$2"
                shift 2
                ;;
            --gateway)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                EXEC_GATEWAY="$2"
                shift 2
                ;;
            --mark)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                EXEC_MARK="$2"
                shift 2
                ;;
            --dscp)
                if [[ $# -lt 2 ]]; then log_err "Missing argument for $1"; usage 1; fi
                EXEC_DSCP="$2"
                shift 2
                ;;
            --)
                shift
                EXEC_CMD=("$@")
                break
                ;;
            --force)
                FORCE_CLEAN=1
                shift
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
        if [[ "${PLATFORM}" == "darwin" ]]; then
            log_err "Network namespaces (-n / --netns) are not supported on macOS (Darwin lacks network namespaces)."
            exit 1
        fi
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
        if [[ -L "${OUT_DIR}" ]]; then
            log_err "Security violation: Output directory '${OUT_DIR}' cannot be a symlink."
            exit 1
        fi
        OUT_DIR=$(resolve_path "${OUT_DIR}")
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
    if [[ "${HW_TYPE}" == "sfp" && "${PLATFORM}" == "darwin" ]]; then
        log_err "Optical SFP/QSFP DDM telemetry (-t sfp) is not supported on macOS (Darwin DriverKit does not expose SFP I2C registers)."
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
            log_err "A probe type must be specified (e.g., --arp-scan, --ndp-scan, --dhcp-discover, --dhcp-discover6, --icmp-pmtu, --tcp-syn, --eapol-check, --snmp-probe, --dns-probe, --nbns-probe)."
            exit 1
        fi
        if [[ -n "${PROBE_SRC_IP}" ]]; then
            if ! [[ "${PROBE_SRC_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                log_err "Invalid source IPv4 address format: '${PROBE_SRC_IP}'."
                exit 1
            fi
            IFS='.' read -r o1 o2 o3 o4 <<< "${PROBE_SRC_IP}"
            if [[ "$((10#$o1))" -gt 255 || "$((10#$o2))" -gt 255 || "$((10#$o3))" -gt 255 || "$((10#$o4))" -gt 255 ]]; then
                log_err "IPv4 octets must be between 0 and 255: '${PROBE_SRC_IP}'."
                exit 1
            fi
        fi
        if [[ -n "${PROBE_SRC_IP6}" ]]; then
            if ! python3 -B -c "import ipaddress, sys; ipaddress.IPv6Address(sys.argv[1])" "${PROBE_SRC_IP6}" >/dev/null 2>&1; then
                log_err "Invalid source IPv6 address format: '${PROBE_SRC_IP6}'."
                exit 1
            fi
        fi
        if [[ -n "${PROBE_SRC_MAC}" ]]; then
            if ! [[ "${PROBE_SRC_MAC}" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
                log_err "Invalid source MAC address format: '${PROBE_SRC_MAC}' (expected aa:bb:cc:dd:ee:ff)."
                exit 1
            fi
        fi
        if ! [[ "${PROBE_RATE}" =~ ^[1-9][0-9]*$ ]]; then
            log_err "Probe rate must be a positive integer."
            exit 1
        fi
        if [[ "${PROBE_RATE}" -gt 5000 ]]; then
            log_err "Probe rate exceeds safety limit (maximum 5000 pps)."
            exit 1
        fi
        if [[ "${PROBE_TYPE}" =~ ^(arp|dhcp)$ && "${PROBE_RATE}" -gt 1000 ]]; then
            log_err "Broadcast probe rate exceeds safety limit (maximum 1000 pps for ${PROBE_TYPE})."
            exit 1
        fi
        if ! [[ "${PROBE_TIMEOUT}" =~ ^[1-9][0-9]*$ ]]; then
            log_err "Probe timeout must be a positive integer in seconds."
            exit 1
        fi
        if [[ -n "${PROBE_PCP}" ]]; then
            if ! [[ "${PROBE_PCP}" =~ ^[0-7]$ ]]; then
                log_err "PCP must be an integer between 0 and 7."
                exit 1
            fi
        fi
        if [[ -n "${PROBE_DEI}" ]]; then
            if ! [[ "${PROBE_DEI}" =~ ^[01]$ ]]; then
                log_err "DEI must be 0 or 1."
                exit 1
            fi
        fi
        if [[ -n "${PROBE_QINQ_TPID}" ]]; then
            if ! [[ "${PROBE_QINQ_TPID}" =~ ^(0x[0-9a-fA-F]+|[0-9]+)$ ]]; then
                log_err "QinQ TPID must be a hex or decimal integer (e.g. 0x88a8)."
                exit 1
            fi
        fi
        if [[ -n "${PROBE_VLAN}" ]]; then
            if ! [[ "${PROBE_VLAN}" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]]; then
                log_err "VLAN ID must be an integer between 1 and 4094 (or range 'start-end')."
                exit 1
            fi
            local expanded_vlans=()
            IFS=',' read -ra vlan_tokens <<< "${PROBE_VLAN}"
            for tok in "${vlan_tokens[@]}"; do
                if [[ "${tok}" == *"-"* ]]; then
                    local v_start="${tok%%-*}"
                    local v_end="${tok##*-}"
                    local v_s_dec=$((10#$v_start))
                    local v_e_dec=$((10#$v_end))
                    if [[ "${v_s_dec}" -lt 1 || "${v_s_dec}" -gt 4094 || "${v_e_dec}" -lt 1 || "${v_e_dec}" -gt 4094 ]]; then
                        log_err "VLAN ID must be an integer between 1 and 4094."
                        exit 1
                    fi
                    if [[ "${v_s_dec}" -gt "${v_e_dec}" ]]; then
                        log_err "Invalid VLAN range '${tok}': start (${v_start}) cannot be greater than end (${v_end})."
                        exit 1
                    fi
                    for ((v = v_s_dec; v <= v_e_dec; v++)); do
                        expanded_vlans+=("${v}")
                    done
                else
                    local tok_dec=$((10#$tok))
                    if [[ "${tok_dec}" -lt 1 || "${tok_dec}" -gt 4094 ]]; then
                        log_err "VLAN ID must be an integer between 1 and 4094."
                        exit 1
                    fi
                    expanded_vlans+=("${tok_dec}")
                fi
            done
            PROBE_VLAN=$(printf "%s\n" "${expanded_vlans[@]}" | sort -n -u | paste -sd, -)
        fi
        if [[ -n "${PROBE_QINQ}" ]]; then
            if ! [[ "${PROBE_QINQ}" =~ ^[0-9]+,[0-9]+$ ]]; then
                log_err "QinQ tags must be in format 's_tag,c_tag' (e.g., 100,200)."
                exit 1
            fi
            local q_s="${PROBE_QINQ%%,*}" q_c="${PROBE_QINQ##*,}"
            local q_s_dec=$((10#$q_s)) q_c_dec=$((10#$q_c))
            if [[ "$q_s_dec" -lt 1 || "$q_s_dec" -gt 4094 || "$q_c_dec" -lt 1 || "$q_c_dec" -gt 4094 ]]; then
                log_err "QinQ tags must be integers between 1 and 4094 (got ${q_s},${q_c})."
                exit 1
            fi
        fi
    fi

    if [[ "${ACTION}" == "exec" ]]; then
        if [[ -z "${IFACE}" ]]; then
            log_err "Interface (-i) is required for exec command."
            exit 1
        fi
        if [[ ${#EXEC_CMD[@]} -eq 0 ]]; then
            log_err "Command to execute must be specified after '--' delimiter (e.g., net-tap exec -i <iface> -- <cmd> [args...])."
            exit 1
        fi
        if [[ -n "${EXEC_VLAN}" ]]; then
            if ! [[ "${EXEC_VLAN}" =~ ^[0-9]+$ ]] || [[ $((10#${EXEC_VLAN})) -lt 1 || $((10#${EXEC_VLAN})) -gt 4094 ]]; then
                log_err "VLAN ID must be an integer between 1 and 4094 (got '${EXEC_VLAN}')."
                exit 1
            fi
        fi
        if [[ -n "${EXEC_QINQ}" ]]; then
            if ! [[ "${EXEC_QINQ}" =~ ^[0-9]+,[0-9]+$ ]]; then
                log_err "QinQ tags must be in format 's_tag,c_tag' (e.g., 100,200)."
                exit 1
            fi
            local eq_s="${EXEC_QINQ%%,*}" eq_c="${EXEC_QINQ##*,}"
            local eq_s_dec=$((10#$eq_s)) eq_c_dec=$((10#$eq_c))
            if [[ "$eq_s_dec" -lt 1 || "$eq_s_dec" -gt 4094 || "$eq_c_dec" -lt 1 || "$eq_c_dec" -gt 4094 ]]; then
                log_err "QinQ tags must be integers between 1 and 4094 (got ${eq_s},${eq_c})."
                exit 1
            fi
        fi
        if [[ -n "${EXEC_PCP}" ]]; then
            if ! [[ "${EXEC_PCP}" =~ ^[0-7]$ ]]; then
                log_err "PCP must be an integer between 0 and 7."
                exit 1
            fi
        fi
        if [[ -n "${EXEC_MARK}" ]]; then
            if ! [[ "${EXEC_MARK}" =~ ^(0x[0-9a-fA-F]+|[0-9]+)$ ]]; then
                log_err "Invalid mark format: '${EXEC_MARK}'. Must be hex (e.g. 0x7a9) or integer."
                exit 1
            fi
        fi
        if [[ -n "${EXEC_DSCP}" ]]; then
            if ! [[ "${EXEC_DSCP}" =~ ^(CS[0-7]|BE|cs[0-7]|be|0x[0-9a-fA-F]+|[0-9]+)$ ]]; then
                log_err "Invalid DSCP format: '${EXEC_DSCP}'. Must be CS0-CS7, BE, hex, or integer."
                exit 1
            fi
        fi
        if [[ -n "${EXEC_IP}" ]]; then
            if ! [[ "${EXEC_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
                log_err "Invalid IP address format: '${EXEC_IP}'."
                exit 1
            fi
            if ! python3 -B -c "import ipaddress, sys; ipaddress.IPv4Interface(sys.argv[1])" "${EXEC_IP}" 2>/dev/null; then
                log_err "Invalid IP address or CIDR prefix length: '${EXEC_IP}'."
                exit 1
            fi
        fi
        if [[ -n "${EXEC_IP6}" ]]; then
            if ! [[ "${EXEC_IP6}" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
                log_err "Invalid IPv6 address format: '${EXEC_IP6}'."
                exit 1
            fi
            if ! python3 -B -c "import ipaddress, sys; ipaddress.IPv6Interface(sys.argv[1])" "${EXEC_IP6}" 2>/dev/null; then
                log_err "Invalid IPv6 address or CIDR prefix length: '${EXEC_IP6}'."
                exit 1
            fi
        fi
        if [[ -n "${EXEC_GATEWAY}" ]]; then
            if ! [[ "${EXEC_GATEWAY}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                log_err "Invalid gateway IP address format: '${EXEC_GATEWAY}'."
                exit 1
            fi
            if ! python3 -B -c "import ipaddress, sys; ipaddress.IPv4Address(sys.argv[1])" "${EXEC_GATEWAY}" 2>/dev/null; then
                log_err "Invalid gateway IP address: '${EXEC_GATEWAY}'."
                exit 1
            fi
        fi
    fi

    if [[ -n "${BPF_FILTER}" ]]; then
        local base_filter="${BPF_FILTER}"
        local expanded_clauses=("(${base_filter})")
        if ! echo "${base_filter}" | grep -qiE '\bvlan\b'; then
            expanded_clauses+=(
                "(vlan and (${base_filter}))"
                "(vlan and vlan and (${base_filter}))"
            )
        fi
        if ! echo "${base_filter}" | grep -qiE '\bmpls\b'; then
            if tcpdump -y EN10MB -d -- "mpls and (${base_filter})" >/dev/null 2>&1; then
                expanded_clauses+=("(mpls and (${base_filter}))")
            fi
        fi
        local IFS=" "
        BPF_FILTER=$(printf "%s or " "${expanded_clauses[@]}")
        BPF_FILTER="${BPF_FILTER% or }"
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

    if [[ -n "${safe_iface}" && ! -f "${STATE_FILE}" ]]; then
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
                        if [[ "${ACTION}" == "on" ]]; then
                            log_err "Interface '${req_i}' is already part of active monitoring session '${basename_f}'."
                            exit 1
                        fi
                        STATE_FILE="$f"
                        # Update IFACE to full multi-interface list for stop/status, but preserve single target for probe and exec
                        if [[ "${ACTION}" != "probe" && "${ACTION}" != "exec" ]]; then
                            IFACE="$ifaces_part"
                        fi
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
        exec)
            run_exec
            ;;
        list)
            list_sessions
            ;;
        clean)
            clean_sessions
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
