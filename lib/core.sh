#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2034
#
# lib/core.sh - Core Logging, Configuration Defaults, and Dependency Verification
#
# Capabilities:
#   - Detects physical/carrier port states (Active / Inactive / DDM Optical power)
#   - Puts NIC into zero-egress silent promiscuous mode with tc egress drop
#   - Captures background traffic into a rotating PCAP ring buffer
#   - Collects dmesg, link carrier, and optical diagnostics
#   - Deep-analyzes captured PCAPs and system logs to infer VLANs, subnets,
#     hosts, gateways, switch topology, and Layer 2 security controls (802.1X, etc.)
#

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- Default Settings ---
DEFAULT_OUT_DIR="./captures"
DEFAULT_HW_TYPE="ethernet" # 'ethernet' or 'sfp'
DEFAULT_SPEED=""           # e.g., 1000 or 10000 (used for SFP)
DEFAULT_ROTATE_SIZE="100"  # Size in MB per chunk
DEFAULT_ROTATE_COUNT="10"  # Ring buffer file count
STATE_DIR="${STATE_DIR:-/var/run/net-tap}"
COMPRESS_PCAPS="${COMPRESS_PCAPS:-0}"
JSON_OUT="${JSON_OUT:-0}"
BPF_FILTER="${BPF_FILTER:-}"

# --- Styling Helpers ---
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_RED=$'\033[31m'
C_CYAN=$'\033[36m'
C_MAGENTA=$'\033[35m'

# --- Syslog Integration ---
_syslog() {
    local level="$1"
    shift
    if command -v logger >/dev/null 2>&1; then
        local clean_msg
        clean_msg=$(printf "%s" "$*" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
        logger -t net-tap "[${level}] ${clean_msg}" || true
    fi
}

log_info()  { 
    printf "%s %s\n" "${C_CYAN}[INFO]${C_RESET}" "$*" >&2
    _syslog "INFO" "$*"
}
log_ok()    { 
    printf "%s %s\n" "${C_GREEN}[OK]${C_RESET}" "$*" >&2
    _syslog "OK" "$*"
}
log_warn()  { 
    printf "%s %s\n" "${C_YELLOW}[WARN]${C_RESET}" "$*" >&2
    _syslog "WARN" "$*"
}
log_err()   { 
    printf "%s %s\n" "${C_RED}[ERROR]${C_RESET}" "$*" >&2
    _syslog "ERROR" "$*"
}

# --- Carrier-Grade Verifications ---
verify_dependencies() {
    local missing=()
    for cmd in ip tc tcpdump ethtool awk dmesg grep sed find ss df du mktemp readlink gzip flock sysctl stat date; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_err "Missing required dependencies: ${missing[*]}"
        exit 1
    fi
}

verify_disk_space() {
    local target_dir="$1"
    local count="${2:-1}"
    local req_mb=$((ROTATE_SIZE * ROTATE_COUNT * count))
    local avail_mb
    
    mkdir -p "${target_dir}"
    avail_mb=$(df -Pm "${target_dir}" 2>/dev/null | awk 'NR==2 {print $4}')
    
    if [[ -z "${avail_mb}" ]] || [[ "${avail_mb}" -lt "${req_mb}" ]]; then
        log_err "Insufficient disk space in ${target_dir}."
        log_err "Required: ${req_mb}MB, Available: ${avail_mb:-0}MB."
        exit 1
    fi
}

# --- Check Root / Capability Privileges ---
require_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi
    if command -v capsh >/dev/null 2>&1; then
        if [[ -n "${NETNS:-}" ]]; then
            if capsh --has-p=cap_net_admin 2>/dev/null && capsh --has-p=cap_net_raw 2>/dev/null && capsh --has-p=cap_sys_admin 2>/dev/null; then
                return 0
            fi
        else
            if capsh --has-p=cap_net_admin 2>/dev/null && capsh --has-p=cap_net_raw 2>/dev/null; then
                return 0
            fi
        fi
    fi
    if [[ -n "${NETNS:-}" ]]; then
        log_err "Operating within network namespaces (-n) requires root privileges or CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN. Please run with sudo."
    else
        log_err "This operation requires root privileges or CAP_NET_ADMIN + CAP_NET_RAW. Please run with sudo."
    fi
    exit 1
}

# --- Safe Deserialization Helper ---
load_state_file() {
    local sfile="$1"
    if [[ ! -f "${sfile}" || -L "${sfile}" ]]; then
        log_err "Security violation: State file '${sfile}' does not exist or is a symlink."
        return 1
    fi
    local real_sfile real_sdir
    real_sfile=$(readlink -f "${sfile}" 2>/dev/null || true)
    real_sdir=$(readlink -f "${STATE_DIR}" 2>/dev/null || true)
    if [[ -z "${real_sfile}" || -z "${real_sdir}" || "${real_sfile}" != "${real_sdir}"/* ]]; then
        log_err "Security violation: State file '${sfile}' resolves outside STATE_DIR (${STATE_DIR})."
        return 1
    fi
    local sdir_owner sdir_perm
    sdir_owner=$(stat -c "%u" "${real_sdir}" 2>/dev/null || echo "-1")
    sdir_perm=$(stat -c "%a" "${real_sdir}" 2>/dev/null || echo "777")
    if [[ "${sdir_owner}" -ne 0 && "${sdir_owner}" -ne "${EUID}" ]]; then
        log_err "Security violation: STATE_DIR '${real_sdir}' is not owned by root (UID 0) or current user."
        return 1
    fi
    if [[ "${sdir_perm: -1}" =~ [2367] ]]; then
        log_err "Security violation: STATE_DIR '${real_sdir}' is world-writable (${sdir_perm})."
        return 1
    fi
    local file_owner perm
    file_owner=$(stat -c "%u" "${sfile}" 2>/dev/null || echo "-1")
    if [[ "${file_owner}" -ne 0 && "${file_owner}" -ne "${EUID}" ]]; then
        log_err "Security violation: State file '${sfile}' is not owned by root (UID 0) or current user."
        return 1
    fi
    perm=$(stat -c "%a" "${sfile}" 2>/dev/null || echo "777")
    if [[ "${perm}" != "600" && "${perm}" != "640" && "${perm}" != "644" && "${perm}" != "400" && "${perm}" != "440" && "${perm}" != "444" ]]; then
        log_err "Security violation: State file '${sfile}' has unsafe permissions (${perm})."
        return 1
    fi
    if [[ $(stat -c "%h" "${sfile}" 2>/dev/null || echo "0") -ne 1 ]]; then
        log_err "Security violation: State file '${sfile}' has multiple hard links."
        return 1
    fi
    # Atomically read content once to prevent TOCTOU file swap race conditions
    local scontent
    scontent=$(cat "${sfile}" 2>/dev/null || true)
    if [[ -z "${scontent}" ]]; then
        log_err "Security violation: State file '${sfile}' is empty or unreadable."
        return 1
    fi
    # shellcheck disable=SC2016
    if echo "${scontent}" | grep -qE '(\$\(|`|\${|;|\||&|<|>)'; then
        log_err "Security violation: State file '${sfile}' contains forbidden expansion characters."
        return 1
    fi
    local allowed_vars="IFACE|HW_TYPE|TIMESTAMP|NETNS|ROTATE_SIZE|ROTATE_COUNT|OUT_DIR|PIDS_TCPDUMP|PIDS_DMESG|PIDS_IPMON|PCAP_FILES|DMESG_LOGS|LINK_LOGS|TCPDUMP_ERRS|CONFIGURED_IFACES|ORIG_[A-Za-z0-9_]+|PID_WATCHDOG|PID_AUTOSHUTDOWN"
    # shellcheck disable=SC2016
    if echo "${scontent}" | grep -qvE '^(#.*|[[:space:]]*|declare (--|-a|-A) ('"${allowed_vars}"')(=([0-9]+|"[^"$`\\]*"|\([][a-zA-Z0-9_./@:+=, "-]*\)))?)$'; then
        log_err "Security violation: State file '${sfile}' contains unauthorized expressions."
        return 1
    fi
    # Use declare -g to ensure variables and associative arrays are defined in global caller scope
    # shellcheck source=/dev/null
    source <(printf "%s\n" "${scontent}" | sed 's/^declare /declare -g /')
    # Ensure critical execution PATH cannot be hijacked
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return 0
}

# --- Safe Process Termination Helper ---
safe_kill() {
    local target_pid="$1"
    local expected_comm="${2:-}"
    local expected_cmd="${3:-}"
    [[ -z "${target_pid}" ]] && return 0

    if ! [[ "${target_pid}" =~ ^[1-9][0-9]*$ ]]; then
        log_warn "safe_kill called with invalid PID '${target_pid}'."
        return 1
    fi

    if [[ "${target_pid}" -eq $$ || "${target_pid}" -eq "${PPID:-0}" || "${target_pid}" -le 1 ]]; then
        log_warn "Refusing to kill self, parent, or init (PID ${target_pid})."
        return 1
    fi

    if [[ -z "${expected_comm}" ]]; then
        log_err "safe_kill called without expected process binary name for PID ${target_pid}."
        return 1
    fi

    if kill -0 "${target_pid}" 2>/dev/null; then
        local actual_comm
        actual_comm=$(cat "/proc/${target_pid}/comm" 2>/dev/null || echo "")
        if ! echo "${actual_comm}" | grep -qE "^(${expected_comm})$"; then
            log_warn "PID ${target_pid} comm '${actual_comm}' did not match expected '${expected_comm}'. Skipping termination."
            return 0
        fi
        if [[ -n "${expected_cmd}" ]]; then
            local actual_cmd
            actual_cmd=$(tr '\0' ' ' < "/proc/${target_pid}/cmdline" 2>/dev/null || echo "")
            if ! echo "${actual_cmd}" | grep -qE "${expected_cmd}"; then
                log_warn "PID ${target_pid} cmdline did not match expected pattern '${expected_cmd}'. Skipping termination."
                return 0
            fi
        fi
        kill -SIGTERM "${target_pid}" 2>/dev/null || true
        local count=0
        while kill -0 "${target_pid}" 2>/dev/null && [[ $count -lt 20 ]]; do
            sleep 0.1
            count=$((count + 1))
        done
        # Re-verify process identity before SIGKILL to defend against PID recycling
        if kill -0 "${target_pid}" 2>/dev/null; then
            local verify_comm
            verify_comm=$(cat "/proc/${target_pid}/comm" 2>/dev/null || echo "")
            if ! echo "${verify_comm}" | grep -qE "^(${expected_comm})$"; then
                log_warn "PID ${target_pid} identity changed during shutdown (new comm: '${verify_comm}'). Skipping SIGKILL to avoid killing recycled process."
                return 0
            fi
            if [[ -n "${expected_cmd}" ]]; then
                local verify_cmd
                verify_cmd=$(tr '\0' ' ' < "/proc/${target_pid}/cmdline" 2>/dev/null || echo "")
                if ! echo "${verify_cmd}" | grep -qE "${expected_cmd}"; then
                    log_warn "PID ${target_pid} cmdline changed during shutdown. Skipping SIGKILL."
                    return 0
                fi
            fi
            kill -9 "${target_pid}" 2>/dev/null || true
            local kill_count=0
            while kill -0 "${target_pid}" 2>/dev/null && [[ $kill_count -lt 10 ]]; do
                sleep 0.05
                kill_count=$((kill_count + 1))
            done
        fi
        wait "${target_pid}" 2>/dev/null || true
    fi
}

# --- POSIX Session Lock Helpers ---
declare -g -a HELD_LOCK_FDS=()

_close_fd() {
    local target_fd="$1"
    if [[ "${target_fd}" =~ ^[0-9]+$ ]]; then
        eval "exec ${target_fd}>&-" 2>/dev/null || true
    fi
}

acquire_lock() {
    local target="${1:-global}"
    mkdir -p "${STATE_DIR}"
    chmod 755 "${STATE_DIR}"

    # Acquire master lock to serialize lock acquisitions
    local master_lock="${STATE_DIR}/.lock_master"
    local master_fd
    exec {master_fd}>"${master_lock}"
    if ! flock -x -w 10 "${master_fd}"; then
        _close_fd "${master_fd}"
        log_err "Could not acquire master lock on ${master_lock} within 10s."
        exit 1
    fi

    local safe_target="${target//\//_}"
    local safe_ns="${NETNS:-}"
    safe_ns="${safe_ns//\//_}"
    local lock_prefix=""
    [[ -n "${safe_ns}" ]] && lock_prefix="${safe_ns}__"

    local if_list=()
    if [[ "${safe_target}" == *","* ]]; then
        IFS=',' read -ra if_list <<< "${safe_target}"
    elif [[ "${safe_target}" != "global" ]]; then
        if_list=("${safe_target}")
    fi

    if [[ ${#if_list[@]} -eq 0 ]]; then
        local global_lockfile="${STATE_DIR}/.lock_${lock_prefix}global"
        local g_fd
        exec {g_fd}>"${global_lockfile}"
        if ! flock -x -w 10 "${g_fd}"; then
            _close_fd "${g_fd}"
            flock -u "${master_fd}" 2>/dev/null || true
            _close_fd "${master_fd}"
            release_lock
            log_err "Could not acquire global session lock."
            exit 1
        fi
        HELD_LOCK_FDS+=("${g_fd}")
    else
        for dev in "${if_list[@]}"; do
            local dev_lockfile="${STATE_DIR}/.lock_${lock_prefix}${dev}"
            local d_fd
            exec {d_fd}>"${dev_lockfile}"
            if ! flock -x -n "${d_fd}"; then
                _close_fd "${d_fd}"
                flock -u "${master_fd}" 2>/dev/null || true
                _close_fd "${master_fd}"
                log_err "Constituent interface '${dev}' is currently locked by another active session."
                release_lock
                exit 1
            fi
            HELD_LOCK_FDS+=("${d_fd}")
        done
    fi

    # Release master lock now that specific device locks are held
    flock -u "${master_fd}" 2>/dev/null || true
    _close_fd "${master_fd}"
}

release_lock() {
    for fd in "${HELD_LOCK_FDS[@]:-}"; do
        flock -u "${fd}" 2>/dev/null || true
        _close_fd "${fd}"
    done
    HELD_LOCK_FDS=()
}

# --- Usage Banner ---
usage() {
    local exit_code="${1:-1}"
    cat <<EOF
Usage: $0 <on|off|status|analyze> [options]
(Note: 'on' and 'off' require sudo / root privileges)

Commands:
  on        Enable silent tap mode, monitor carrier status, and spawn background capture.
  off       Stop capture, terminate background loggers, and reset the NIC to default.
  status    Check interface carrier state (Active/Inactive), link params, and capture stats.
  analyze   Deep-analyze PCAPs and log files in a target directory to deduce network config.

Options:
  -i, --interface <iface>   Target network interface (required for on, off, status).
  -n, --netns <name>        Target Linux network namespace to run the capture in.
  -t, --type <type>         Hardware type: 'ethernet' or 'sfp' (default: ${DEFAULT_HW_TYPE}).
  -o, --output-dir <path>   Directory to store or read logs/captures (default: ${DEFAULT_OUT_DIR}).
  -d, --dir <path>          Alias for -o when running 'analyze'.
  -s, --speed <speed>       Force link speed in Mbps for SFP (e.g., 1000, 10000).
  -C, --rotate-size <MB>    Ring-buffer max size per PCAP file in MB (default: ${DEFAULT_ROTATE_SIZE}).
  -W, --rotate-count <num>  Ring-buffer maximum file count (default: ${DEFAULT_ROTATE_COUNT}).
  -f, --filter <bpf>        BPF capture filter (e.g., "(ip or ip6 or arp) or (vlan and (ip or ip6))").
  -D, --duration <sec>      Auto-shutdown timer in seconds (e.g., 3600 for 1 hour).
  -z, --gzip                Enable gzip compression for rotated PCAP chunks.
  -w, --watchdog-threshold <pct> Disk watchdog shutdown threshold % (default: 85).
  -j, --json                Output analyze results as JSON (suppresses human-readable text).
  -h, --help                Show this help message.

Examples:
  sudo $0 on -i eth1 -o /data/trace
  sudo $0 on -i sfp0,sfp1 -t sfp -o /data/trace -z -D 3600
  $0 status -i eth1
  sudo $0 off -i eth1
  $0 analyze -d /data/trace
EOF
    exit "${exit_code}"
}

# --- Network Namespace Helper ---
cmd_netns() {
    if [[ -n "${NETNS:-}" ]]; then
        ip netns exec "${NETNS}" "$@"
    else
        "$@"
    fi
}
