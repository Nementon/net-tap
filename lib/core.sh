#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2034 # Exported configuration defaults and ANSI styling helpers consumed across net-tap scripts
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
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- Platform Detection ---
PLATFORM="${NET_TAP_PLATFORM:-}"
if [[ -z "${PLATFORM}" ]]; then
    case "$(uname -s)" in
        Darwin*) PLATFORM="darwin" ;;
        Linux*)  PLATFORM="linux" ;;
        *)       PLATFORM="linux" ;;
    esac
fi

CORE_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -f "${CORE_LIB_DIR}/platform_${PLATFORM}.sh" ]]; then
    # shellcheck source=/dev/null
    source "${CORE_LIB_DIR}/platform_${PLATFORM}.sh"
elif [[ -n "${LIB_DIR:-}" && -f "${LIB_DIR}/platform_${PLATFORM}.sh" ]]; then
    # shellcheck source=/dev/null
    source "${LIB_DIR}/platform_${PLATFORM}.sh"
fi

# --- Portable Utility Helpers ---
resolve_path() {
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

file_stat_owner() {
    platform_stat_owner "$1"
}

file_stat_perm() {
    platform_stat_perm "$1"
}

file_stat_nlinks() {
    platform_stat_nlinks "$1"
}

get_proc_starttime() {
    platform_proc_starttime "$1"
}

get_proc_comm() {
    platform_proc_comm "$1"
}

get_proc_cmdline() {
    platform_proc_cmdline "$1"
}

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
DEFAULT_MODE="passive"       # 'passive' (zero-egress) or 'active' (controlled audit probing)

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
        clean_msg=$(printf "%s" "$*" | sed -E 's/\x1B\[[0-9;]*[mK]//g')
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

# --- Dependency Verification ---
verify_dependencies() {
    platform_verify_dependencies
}

verify_disk_space() {
    local target_dir="$1"
    local count="${2:-1}"
    local rot_size="${ROTATE_SIZE:-${DEFAULT_ROTATE_SIZE:-100}}"
    local rot_count="${ROTATE_COUNT:-${DEFAULT_ROTATE_COUNT:-10}}"
    local req_mb=$((rot_size * rot_count * count))
    local avail_mb
    
    if ! mkdir -p "${target_dir}" 2>/dev/null; then
        log_err "Cannot create output directory '${target_dir}' (read-only filesystem or permission denied)."
        exit 1
    fi
    avail_mb=$(df -Pm "${target_dir}" 2>/dev/null | awk 'NR==2 {print $4}')
    
    if [[ -z "${avail_mb}" || ! "${avail_mb}" =~ ^[0-9]+$ ]] || (( avail_mb < req_mb )); then
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
    if [[ "${PLATFORM}" == "darwin" ]]; then
        log_err "This operation requires root privileges on macOS. Please run with sudo."
        exit 1
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
    real_sfile=$(resolve_path "${sfile}" 2>/dev/null || true)
    real_sdir=$(resolve_path "${STATE_DIR}" 2>/dev/null || true)
    if [[ -z "${real_sfile}" || -z "${real_sdir}" || "${real_sfile}" != "${real_sdir}"/* ]]; then
        log_err "Security violation: State file '${sfile}' resolves outside STATE_DIR (${STATE_DIR})."
        return 1
    fi
    local sdir_owner sdir_perm
    sdir_owner=$(file_stat_owner "${real_sdir}")
    sdir_perm=$(file_stat_perm "${real_sdir}")
    if [[ "${sdir_owner}" -ne 0 && "${sdir_owner}" -ne "${EUID}" && "${sdir_owner}" -ne "${SUDO_UID:-0}" ]]; then
        log_err "Security violation: STATE_DIR '${real_sdir}' is not owned by root (UID 0) or current user."
        return 1
    fi
    if [[ "${sdir_perm: -1}" =~ [2367] ]]; then
        log_err "Security violation: STATE_DIR '${real_sdir}' is world-writable (${sdir_perm})."
        return 1
    fi
    local file_owner perm
    file_owner=$(file_stat_owner "${sfile}")
    if [[ "${EUID}" -eq 0 ]]; then
        if [[ "${file_owner}" -ne 0 && "${file_owner}" -ne "${SUDO_UID:-0}" ]]; then
            log_err "Security violation: State file '${sfile}' must be owned by root (UID 0) or invoking user (${SUDO_UID:-0})."
            return 1
        fi
    else
        if [[ "${file_owner}" -ne 0 && "${file_owner}" -ne "${EUID}" ]]; then
            log_err "Security violation: State file '${sfile}' is not owned by root (UID 0) or current user (${EUID})."
            return 1
        fi
    fi
    perm=$(file_stat_perm "${sfile}")
    if [[ "${perm}" != "600" && "${perm}" != "640" && "${perm}" != "644" && "${perm}" != "400" && "${perm}" != "440" && "${perm}" != "444" ]]; then
        log_err "Security violation: State file '${sfile}' has unsafe permissions (${perm})."
        return 1
    fi
    if [[ $(file_stat_nlinks "${sfile}") -ne 1 ]]; then
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
    # shellcheck disable=SC2016 # Intentional regex matching literal shell expansion syntax to prevent command injection
    if echo "${scontent}" | grep -qE '(\$\(|`|\${|;)'; then
        log_err "Security violation: State file '${sfile}' contains forbidden expansion characters."
        return 1
    fi
    local allowed_vars="IFACE|MODE|HW_TYPE|TIMESTAMP|NETNS|ROTATE_SIZE|ROTATE_COUNT|OUT_DIR|BPF_FILTER|PIDS_TCPDUMP|PIDS_DMESG|PIDS_IPMON|PCAP_FILES|DMESG_LOGS|LINK_LOGS|TCPDUMP_ERRS|CONFIGURED_IFACES|ORIG_[A-Za-z0-9_]+|PID_WATCHDOG|PID_AUTOSHUTDOWN"
    # shellcheck disable=SC2016 # Intentional regex matching literal shell expansion syntax to prevent command injection
    if echo "${scontent}" | grep -qvE '^(#.*|[[:space:]]*|declare (--|-a|-A) ('"${allowed_vars}"')(=([0-9]+|"[^"$`\\]*"|\([][a-zA-Z0-9_./@:+=, "-]*\)))?)$'; then
        log_err "Security violation: State file '${sfile}' contains unauthorized expressions."
        return 1
    fi
    # Use declare -g to ensure variables and associative arrays are defined in global caller scope
    # shellcheck source=/dev/null
    source <(printf "%s\n" "${scontent}" | sed 's/^declare /declare -g /')
    # Validate deserialized variables against strict whitelist patterns
    if [[ -n "${NETNS:-}" ]] && ! [[ "${NETNS}" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
        log_err "Security violation: Deserialized NETNS contains invalid characters."
        return 1
    fi
    if [[ -n "${IFACE:-}" ]] && ! [[ "${IFACE}" =~ ^[a-zA-Z0-9_.,-]+$ ]]; then
        log_err "Security violation: Deserialized IFACE contains invalid characters."
        return 1
    fi
    if [[ -n "${MODE:-}" ]] && ! [[ "${MODE}" =~ ^(passive|active)$ ]]; then
        log_err "Security violation: Deserialized MODE contains invalid value."
        return 1
    fi
    # Ensure critical execution PATH cannot be hijacked
    export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return 0
}

# --- Safe Process Termination Helper ---
safe_kill() {
    local target_pid="$1"
    local expected_comm="${2:-}"
    local expected_cmd="${3:-}"
    local expected_starttime="${4:-}"
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
        actual_comm=$(get_proc_comm "${target_pid}")
        if ! echo "${actual_comm}" | grep -qE "^(${expected_comm})$"; then
            log_warn "PID ${target_pid} comm '${actual_comm}' did not match expected '${expected_comm}'. Skipping termination."
            return 0
        fi
        if [[ -n "${expected_cmd}" ]]; then
            local actual_cmd
            actual_cmd=$(get_proc_cmdline "${target_pid}")
            if ! echo "${actual_cmd}" | grep -qE "${expected_cmd}"; then
                log_warn "PID ${target_pid} cmdline did not match expected pattern '${expected_cmd}'. Skipping termination."
                return 0
            fi
        fi
        local initial_starttime
        initial_starttime=$(get_proc_starttime "${target_pid}")
        if [[ -n "${expected_starttime}" && -n "${initial_starttime}" && "${initial_starttime}" != "${expected_starttime}" ]]; then
            log_warn "PID ${target_pid} starttime (${initial_starttime}) did not match expected (${expected_starttime}). Skipping termination to avoid killing recycled process."
            return 0
        fi

        kill -SIGTERM "${target_pid}" 2>/dev/null || true
        local count=0
        while kill -0 "${target_pid}" 2>/dev/null && [[ $count -lt 20 ]]; do
            sleep 0.1
            count=$((count + 1))
        done
        # Re-verify process identity and starttime before SIGKILL to defend against PID recycling
        if kill -0 "${target_pid}" 2>/dev/null; then
            local verify_comm
            verify_comm=$(get_proc_comm "${target_pid}")
            if ! echo "${verify_comm}" | grep -qE "^(${expected_comm})$"; then
                log_warn "PID ${target_pid} identity changed during shutdown (new comm: '${verify_comm}'). Skipping SIGKILL to avoid killing recycled process."
                return 0
            fi
            if [[ -n "${expected_cmd}" ]]; then
                local verify_cmd
                verify_cmd=$(get_proc_cmdline "${target_pid}")
                if ! echo "${verify_cmd}" | grep -qE "${expected_cmd}"; then
                    log_warn "PID ${target_pid} cmdline changed during shutdown. Skipping SIGKILL."
                    return 0
                fi
            fi
            local verify_starttime
            verify_starttime=$(get_proc_starttime "${target_pid}")
            if [[ -n "${initial_starttime}" && -n "${verify_starttime}" && "${verify_starttime}" != "${initial_starttime}" ]]; then
                log_warn "PID ${target_pid} starttime changed during shutdown (${verify_starttime} != ${initial_starttime}). Skipping SIGKILL to avoid killing recycled process."
                return 0
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
declare -g -a HELD_LOCK_DIRS=()

_close_fd() {
    local target_fd="$1"
    if [[ "${target_fd}" =~ ^[0-9]+$ ]]; then
        eval "exec ${target_fd}>&-" 2>/dev/null || true
    fi
}

_is_lockdir_stale() {
    local target_dir="$1"
    if [[ -d "${target_dir}" ]]; then
        local pid_file="${target_dir}/pid"
        if [[ -f "${pid_file}" ]]; then
            local owner_pid
            owner_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
            if [[ -n "${owner_pid}" && "${owner_pid}" =~ ^[0-9]+$ ]]; then
                if ! kill -0 "${owner_pid}" 2>/dev/null; then
                    return 0 # Deceased PID
                fi
                return 1 # Active PID
            fi
        fi
        local now_t mtime_t
        now_t=$(date +%s)
        mtime_t=$(platform_stat_mtime "${target_dir}")
        if [[ -n "${mtime_t}" && "${mtime_t}" =~ ^[0-9]+$ ]] && (( now_t - mtime_t > 30 )); then
            return 0
        fi
    fi
    return 1
}

_acquire_atomic_lockdir() {
    local target_dir="$1"
    local timeout="${2:-10}"
    local start_t
    start_t=$(date +%s)
    while ! mkdir "${target_dir}" 2>/dev/null; do
        if _is_lockdir_stale "${target_dir}"; then
            log_warn "Detected stale directory lock '${target_dir}' from deceased process. Purging..."
            rm -rf "${target_dir}" 2>/dev/null || true
            if mkdir "${target_dir}" 2>/dev/null; then
                break
            fi
        fi
        local now_t
        now_t=$(date +%s)
        if (( now_t - start_t >= timeout )); then
            return 1
        fi
        sleep 0.1
    done
    echo "$$" > "${target_dir}/pid" 2>/dev/null || true
    return 0
}

acquire_lock() {
    local target="${1:-global}"
    mkdir -p "${STATE_DIR}"
    chmod 755 "${STATE_DIR}"

    local master_lock="${STATE_DIR}/.lock_master"
    if [[ -L "${master_lock}" ]]; then
        log_err "Security violation: Master lock '${master_lock}' is a symlink!"
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

    if command -v flock >/dev/null 2>&1 && [[ -z "${NET_TAP_NO_FLOCK:-}" ]]; then
        local master_fd
        exec {master_fd}>>"${master_lock}"
        if ! flock -x -w 10 "${master_fd}"; then
            _close_fd "${master_fd}"
            log_err "Could not acquire master lock on ${master_lock} within 10s."
            exit 1
        fi

        if [[ ${#if_list[@]} -eq 0 ]]; then
            local global_lockfile="${STATE_DIR}/.lock_${lock_prefix}global"
            if [[ -L "${global_lockfile}" ]]; then
                log_err "Security violation: Lock file '${global_lockfile}' is a symlink!"
                flock -u "${master_fd}" 2>/dev/null || true
                _close_fd "${master_fd}"
                exit 1
            fi
            local g_fd
            exec {g_fd}>>"${global_lockfile}"
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
            local newly_acquired_fds=()
            for dev in "${if_list[@]}"; do
                local dev_lockfile="${STATE_DIR}/.lock_${lock_prefix}${dev}"
                if [[ -L "${dev_lockfile}" ]]; then
                    log_err "Security violation: Lock file '${dev_lockfile}' is a symlink!"
                    flock -u "${master_fd}" 2>/dev/null || true
                    _close_fd "${master_fd}"
                    for n_fd in "${newly_acquired_fds[@]}"; do
                        flock -u "${n_fd}" 2>/dev/null || true
                        _close_fd "${n_fd}"
                    done
                    exit 1
                fi
                local d_fd
                exec {d_fd}>>"${dev_lockfile}"
                if ! flock -x -n "${d_fd}"; then
                    _close_fd "${d_fd}"
                    flock -u "${master_fd}" 2>/dev/null || true
                    _close_fd "${master_fd}"
                    log_err "Constituent interface '${dev}' is currently locked by another active session."
                    for n_fd in "${newly_acquired_fds[@]}"; do
                        flock -u "${n_fd}" 2>/dev/null || true
                        _close_fd "${n_fd}"
                    done
                    exit 1
                fi
                newly_acquired_fds+=("${d_fd}")
            done
            HELD_LOCK_FDS+=("${newly_acquired_fds[@]}")
        fi

        flock -u "${master_fd}" 2>/dev/null || true
        _close_fd "${master_fd}"
    else
        # Directory-based atomic locking fallback for macOS Darwin when util-linux flock is absent
        local master_dir="${master_lock}.lockdir"
        if ! _acquire_atomic_lockdir "${master_dir}" 10; then
            log_err "Could not acquire directory master lock within 10s."
            exit 1
        fi

        if [[ ${#if_list[@]} -eq 0 ]]; then
            local global_lockdir="${STATE_DIR}/.lock_${lock_prefix}global.lockdir"
            if ! _acquire_atomic_lockdir "${global_lockdir}" 10; then
                rm -rf "${master_dir}" 2>/dev/null || true
                log_err "Could not acquire global session lock."
                exit 1
            fi
            HELD_LOCK_DIRS+=("${global_lockdir}")
        else
            local newly_acquired_dirs=()
            for dev in "${if_list[@]}"; do
                local dev_lockdir="${STATE_DIR}/.lock_${lock_prefix}${dev}.lockdir"
                if ! _acquire_atomic_lockdir "${dev_lockdir}" 0; then
                    rm -rf "${master_dir}" 2>/dev/null || true
                    log_err "Constituent interface '${dev}' is currently locked by another active session."
                    for n_dir in "${newly_acquired_dirs[@]}"; do
                        rm -rf "${n_dir}" 2>/dev/null || true
                    done
                    exit 1
                fi
                newly_acquired_dirs+=("${dev_lockdir}")
            done
            HELD_LOCK_DIRS+=("${newly_acquired_dirs[@]}")
        fi

        rm -rf "${master_dir}" 2>/dev/null || true
    fi
}

release_lock() {
    for fd in ${HELD_LOCK_FDS[@]+"${HELD_LOCK_FDS[@]}"}; do
        flock -u "${fd}" 2>/dev/null || true
        _close_fd "${fd}"
    done
    HELD_LOCK_FDS=()
    for ldir in ${HELD_LOCK_DIRS[@]+"${HELD_LOCK_DIRS[@]}"}; do
        rm -rf "${ldir}" 2>/dev/null || true
    done
    HELD_LOCK_DIRS=()
}

# --- Usage Banner ---
usage() {
    local exit_code="${1:-1}"
    cat <<EOF
Usage: $0 <on|off|status|analyze|probe|exec|list|clean> [options]
(Note: 'on', 'off', 'probe', 'exec', and 'clean' require sudo / root privileges)

Commands:
  on        Enable tap mode, monitor carrier status, and spawn background capture.
  off       Stop capture, terminate background loggers, and reset the NIC to default.
  status    Check interface carrier state (Active/Inactive), link params, and capture stats.
  analyze   Deep-analyze PCAPs and log files in a target directory to deduce network config.
  probe     Execute active, controlled discovery probes with audit logging and rate-limiting.
  exec      Execute arbitrary third-party command with egress watermarking and optional VLAN tagging.
  list      Enumerate all active net-tap sessions and background captures.
  clean     Reconcile crashed sessions, purge stale locks, and detach dangling filters.

Options:
  -i, --interface <iface>   Target network interface (required for on, off, status, probe, exec; optional for list, clean).
  -n, --netns <name>        Target Linux network namespace to run the capture in (Linux only).
  -m, --mode <mode>         Operational mode: 'passive' (zero-egress) or 'active' (audit probes permitted).
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
  -j, --json                Output analyze or list results as JSON (suppresses human-readable text).
  --force                   Force cleanup and termination of running captures during 'clean'.
  -h, --help                Show this help message.

Probe Options (for 'probe' command):
  --arp-scan <cidr>         Scan IPv4 subnet via ARP requests (e.g., 192.168.1.0/24).
  --ndp-scan <cidr>         Scan IPv6 subnet via ICMPv6 Neighbor/Router Solicitations.
  --dhcp-discover           Broadcast RFC 2131 DHCP Discover (IPv4).
  --dhcp-discover6          Transmit RFC 8415 DHCPv6 Solicit (IPv6, alias: --dhcp6-discover).
  --icmp-pmtu <target>      Measure Path MTU using stepped DF-bit ICMP Echo requests.
  --tcp-syn <target>        Probe TCP port availability using single SYN packets.
  --eapol-check             Audit 802.1X Network Access Control via EAPOL-Start frame (alias: --eapol-probe).
  --snmp-probe <target>     Probe SNMPv2c sysDescr.0 via single UDP 161 frame.
  --dns-probe <target>      Probe DNS server version via CHAOS TXT version.bind query.
  --nbns-probe <target>     Probe NetBIOS Name Service Node Status on UDP 137.
  -p, --ports <ports>       Target port list for TCP probe (e.g., 22,80,443; default: 22,80,443).
  --src-ip <ip>             Custom source IPv4 address for active probes.
  --src-ip6 <ipv6>          Custom source IPv6 address for active probes.
  --src-mac <mac>           Custom source MAC address for active probes.
  --community <str>         SNMP community string (default: public).
  --vlan <vid>              Inject probes with IEEE 802.1Q VLAN tag(s) (e.g. 100, 10-20, or 10,20,100-105).
  --qinq <s-tag,c-tag>      Inject probes with double-tagged QinQ headers (e.g., 100,200).
  --auto-vlans              Automatically probe across all VLANs passively observed on link.
  --pcp <0-7>               IEEE 802.1p Priority Code Point (default: 0).
  --dei <0|1>               IEEE 802.1Q Drop Eligible Indicator bit (default: 0).
  --qinq-tpid <hex>         Outer VLAN TPID / EtherType (e.g. 0x88a8, 0x8100; default: 0x88a8).
  --rate <pps>              Maximum probe transmission rate in packets/sec (default: 50).
  --timeout <sec>           Probe execution timeout in seconds (default: 5).
  --audit-id <id>           Custom audit identifier for probe correlation (default: auto).

Exec Options (for 'exec' command):
  -- <cmd> [args...]        Command and arguments to execute through active tap session.
  --vlan <vid>              Force IEEE 802.1Q VLAN encapsulation (stateful netns by default).
  --stateless-vlan          Use stateless tc act_vlan push/pop datapath instead of netns (alias: --raw).
  --qinq <s-tag,c-tag>      Force IEEE 802.1ad QinQ double-tagging (stateless tc act_vlan).
  --ip <cidr>               Assign static IPv4 address/mask to virtual interface in netns (e.g. 192.168.1.50/24).
  --ip6 <cidr>              Assign static IPv6 address/prefix to virtual interface in netns.
  --pcp <0-7>               IEEE 802.1p Priority Code Point for VLAN tag (default: 7).
  --dscp <class|num>        Wire watermark DSCP class (e.g. CS7, 0x38; default: CS7).
  --mark <hex>              Internal firewall watermark value (default: 0x7a9).
  --auto-baby-giant         Automatically adjust parent physical MTU (1504/1508) to fit 802.1Q tags.
  --no-drop-privileges      Do not drop root privileges to invoking user (\$SUDO_USER).

Examples:
  sudo $0 on -i eth1 -o /data/trace
  sudo $0 on -i eth1 --mode active -o /data/trace
  sudo $0 exec -i eth1 -- curl -s http://192.168.1.1
  sudo $0 exec -i eth1 --vlan 100 --ip 192.168.100.50/24 -- iperf3 -c 192.168.100.1
  sudo $0 exec -i eth1 --stateless-vlan --vlan 100 -- tcpreplay -i eth1 traffic.pcap
  sudo $0 probe -i eth1 --arp-scan 192.168.1.0/24
  sudo $0 probe -i eth1 --vlan 100 --arp-scan 10.100.1.0/24
  sudo $0 probe -i eth1 --auto-vlans --arp-scan 10.0.0.0/24
  sudo $0 probe -i eth1 --dhcp-discover
  sudo $0 probe -i eth1 --eapol-check
  sudo $0 probe -i eth1 --snmp-probe 192.168.1.1
  sudo $0 probe -i eth1 --dns-probe 192.168.1.1
  sudo $0 probe -i eth1 --nbns-probe 192.168.1.50
  sudo $0 probe -i eth1 --tcp-syn 192.168.1.50 --src-ip 192.168.1.253 -p 80,443
  $0 status -i eth1
  sudo $0 off -i eth1
  $0 analyze -d /data/trace
EOF
    exit "${exit_code}"
}

# --- Network Namespace Helper ---
cmd_netns() {
    if [[ -n "${NETNS:-}" ]]; then
        if [[ "${PLATFORM:-linux}" == "darwin" ]]; then
            log_err "Network namespaces (-n / --netns) are not supported on macOS."
            exit 1
        fi
        ip netns exec "${NETNS}" "$@"
    else
        "$@"
    fi
}
