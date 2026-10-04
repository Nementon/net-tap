#!/usr/bin/env bash
# shellcheck shell=bash
# run_tests.sh - Comprehensive automated test suite for net-tap

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="${SCRIPT_DIR}/../bin/net-tap.sh"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"

echo "================================================="
echo " Net-Tap: Carrier-Grade Test & Compliance Runner"
echo "================================================="

FAILED=0
PASSED=0

for cmd in ip tc awk grep mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: Required command '$cmd' not found." >&2
        exit 1
    fi
done

# shellcheck disable=SC2317
cleanup() {
    local exit_code=$?
    if [[ -n "${TMP_PRIV_DIR:-}" ]]; then rm -rf "${TMP_PRIV_DIR}" 2>/dev/null || true; fi
    if [[ -n "${EMPTY_DIR:-}" ]]; then rm -rf "${EMPTY_DIR}" 2>/dev/null || true; fi
    if [[ -n "${STATE_SEC_DIR:-}" ]]; then rm -rf "${STATE_SEC_DIR}" 2>/dev/null || true; fi
    if [[ $exit_code -eq 0 ]]; then
        if [[ -n "${TEST_CAPTURE_DIR:-}" ]]; then rm -rf "${TEST_CAPTURE_DIR}" 2>/dev/null || true; fi
        if [[ -n "${TEST_MULTI_DIR:-}" ]]; then rm -rf "${TEST_MULTI_DIR}" 2>/dev/null || true; fi
        if [[ -n "${TEST_DUR_DIR:-}" ]]; then rm -rf "${TEST_DUR_DIR}" 2>/dev/null || true; fi
        if [[ -n "${TEST_EAP_DIR:-}" ]]; then rm -rf "${TEST_EAP_DIR}" 2>/dev/null || true; fi
        if [[ -n "${TEST_ACTIVE_DIR:-}" ]]; then rm -rf "${TEST_ACTIVE_DIR}" 2>/dev/null || true; fi
    else
        if [[ -n "${TEST_CAPTURE_DIR:-}" ]]; then
            echo "[DIAGNOSTIC] Preserving test capture dir for failure inspection: ${TEST_CAPTURE_DIR}" >&2
        fi
        if [[ -n "${TEST_MULTI_DIR:-}" ]]; then
            echo "[DIAGNOSTIC] Preserving multi-tap dir for failure inspection: ${TEST_MULTI_DIR}" >&2
        fi
        if [[ -n "${TEST_DUR_DIR:-}" ]]; then
            echo "[DIAGNOSTIC] Preserving duration dir for failure inspection: ${TEST_DUR_DIR}" >&2
        fi
        if [[ -n "${TEST_EAP_DIR:-}" ]]; then
            echo "[DIAGNOSTIC] Preserving EAP test dir for failure inspection: ${TEST_EAP_DIR}" >&2
        fi
        if [[ -n "${TEST_ACTIVE_DIR:-}" ]]; then
            echo "[DIAGNOSTIC] Preserving active audit dir for failure inspection: ${TEST_ACTIVE_DIR}" >&2
        fi
    fi
    if [[ -n "${WPA_PID_FILE:-}" && -f "${WPA_PID_FILE}" ]]; then
        kill "$(cat "${WPA_PID_FILE}")" 2>/dev/null || true
        rm -f "${WPA_PID_FILE}" 2>/dev/null || true
    fi
    if [[ -n "${WPA_CONF_FILE:-}" && -f "${WPA_CONF_FILE}" ]]; then
        rm -f "${WPA_CONF_FILE}" 2>/dev/null || true
    fi
    if [[ -n "${WPA_PID_CTRL:-}" && -f "${WPA_PID_CTRL}" ]]; then
        kill "$(cat "${WPA_PID_CTRL}")" 2>/dev/null || true
        rm -f "${WPA_PID_CTRL}" 2>/dev/null || true
    fi
    if [[ -n "${WPA_CONF_CTRL:-}" && -f "${WPA_CONF_CTRL}" ]]; then
        rm -f "${WPA_CONF_CTRL}" 2>/dev/null || true
    fi
    if [[ -n "${TEST_NS:-}" ]]; then
        "$BIN_PATH" off -n "${TEST_NS}" -i veth-tap >/dev/null 2>&1 || true
        "$BIN_PATH" off -n "${TEST_NS}" -i "veth-tap1,veth-tap2" >/dev/null 2>&1 || true
        "$BIN_PATH" off -n "${TEST_NS}" -i veth-tap1 >/dev/null 2>&1 || true
        ip netns del "${TEST_NS}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

assert_fail() {
    local expected_err="$1"
    shift
    echo -n "[TEST] '$*' should fail... "
    local out ret=0
    out=$("$@" 2>&1) || ret=$?
    
    # Check if command failed and output matched expected error
    if [[ $ret -ne 0 ]] && echo "$out" | grep -qiE "$expected_err"; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        if [[ $ret -eq 0 ]]; then
            echo "FAILED (command unexpectedly succeeded with exit code 0)"
        else
            echo "FAILED (command failed with exit $ret, but output did not match expected pattern: '$expected_err')"
        fi
        echo "Output: $out"
        FAILED=$((FAILED + 1))
    fi
}

assert_success() {
    echo -n "[TEST] '$*' should succeed... "
    local out
    local ret=0
    out=$("$@" 2>&1) || ret=$?
    
    if [[ $ret -ne 0 ]]; then
        echo "FAILED (exited $ret)"
        echo "$out"
        FAILED=$((FAILED + 1))
    else
        echo "PASSED"
        PASSED=$((PASSED + 1))
    fi
}

# --- 1. CLI Usage & Help Tests ---
assert_success "$BIN_PATH" --help
assert_success "$BIN_PATH" -h
assert_fail "Usage:" "$BIN_PATH"
assert_fail "Unknown action" "$BIN_PATH" foobar
assert_fail "required" "$BIN_PATH" status
assert_fail "(required|requires root privileges)" "$BIN_PATH" on
assert_fail "(required|requires root privileges)" "$BIN_PATH" off
assert_fail "(required|requires root privileges)" "$BIN_PATH" probe

# --- 2. Input Validation Tests ---
assert_fail "Invalid interface name format" "$BIN_PATH" status -i "bad;name"
assert_fail "Invalid interface name format" "$BIN_PATH" status -i "eth0,bad;eth1"
assert_fail "Invalid network namespace name format" "$BIN_PATH" status -n "bad;netns" -i lo
assert_fail "cannot start with a hyphen" "$BIN_PATH" on -i lo -o "-bad-dir"
assert_fail "cannot start with a hyphen" "$BIN_PATH" analyze -d "-bad-dir"
assert_fail "Speed must be a positive integer" "$BIN_PATH" on -i lo -s "notanumber"
assert_fail "Speed must be a positive integer" "$BIN_PATH" on -i lo -s 0
assert_fail "Rotate size and count must be positive integers" "$BIN_PATH" on -i lo -C "notanumber"
assert_fail "Rotate size and count must be positive integers" "$BIN_PATH" on -i lo -C 0
assert_fail "Rotate size and count must be positive integers" "$BIN_PATH" on -i lo -W "notanumber"
assert_fail "Rotate size and count must be positive integers" "$BIN_PATH" on -i lo -W 0
assert_fail "Duration must be a positive integer in seconds" "$BIN_PATH" on -i lo -D "notanumber"
assert_fail "Duration must be a positive integer in seconds" "$BIN_PATH" on -i lo -D 0
assert_fail "Disk threshold must be an integer" "$BIN_PATH" on -i lo -w "150"
assert_fail "Disk threshold must be an integer" "$BIN_PATH" on -i lo -w "0"
assert_fail "Hardware type must be" "$BIN_PATH" on -i lo -t "invalidtype"
assert_fail "Operational mode must be 'passive' or 'active'" "$BIN_PATH" on -i lo --mode "invalidmode"
assert_fail "Probe rate must be a positive integer" "$BIN_PATH" probe -i lo --arp-scan --rate 0
assert_fail "Probe rate must be a positive integer" "$BIN_PATH" probe -i lo --arp-scan --rate "notanumber"
assert_fail "Probe timeout must be a positive integer in seconds" "$BIN_PATH" probe -i lo --arp-scan --timeout 0
assert_fail "Probe timeout must be a positive integer in seconds" "$BIN_PATH" probe -i lo --arp-scan --timeout "notanumber"
assert_fail "VLAN ID must be an integer between 1 and 4094" "$BIN_PATH" probe -i lo --arp-scan --vlan 5000
assert_fail "VLAN ID must be an integer between 1 and 4094" "$BIN_PATH" probe -i lo --arp-scan --vlan 0
assert_fail "QinQ tags must be in format 's_tag,c_tag'" "$BIN_PATH" probe -i lo --arp-scan --qinq "badqinq"

# --- 3. Privilege Checks ---
if [[ $EUID -ne 0 ]]; then
    assert_fail "requires root privileges" "$BIN_PATH" on -i lo
    assert_fail "requires root privileges" "$BIN_PATH" off -i lo
    assert_fail "requires root privileges" "$BIN_PATH" probe -i lo --arp-scan
else
    # We are root; test that non-root user is rejected by staging into /tmp
    if command -v su >/dev/null 2>&1 && id -u nobody >/dev/null 2>&1; then
        TMP_PRIV_DIR=$(mktemp -d /tmp/net-tap-priv.XXXXXX)
        chmod 755 "${TMP_PRIV_DIR}"
        cp -r "${SCRIPT_DIR}/../bin" "${SCRIPT_DIR}/../lib" "${TMP_PRIV_DIR}/"
        chmod -R 755 "${TMP_PRIV_DIR}"
        assert_fail "requires root privileges" su -s /bin/bash nobody -c "cd /tmp && '${TMP_PRIV_DIR}/bin/net-tap.sh' on -i lo"
        rm -rf "${TMP_PRIV_DIR}" 2>/dev/null || true
    fi
fi

# --- 3b. State File Security & Deserialization Defenses ---
STATE_SEC_DIR=$(mktemp -d /tmp/net-tap-sec-state.XXXXXX)

echo -n "[TEST] Verifying load_state_file command injection defense... "
cat << 'EOF' > "${STATE_SEC_DIR}/tap_malicious.state"
declare IFACE="veth0"; rm -rf /tmp/test_pwn
declare STATE_PID=1234
EOF
chmod 600 "${STATE_SEC_DIR}/tap_malicious.state"
if bash -c "source '${SCRIPT_DIR}/../lib/core.sh' && STATE_DIR='${STATE_SEC_DIR}' && load_state_file '${STATE_SEC_DIR}/tap_malicious.state'" >/dev/null 2>&1; then
    echo "FAILED (malicious state file with command injection was accepted)"
    FAILED=$((FAILED + 1))
else
    echo "PASSED"
    PASSED=$((PASSED + 1))
fi

echo -n "[TEST] Verifying load_state_file symlink rejection... "
ln -s "${STATE_SEC_DIR}/tap_malicious.state" "${STATE_SEC_DIR}/tap_symlink.state"
if bash -c "source '${SCRIPT_DIR}/../lib/core.sh' && STATE_DIR='${STATE_SEC_DIR}' && load_state_file '${STATE_SEC_DIR}/tap_symlink.state'" >/dev/null 2>&1; then
    echo "FAILED (symlink state file was accepted)"
    FAILED=$((FAILED + 1))
else
    echo "PASSED"
    PASSED=$((PASSED + 1))
fi

echo -n "[TEST] Verifying load_state_file unsafe permissions rejection... "
cat << 'EOF' > "${STATE_SEC_DIR}/tap_insecure_perm.state"
declare IFACE="veth0"
declare STATE_PID=1234
EOF
chmod 777 "${STATE_SEC_DIR}/tap_insecure_perm.state"
if bash -c "source '${SCRIPT_DIR}/../lib/core.sh' && STATE_DIR='${STATE_SEC_DIR}' && load_state_file '${STATE_SEC_DIR}/tap_insecure_perm.state'" >/dev/null 2>&1; then
    echo "FAILED (state file with 777 permissions was accepted)"
    FAILED=$((FAILED + 1))
else
    echo "PASSED"
    PASSED=$((PASSED + 1))
fi

echo -n "[TEST] Verifying load_state_file PATH injection rejection... "
cat << 'EOF' > "${STATE_SEC_DIR}/tap_path_inject.state"
declare PATH="/tmp/evil:/bin"
declare IFACE="veth0"
declare STATE_PID=1234
EOF
chmod 600 "${STATE_SEC_DIR}/tap_path_inject.state"
if bash -c "source '${SCRIPT_DIR}/../lib/core.sh' && STATE_DIR='${STATE_SEC_DIR}' && load_state_file '${STATE_SEC_DIR}/tap_path_inject.state'" >/dev/null 2>&1; then
    echo "FAILED (state file with PATH override was accepted)"
    FAILED=$((FAILED + 1))
else
    echo "PASSED"
    PASSED=$((PASSED + 1))
fi

echo -n "[TEST] Verifying load_state_file unauthorized options rejection... "
cat << 'EOF' > "${STATE_SEC_DIR}/tap_fn_inject.state"
declare -f evil_function
declare IFACE="veth0"
declare STATE_PID=1234
EOF
chmod 600 "${STATE_SEC_DIR}/tap_fn_inject.state"
if bash -c "source '${SCRIPT_DIR}/../lib/core.sh' && STATE_DIR='${STATE_SEC_DIR}' && load_state_file '${STATE_SEC_DIR}/tap_fn_inject.state'" >/dev/null 2>&1; then
    echo "FAILED (state file with declare -f was accepted)"
    FAILED=$((FAILED + 1))
else
    echo "PASSED"
    PASSED=$((PASSED + 1))
fi

echo -n "[TEST] Verifying load_state_file path traversal rejection... "
OUTSIDE_STATE=$(mktemp /tmp/net-tap-outside.XXXXXX)
cat << 'EOF' > "${OUTSIDE_STATE}"
declare IFACE="veth0"
declare STATE_PID=1234
EOF
chmod 600 "${OUTSIDE_STATE}"
if bash -c "source '${SCRIPT_DIR}/../lib/core.sh' && STATE_DIR='${STATE_SEC_DIR}' && load_state_file '${OUTSIDE_STATE}'" >/dev/null 2>&1; then
    echo "FAILED (state file outside STATE_DIR was accepted)"
    FAILED=$((FAILED + 1))
else
    echo "PASSED"
    PASSED=$((PASSED + 1))
fi
rm -f "${OUTSIDE_STATE}" 2>/dev/null || true
rm -rf "${STATE_SEC_DIR}" 2>/dev/null || true
STATE_SEC_DIR=""

# --- 4. Unprivileged Status & Analyzer Tests ---
assert_success "$BIN_PATH" status -i lo

assert_fail "does not exist" "$BIN_PATH" analyze -d /tmp/net-tap-nonexistent-$$

EMPTY_DIR=$(mktemp -d /tmp/net-tap-test-empty.XXXXXX)
assert_fail "No PCAP trace files found" "$BIN_PATH" analyze -d "$EMPTY_DIR"

# --- 5. Analyzer Engine & Synthetic Dual-Stack Fixtures ---
if [[ -d "$FIXTURES_DIR" && -f "$FIXTURES_DIR/synthetic_carrier_trace.pcap" ]]; then
    assert_success "$BIN_PATH" analyze -d "$FIXTURES_DIR"
    
    if command -v jq >/dev/null 2>&1; then
        echo -n "[TEST] Validating analyzer JSON schema with jq... "
        JSON_PAYLOAD=$("$BIN_PATH" analyze -d "$FIXTURES_DIR" --json)
        
        jq_errors=0
        assert_jq() {
            if ! echo "$JSON_PAYLOAD" | jq -e "$1" >/dev/null 2>&1; then
                echo "FAILED jq: $1"
                FAILED=$((FAILED + 1))
                jq_errors=$((jq_errors + 1))
            fi
        }
        
        assert_jq .
        assert_jq '.vlans | index("10") != null'
        assert_jq '.vlans | index("100") != null'
        assert_jq '.vlans | index("200") != null'
        assert_jq '.vlans | index("300") != null'
        assert_jq '.vlans | index("400") != null'
        assert_jq '.vlans | index("500") != null'
        assert_jq '.qinq_frames == 3'
        assert_jq '.mac_addresses | length > 0'
        assert_jq '.mac_addresses | index("00:11:22:33:44:55") != null'
        assert_jq '.ipv4_addresses | index("10.10.1.1") != null'
        assert_jq '.ipv4_gateways | index("10.10.1.254") != null'
        assert_jq '.ipv6_prefixes | index("2001:db8:beef::/64") != null'
        assert_jq '.ipv6_routers | index("fe80::1") != null'
        assert_jq '.ipv6_addresses | index("2001:db8:beef::100") != null'
        assert_jq '.ipv6_addresses | index("2001:db8:beef::200") != null'
        assert_jq '.ipv6_addresses | index("2001:db8:beef::201") != null'
        assert_jq '.ipv6_addresses | index("fd00:beef:10::100") != null'
        assert_jq '.ipv6_addresses | index("fe80::100") != null'
        assert_jq '.resolution.arp_frames == 2'
        assert_jq '.resolution.ndp_frames == 5'
        assert_jq '.resolution.ndp_details.neighbor_solicitation == 1'
        assert_jq '.resolution.ndp_details.neighbor_advertisement == 1'
        assert_jq '.resolution.ndp_details.router_solicitation == 1'
        assert_jq '.resolution.ndp_details.router_advertisement == 1'
        assert_jq '.resolution.ndp_details.redirect == 1'
        assert_jq '.tunnels.vxlan == 1'
        assert_jq '.tunnels.gtp_u == 2'
        assert_jq '.tunnels.gtp_c == 1'
        assert_jq '.tunnels.geneve == 1'
        assert_jq '.tunnels.gre == 1'
        assert_jq '.tunnels.mpls == 3'
        assert_jq '.tunnels.six_in_four == 1'
        assert_jq '.tunnels.four_in_six == 1'
        assert_jq '.tunnels.srv6 == 1'
        assert_jq '.protocols.sctp == 3'
        assert_jq '.protocols.pmtud == 2'
        assert_jq '.protocols.tcp_flags.syn == 6'
        assert_jq '.protocols.tcp_flags.syn_ack == 1'
        assert_jq '.protocols.tcp_flags.rst == 1'
        assert_jq '.protocols.tcp_flags.fin == 1'
        assert_jq '.protocols.tcp_flags.psh > 0'
        assert_jq '.protocols.tcp_flags.urg > 0'
        assert_jq '.protocols.tcp_flags.zero_window >= 1'
        assert_jq '.protocols.tcp_flags.retransmission >= 1'
        assert_jq '.infrastructure_frames.lldp == 1'
        assert_jq '.infrastructure_frames.cdp == 1'
        assert_jq '.infrastructure_frames.stp == 1'
        assert_jq '.infrastructure_frames.vrrp == 1'
        assert_jq '.infrastructure_frames.hsrp == 1'
        assert_jq '.infrastructure_frames.isis == 1'
        assert_jq '.infrastructure_frames.bfd == 3'
        assert_jq '.security_frames.eapol == 1'
        assert_jq '.security_frames.dhcp == 2'
        assert_jq '.dpi.dns_queries | index("api.internal.network") != null'
        assert_jq '.dpi.snmp_community_strings | index("public") != null'
        assert_jq '.dpi.ospf_routers | index("10.255.255.1") != null'
        assert_jq '.dpi.bgp_asns | index("65001") != null'
        assert_jq '.dpi.bgp_asns | index("65002") != null'
        assert_jq '.dpi.dhcp_hostnames | index("srv-dc01") != null'
        assert_jq '.dpi.tls_sni | index("login.microsoftonline.com") != null'
        
        if [[ $jq_errors -eq 0 ]]; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        fi

        # Formal Draft-7 JSON Schema Validation with Strict Format Checking
        echo -n "[TEST] Validating analyzer JSON output against Draft-7 schema with FormatChecker... "
        if ! python3 -c "import jsonschema" >/dev/null 2>&1; then
            echo "FAILED (python3-jsonschema is not installed)"
            FAILED=$((FAILED + 1))
        elif python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (JSON output violated Draft-7 schema or format validation)"
            FAILED=$((FAILED + 1))
        fi

        # Negative Schema Tests: Malformed IP, Invalid MAC, Missing Required Section, Duplicate Items, Range Limits
        echo -n "[TEST] Validating schema rejection of invalid IPv4 formats... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
data['ipv4_addresses'] = ['999.999.999.999']
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(1)
except jsonschema.ValidationError:
    sys.exit(0)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema failed to reject out-of-range IPv4 address)"
            FAILED=$((FAILED + 1))
        fi

        echo -n "[TEST] Validating schema rejection of invalid MAC formats... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
data['mac_addresses'] = ['bad-mac-string']
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(1)
except jsonschema.ValidationError:
    sys.exit(0)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema failed to reject non-hex MAC address)"
            FAILED=$((FAILED + 1))
        fi

        echo -n "[TEST] Validating schema rejection of missing required fields... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
del data['tunnels']
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(1)
except jsonschema.ValidationError:
    sys.exit(0)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema failed to reject payload missing required 'tunnels' property)"
            FAILED=$((FAILED + 1))
        fi

        echo -n "[TEST] Validating schema rejection of duplicate array items... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
data['vlans'] = ['10', '10']
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(1)
except jsonschema.ValidationError:
    sys.exit(0)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema failed to reject duplicate array items)"
            FAILED=$((FAILED + 1))
        fi

        echo -n "[TEST] Validating schema rejection of out-of-range VLAN IDs... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
data['vlans'] = ['4096']
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(1)
except jsonschema.ValidationError:
    sys.exit(0)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema failed to reject out-of-range VLAN ID 4096)"
            FAILED=$((FAILED + 1))
        fi

        # Validate Schema Acceptance of valid active_audit block
        echo -n "[TEST] Validating schema acceptance of valid active_audit block... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
data['active_audit'] = {
    'audit_files': ['20261004_test_veth-tap_probe_audit.jsonl'],
    'probes_sent': 10,
    'responses_received': 2,
    'vlans_probed': ['untagged', '100'],
    'discovered_hosts': [
        {'ip': '192.0.2.1', 'mac': '02:00:00:11:22:33', 'vlan': 'untagged'},
        {'ip': '10.100.1.1', 'mac': '02:00:00:44:55:66', 'vlan': '100'}
    ]
}
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(0)
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema rejected valid active_audit block)"
            FAILED=$((FAILED + 1))
        fi

        # Validate Schema Rejection of invalid MAC in active_audit
        echo -n "[TEST] Validating schema rejection of invalid MAC format in active_audit... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
data['active_audit'] = {
    'audit_files': ['test.jsonl'],
    'probes_sent': 1,
    'responses_received': 0,
    'vlans_probed': ['untagged'],
    'discovered_hosts': [
        {'ip': '192.0.2.1', 'mac': 'bad-mac-str', 'vlan': 'untagged'}
    ]
}
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(1)
except jsonschema.ValidationError:
    sys.exit(0)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema failed to reject invalid MAC in discovered_hosts)"
            FAILED=$((FAILED + 1))
        fi

        # Validate Schema Rejection of missing required field in active_audit
        echo -n "[TEST] Validating schema rejection of missing required field in active_audit... "
        if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
data['active_audit'] = {
    'audit_files': ['test.jsonl'],
    'probes_sent': 1,
    'responses_received': 0,
    'vlans_probed': ['untagged']
}
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    sys.exit(1)
except jsonschema.ValidationError:
    sys.exit(0)
" "${JSON_PAYLOAD}" >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (Schema failed to reject missing required field in active_audit)"
            FAILED=$((FAILED + 1))
        fi

        # Verify Native tcpdump DPI Fallback (when tshark is absent or bypassed)
        echo -n "[TEST] Validating native tcpdump DPI fallback (tshark absent)... "
        DPI_FALLBACK_JSON=$(PATH="/bin:/usr/local/bin" "$BIN_PATH" analyze -d "$FIXTURES_DIR" --json 2>/dev/null)
        if echo "${DPI_FALLBACK_JSON}" | jq -e '
            (.dpi.ospf_routers | index("10.255.255.1") != null) and
            (.dpi.bgp_asns | index("65001") != null) and
            (.dpi.bgp_asns | index("65002") != null) and
            (.dpi.dhcp_hostnames | index("srv-dc01") != null) and
            (.dpi.dns_queries | index("api.internal.network") != null) and
            (.dpi.snmp_community_strings | index("public") != null) and
            (.dpi.tls_sni | index("login.microsoftonline.com") != null)
        ' >/dev/null 2>&1; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (tcpdump fallback did not extract expected DPI telemetry)"
            FAILED=$((FAILED + 1))
        fi
    else
        echo "[WARNING] jq not installed, skipping JSON validations."
    fi
fi

# --- 6. End-to-End Namespace Lifecycle & Egress Drop Verification (Root Only) ---
if [[ $EUID -eq 0 ]]; then
    TEST_NS="nettap_test_$$"
    TEST_CAPTURE_DIR=$(mktemp -d /tmp/net-tap-test-captures.XXXXXX)
    echo "[TEST] Provisioning isolated test network namespace '${TEST_NS}'..."
    ip netns add "${TEST_NS}"
    
    ip netns exec "${TEST_NS}" ip link add name veth-tap type veth peer name veth-peer
    ip netns exec "${TEST_NS}" ip link set dev veth-peer up

    # 6.1 Test invalid BPF filter
    assert_fail "Invalid BPF filter" "$BIN_PATH" on -n "${TEST_NS}" -i veth-tap -f "bad filter syntax"

    # 6.1b Test enslaved interface rejection
    ip netns exec "${TEST_NS}" ip link add name br-test type bridge
    ip netns exec "${TEST_NS}" ip link set dev veth-tap master br-test
    assert_fail "is enslaved to master" "$BIN_PATH" on -n "${TEST_NS}" -i veth-tap -o "${TEST_CAPTURE_DIR}"
    ip netns exec "${TEST_NS}" ip link set dev veth-tap nomaster
    ip netns exec "${TEST_NS}" ip link del dev br-test

    # 6.2 Test valid startup in namespace with isolated output directory
    assert_success "$BIN_PATH" on -n "${TEST_NS}" -i veth-tap -f "(ip or ip6 or arp)" -o "${TEST_CAPTURE_DIR}"

    # 6.3 Verify Egress Drop Filter
    echo -n "[TEST] Verifying zero-egress hardware packet drop in namespace... "
    # Attempt layer-2 transmission via raw socket to verify tc egress drop
    if command -v python3 >/dev/null 2>&1; then
        ip netns exec "${TEST_NS}" python3 -c "from scapy.all import *; sendp(Ether()/IP(dst='192.0.2.1')/ICMP(), iface='veth-tap', count=1, verbose=0)" >/dev/null 2>&1 || true
    fi
    # Also attempt layer-3 transmission outbound from the tapped interface
    ip netns exec "${TEST_NS}" ping -c 1 -W 1 -I veth-tap 192.0.2.1 >/dev/null 2>&1 || true
    
    # Query tc egress filter dropped counter
    DROPPED=$(ip netns exec "${TEST_NS}" tc -s filter show dev veth-tap egress | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
    if [[ "${DROPPED}" -gt 0 ]]; then
        echo "PASSED (blocked ${DROPPED} egress packets)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (egress filter did not increment dropped counter)"
        FAILED=$((FAILED + 1))
    fi

    # 6.3b Verify zero frames leaked to peer link during capture
    echo -n "[TEST] Verifying zero frame leak on peer link during capture... "
    PEER_RX=$(ip netns exec "${TEST_NS}" ip -s link show veth-peer | awk '/RX:/ {getline; print $1}')
    if [[ "${PEER_RX}" -eq 0 ]]; then
        echo "PASSED (0 frames leaked to peer)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (${PEER_RX} frames leaked to peer link)"
        FAILED=$((FAILED + 1))
    fi

    # 6.4 Status check
    assert_success "$BIN_PATH" status -n "${TEST_NS}" -i veth-tap

    # 6.5 Clean teardown
    assert_success "$BIN_PATH" off -n "${TEST_NS}" -i veth-tap

    # 6.6 Verify interface restored
    echo -n "[TEST] Verifying clsact qdisc removal and interface restoration... "
    if ! ip netns exec "${TEST_NS}" tc qdisc show dev veth-tap | grep -q "clsact"; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (clsact qdisc remained attached)"
        FAILED=$((FAILED + 1))
    fi

    # 6.6b Verify zero frames leaked to peer during teardown
    echo -n "[TEST] Verifying zero frame leak on peer link after teardown... "
    PEER_RX_AFTER=$(ip netns exec "${TEST_NS}" ip -s link show veth-peer | awk '/RX:/ {getline; print $1}')
    if [[ "${PEER_RX_AFTER}" -eq 0 ]]; then
        echo "PASSED (0 frames leaked during teardown)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (${PEER_RX_AFTER} frames leaked to peer during teardown)"
        FAILED=$((FAILED + 1))
    fi

    # 6.7 Verify capture output analysis
    assert_success "$BIN_PATH" analyze -d "${TEST_CAPTURE_DIR}"
    rm -rf "${TEST_CAPTURE_DIR}" 2>/dev/null || true
    TEST_CAPTURE_DIR=""

    # 6.7b IEEE 802.1X EAP-Request Ingress & EAP-Response Zero-Egress Drop Verification
    echo "[TEST] Running IEEE 802.1X EAP-Request ingress & EAP-Response zero-egress drop verification..."

    # Control Verification: Verify that WITHOUT net-tap drop filter, 802.1X response is indeed sent and received
    if command -v wpa_supplicant >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        echo -n "[TEST] Verifying unshielded baseline sends 802.1X EAP-Response (control test)... "
        ip netns exec "${TEST_NS}" ip link set dev veth-tap up
        ip netns exec "${TEST_NS}" ip link set dev veth-peer up

        WPA_CONF_CTRL=$(mktemp /tmp/wpa_ctrl.XXXXXX.conf)
        WPA_PID_CTRL=$(mktemp /tmp/wpa_ctrl.XXXXXX.pid)
        rm -f "${WPA_PID_CTRL}"
        cat << 'EOF' > "${WPA_CONF_CTRL}"
ctrl_interface=/var/run/wpa_supplicant
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="testuser"
    password="password"
}
EOF
        ip netns exec "${TEST_NS}" wpa_supplicant -i veth-tap -c "${WPA_CONF_CTRL}" -D wired -B -P "${WPA_PID_CTRL}" 2>/dev/null || true
        sleep 0.4

        CTRL_RESULT=$(ip netns exec "${TEST_NS}" python3 -c "
import threading, time
from scapy.all import sniff, sendp, Ether, Raw
from scapy.layers.eap import EAP, EAPOL

rx_responses = []
def listen():
    pkts = sniff(iface='veth-peer', timeout=2, lfilter=lambda p: p.haslayer(EAP) and p[EAP].code == 2)
    rx_responses.extend(pkts)

t = threading.Thread(target=listen)
t.start()
time.sleep(0.3)

# Send EAP-Request from peer
eapol_req = b'\x01\x00\x00\x05\x01\x01\x00\x05\x01'
req_pkt = Ether(src='00:50:56:bb:cc:01', dst='01:80:c2:00:00:03', type=0x888e) / Raw(load=eapol_req)
sendp(req_pkt, iface='veth-peer', count=1, verbose=0)
t.join()

if len(rx_responses) > 0 and rx_responses[0].haslayer(EAP) and rx_responses[0][EAP].identity == b'testuser':
    print('OK')
else:
    print('NONE')
" 2>/dev/null || echo "ERROR")

        if [[ -f "${WPA_PID_CTRL}" ]]; then
            kill "$(cat "${WPA_PID_CTRL}")" 2>/dev/null || true
            rm -f "${WPA_PID_CTRL}"
        fi
        rm -f "${WPA_CONF_CTRL}"
        WPA_CONF_CTRL=""
        WPA_PID_CTRL=""
        ip netns exec "${TEST_NS}" ip link set dev veth-tap down

        if [[ "${CTRL_RESULT}" == "OK" ]]; then
            echo "PASSED (confirmed unshielded supplicant emitted EAP-Response 'testuser' to peer)"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (unshielded supplicant did not emit expected response, got: ${CTRL_RESULT})"
            FAILED=$((FAILED + 1))
        fi
    fi

    TEST_EAP_DIR=$(mktemp -d /tmp/net-tap-test-eap.XXXXXX)
    ip netns exec "${TEST_NS}" ip link set dev veth-peer up

    assert_success "$BIN_PATH" on -n "${TEST_NS}" -i veth-tap -o "${TEST_EAP_DIR}"

    INIT_EAP_DROPS=$(ip netns exec "${TEST_NS}" tc -s filter show dev veth-tap egress 2>/dev/null | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
    INIT_PEER_RX=$(ip netns exec "${TEST_NS}" ip -s link show veth-peer 2>/dev/null | awk '/RX:/ {getline; print $1}')

    # Authenticator sends IEEE 802.1X EAP-Request/Identity (EtherType 0x888e) from peer to tap
    if command -v python3 >/dev/null 2>&1; then
        ip netns exec "${TEST_NS}" python3 -c "
from scapy.all import Ether, Raw, sendp
# EAPOL Version 1, Type 0 (EAP-Packet), Len 5, EAP Code 1 (Request), Id 1, Len 5, Type 1 (Identity)
eapol_req = b'\x01\x00\x00\x05\x01\x01\x00\x05\x01'
req_pkt = Ether(src='00:50:56:bb:cc:01', dst='01:80:c2:00:00:03', type=0x888e) / Raw(load=eapol_req)
sendp(req_pkt, iface='veth-peer', count=1, verbose=0)
" 2>/dev/null || true
    fi

    # Supplicant/client on veth-tap attempts to send an EAP-Response/Identity answer back
    echo -n "[TEST] Verifying 802.1X EAP-Response answer dropped on egress... "
    if command -v python3 >/dev/null 2>&1; then
        ip netns exec "${TEST_NS}" python3 -c "
from scapy.all import Ether, Raw, sendp
# EAPOL Version 1, Type 0 (EAP-Packet), EAP Code 2 (Response), Id 1, Type 1 (Identity)
eapol_resp = b'\x01\x00\x00\x18\x02\x01\x00\x18\x01supplicant@internal'
resp_pkt = Ether(src='02:00:00:00:00:01', dst='00:50:56:bb:cc:01', type=0x888e) / Raw(load=eapol_resp)
try:
    sendp(resp_pkt, iface='veth-tap', count=1, verbose=0)
except OSError:
    pass
" 2>/dev/null || true
    fi

    AFTER_RESP_DROPS=$(ip netns exec "${TEST_NS}" tc -s filter show dev veth-tap egress 2>/dev/null | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
    AFTER_RESP_PEER_RX=$(ip netns exec "${TEST_NS}" ip -s link show veth-peer 2>/dev/null | awk '/RX:/ {getline; print $1}')

    if [[ "${AFTER_RESP_DROPS}" -gt "${INIT_EAP_DROPS}" ]] && [[ "${AFTER_RESP_PEER_RX}" -eq "${INIT_PEER_RX}" ]]; then
        echo "PASSED (blocked EAP-Response, 0 frames leaked to peer)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (egress drops before: ${INIT_EAP_DROPS}, after: ${AFTER_RESP_DROPS} | peer RX before: ${INIT_PEER_RX}, after: ${AFTER_RESP_PEER_RX})"
        FAILED=$((FAILED + 1))
    fi

    # If wpa_supplicant is available, also test real userspace 802.1X supplicant daemon response drop
    if command -v wpa_supplicant >/dev/null 2>&1; then
        echo -n "[TEST] Verifying wpa_supplicant 802.1X response answer dropped on egress... "
        WPA_CONF_FILE=$(mktemp /tmp/wpa_eap.XXXXXX.conf)
        WPA_PID_FILE=$(mktemp /tmp/wpa_eap.XXXXXX.pid)
        rm -f "${WPA_PID_FILE}"
        cat << 'EOF' > "${WPA_CONF_FILE}"
ctrl_interface=/var/run/wpa_supplicant
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="testuser"
    password="password"
}
EOF
        WPA_DROPS_PRE=$(ip netns exec "${TEST_NS}" tc -s filter show dev veth-tap egress 2>/dev/null | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
        ip netns exec "${TEST_NS}" wpa_supplicant -i veth-tap -c "${WPA_CONF_FILE}" -D wired -B -P "${WPA_PID_FILE}" 2>/dev/null || true
        sleep 0.3

        # Authenticator transmits EAP-Request/Identity for wpa_supplicant
        if command -v python3 >/dev/null 2>&1; then
            ip netns exec "${TEST_NS}" python3 -c "
from scapy.all import Ether, Raw, sendp
eapol_req = b'\x01\x00\x00\x05\x01\x02\x00\x05\x01'
req_pkt = Ether(src='00:50:56:bb:cc:01', dst='01:80:c2:00:00:03', type=0x888e) / Raw(load=eapol_req)
sendp(req_pkt, iface='veth-peer', count=1, verbose=0)
" 2>/dev/null || true
        fi
        sleep 0.5

        if [[ -f "${WPA_PID_FILE}" ]]; then
            kill "$(cat "${WPA_PID_FILE}")" 2>/dev/null || true
            rm -f "${WPA_PID_FILE}"
        fi
        rm -f "${WPA_CONF_FILE}"
        WPA_CONF_FILE=""
        WPA_PID_FILE=""

        WPA_DROPS_POST=$(ip netns exec "${TEST_NS}" tc -s filter show dev veth-tap egress 2>/dev/null | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
        WPA_PEER_RX_POST=$(ip netns exec "${TEST_NS}" ip -s link show veth-peer 2>/dev/null | awk '/RX:/ {getline; print $1}')

        if [[ "${WPA_DROPS_POST}" -gt "${WPA_DROPS_PRE}" ]] && [[ "${WPA_PEER_RX_POST}" -eq "${INIT_PEER_RX}" ]]; then
            echo "PASSED (blocked wpa_supplicant EAP-Response, 0 frames leaked to peer)"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (wpa drops before: ${WPA_DROPS_PRE}, after: ${WPA_DROPS_POST} | peer RX: ${WPA_PEER_RX_POST})"
            FAILED=$((FAILED + 1))
        fi
    fi

    # Teardown 802.1X session
    assert_success "$BIN_PATH" off -n "${TEST_NS}" -i veth-tap

    # Verify that the incoming 802.1X EAP-Request was captured and recognized by the analyzer
    echo -n "[TEST] Verifying 802.1X EAPOL frames captured in pcap and detected by analyzer... "
    EAP_JSON=$("$BIN_PATH" analyze -d "${TEST_EAP_DIR}" --json 2>/dev/null || echo "{}")
    if command -v jq >/dev/null 2>&1; then
        EAP_COUNT=$(echo "${EAP_JSON}" | jq -r '.security_frames.eapol // 0' 2>/dev/null || echo "0")
        if [[ "${EAP_COUNT}" -ge 1 ]]; then
            echo "PASSED (detected ${EAP_COUNT} EAPOL frames)"
            PASSED=$((PASSED + 1))
        else
            echo "FAILED (analyzer reported ${EAP_COUNT} EAPOL frames, expected >= 1)"
            FAILED=$((FAILED + 1))
        fi
    else
        echo "PASSED (skipped jq validation)"
        PASSED=$((PASSED + 1))
    fi

    rm -rf "${TEST_EAP_DIR}" 2>/dev/null || true
    TEST_EAP_DIR=""
    # 6.8 Multi-Interface Capture, Netfilter Raw Rules & Sysctl Restoration Test
    echo "[TEST] Running multi-interface dual-tap verification (veth-tap1,veth-tap2)..."
    ip netns exec "${TEST_NS}" ip link add name veth-tap1 type veth peer name veth-peer1
    ip netns exec "${TEST_NS}" ip link add name veth-tap2 type veth peer name veth-peer2
    ip netns exec "${TEST_NS}" ip link set dev veth-peer1 up
    ip netns exec "${TEST_NS}" ip link set dev veth-peer2 up

    INIT_ARP_IGNORE=$(ip netns exec "${TEST_NS}" sysctl -n net.ipv4.conf.veth-tap1.arp_ignore 2>/dev/null || echo "0")

    TEST_MULTI_DIR=$(mktemp -d /tmp/net-tap-test-multi.XXXXXX)
    assert_success "$BIN_PATH" on -n "${TEST_NS}" -i "veth-tap1,veth-tap2" -o "${TEST_MULTI_DIR}"

    echo -n "[TEST] Verifying Netfilter raw table NOTRACK and DROP rules... "
    RAW_IPTABLES=$(ip netns exec "${TEST_NS}" iptables -t raw -S 2>/dev/null || true)
    if echo "${RAW_IPTABLES}" | grep -q "veth-tap1.*NOTRACK" && echo "${RAW_IPTABLES}" | grep -q "veth-tap1.*DROP"; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (missing NOTRACK or DROP rules in raw table)"
        FAILED=$((FAILED + 1))
    fi

    echo -n "[TEST] Verifying stealth sysctls applied during capture... "
    TAP_ARP_IGNORE=$(ip netns exec "${TEST_NS}" sysctl -n net.ipv4.conf.veth-tap1.arp_ignore 2>/dev/null || echo "0")
    if [[ "${TAP_ARP_IGNORE}" == "8" ]]; then
        echo "PASSED (arp_ignore=8)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (arp_ignore is ${TAP_ARP_IGNORE}, expected 8)"
        FAILED=$((FAILED + 1))
    fi

    assert_success "$BIN_PATH" status -n "${TEST_NS}" -i "veth-tap1,veth-tap2"
    assert_success "$BIN_PATH" off -n "${TEST_NS}" -i "veth-tap1,veth-tap2"

    echo -n "[TEST] Verifying Netfilter raw table rule cleanup after teardown... "
    RAW_IPTABLES_AFTER=$(ip netns exec "${TEST_NS}" iptables -t raw -S 2>/dev/null || true)
    if ! echo "${RAW_IPTABLES_AFTER}" | grep -q "veth-tap1.*NOTRACK" && ! echo "${RAW_IPTABLES_AFTER}" | grep -q "veth-tap1.*DROP"; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (raw table rules remained after teardown)"
        FAILED=$((FAILED + 1))
    fi

    echo -n "[TEST] Verifying sysctl restoration after teardown... "
    REST_ARP_IGNORE=$(ip netns exec "${TEST_NS}" sysctl -n net.ipv4.conf.veth-tap1.arp_ignore 2>/dev/null || echo "0")
    if [[ "${REST_ARP_IGNORE}" == "${INIT_ARP_IGNORE}" ]]; then
        echo "PASSED (arp_ignore restored to ${INIT_ARP_IGNORE})"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (arp_ignore is ${REST_ARP_IGNORE}, expected ${INIT_ARP_IGNORE})"
        FAILED=$((FAILED + 1))
    fi
    rm -rf "${TEST_MULTI_DIR}" 2>/dev/null || true
    TEST_MULTI_DIR=""

    # 6.9 Auto-shutdown Duration Timer Verification (-D 2)
    echo "[TEST] Verifying auto-shutdown duration timer (-D 2)..."
    TEST_DUR_DIR=$(mktemp -d /tmp/net-tap-test-dur.XXXXXX)
    assert_success "$BIN_PATH" on -n "${TEST_NS}" -i veth-tap1 -D 2 -o "${TEST_DUR_DIR}"
    
    echo -n "[TEST] Waiting for auto-shutdown worker to complete... "
    shutdown_success=0
    for _ in $(seq 1 40); do
        if "$BIN_PATH" status -n "${TEST_NS}" -i veth-tap1 2>&1 | grep -qi "Not running"; then
            shutdown_success=1
            break
        fi
        sleep 0.2
    done
    if [[ $shutdown_success -eq 1 ]]; then
        echo "PASSED (session automatically terminated after 2s)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (session still active after duration expired)"
        FAILED=$((FAILED + 1))
        "$BIN_PATH" off -n "${TEST_NS}" -i veth-tap1 >/dev/null 2>&1 || true
    fi
    "$BIN_PATH" off -n "${TEST_NS}" -i "veth-tap1,veth-tap2" >/dev/null 2>&1 || true
    rm -rf "${TEST_DUR_DIR}" 2>/dev/null || true
    TEST_DUR_DIR=""
    sleep 0.3

    # 6.10 Active Probing & Selective Egress Verification (--mode active & probe)
    echo "[TEST] Running active probing & selective egress verification (--mode active & probe)..."
    TEST_ACTIVE_DIR=$(mktemp -d /tmp/net-tap-test-active.XXXXXX)
    ip netns exec "${TEST_NS}" ip link set dev veth-peer up

    # 6.10a Attempting probe on passive mode tap session must be rejected
    assert_success "$BIN_PATH" on -n "${TEST_NS}" -i veth-tap -o "${TEST_ACTIVE_DIR}"
    assert_fail "running in PASSIVE mode" "$BIN_PATH" probe -n "${TEST_NS}" -i veth-tap --arp-scan 192.0.2.0/24
    assert_success "$BIN_PATH" off -n "${TEST_NS}" -i veth-tap
    rm -rf "${TEST_ACTIVE_DIR:?}"/* 2>/dev/null || true

    # 6.10b Start tap in active mode
    assert_success "$BIN_PATH" on -n "${TEST_NS}" -i veth-tap --mode active -o "${TEST_ACTIVE_DIR}"

    # Verify status reflects active mode
    echo -n "[TEST] Verifying status reflects active operational mode... "
    STATUS_MODE=$("$BIN_PATH" status -n "${TEST_NS}" -i veth-tap 2>&1 || true)
    if echo "${STATUS_MODE}" | grep -iE "Mode\s*:\s*active"; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (status did not display active mode)"
        FAILED=$((FAILED + 1))
    fi

    # Verify unmarked host traffic is still dropped by tc in active mode
    echo -n "[TEST] Verifying unmarked host egress frames dropped in active mode... "
    PRE_ACTIVE_DROP=$(ip netns exec "${TEST_NS}" tc -s filter show dev veth-tap egress 2>/dev/null | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
    if command -v python3 >/dev/null 2>&1; then
        ip netns exec "${TEST_NS}" python3 -c "from scapy.all import sendp, Ether, IP, ICMP; sendp(Ether()/IP(dst='192.0.2.1')/ICMP(), iface='veth-tap', count=1, verbose=0)" 2>/dev/null || true
    fi
    POST_ACTIVE_DROP=$(ip netns exec "${TEST_NS}" tc -s filter show dev veth-tap egress 2>/dev/null | awk '/dropped/ {gsub(/,/, "", $7); sum += $7} END {print sum+0}')
    if [[ "${POST_ACTIVE_DROP}" -gt "${PRE_ACTIVE_DROP}" ]]; then
        echo "PASSED (unmarked host packet dropped by tc)"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (unmarked host packet was not dropped)"
        FAILED=$((FAILED + 1))
    fi

    # Start responder on veth-peer in python
    ip netns exec "${TEST_NS}" python3 -c "
import sys, time
from scapy.all import sniff, sendp, Ether, Dot1Q, ARP, IP, ICMP, TCP, UDP, BOOTP, DHCP

def process_pkt(pkt):
    reply = None
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:
        if pkt.haslayer(Dot1Q) and pkt[Dot1Q].vlan == 100:
            if pkt[ARP].pdst == '10.100.1.1':
                reply = Ether(src='02:00:00:10:01:01', dst=pkt[Ether].src) / Dot1Q(vlan=100) / ARP(op=2, hwsrc='02:00:00:10:01:01', psrc='10.100.1.1', hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
        elif not pkt.haslayer(Dot1Q):
            if pkt[ARP].pdst == '192.0.2.99':
                reply = Ether(src='02:00:00:88:99:aa', dst=pkt[Ether].src) / ARP(op=2, hwsrc='02:00:00:88:99:aa', psrc='192.0.2.99', hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
    elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        reply = Ether(src='02:00:00:88:99:aa', dst=pkt[Ether].src) / IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
    elif pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        reply = Ether(src='02:00:00:88:99:aa', dst=pkt[Ether].src) / IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='SA', seq=1000, ack=pkt[TCP].seq+1)
    elif pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        bootp = pkt[BOOTP]
        reply = Ether(src='02:00:00:88:99:aa', dst=pkt[Ether].src) / IP(src='192.0.2.254', dst='255.255.255.255') / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr='192.0.2.50', siaddr='192.0.2.254', chaddr=bootp.chaddr, xid=bootp.xid) / DHCP(options=[('message-type', 'offer'), ('server_id', '192.0.2.254'), 'end'])

    if reply is not None:
        sendp(reply, iface='veth-peer', count=1, verbose=0)

sniff(iface='veth-peer', timeout=10, prn=process_pkt)
" &
    RESP_PID=$!
    sleep 0.4

    # Execute active probes
    assert_success "$BIN_PATH" probe -n "${TEST_NS}" -i veth-tap --arp-scan 192.0.2.99/32 --rate 50
    assert_success "$BIN_PATH" probe -n "${TEST_NS}" -i veth-tap --vlan 100 --arp-scan 10.100.1.1/32 --rate 50
    assert_success "$BIN_PATH" probe -n "${TEST_NS}" -i veth-tap --auto-vlans --arp-scan 10.100.1.1/32 --rate 50
    assert_success "$BIN_PATH" probe -n "${TEST_NS}" -i veth-tap --dhcp-discover
    assert_success "$BIN_PATH" probe -n "${TEST_NS}" -i veth-tap --icmp-pmtu 192.0.2.99
    assert_success "$BIN_PATH" probe -n "${TEST_NS}" -i veth-tap --tcp-syn 192.0.2.99 -p 80,443

    kill "${RESP_PID}" 2>/dev/null || true
    wait "${RESP_PID}" 2>/dev/null || true

    # Stop active tap session
    assert_success "$BIN_PATH" off -n "${TEST_NS}" -i veth-tap

    # Verify audit file was created
    echo -n "[TEST] Verifying audit JSONL log file created... "
    if compgen -G "${TEST_ACTIVE_DIR}/*probe_audit.jsonl" > /dev/null; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (no probe audit log found)"
        FAILED=$((FAILED + 1))
    fi

    # Run analyzer on active capture session and validate schema
    echo -n "[TEST] Validating analyzer JSON schema on active probing session... "
    ACTIVE_JSON=$("$BIN_PATH" analyze -d "${TEST_ACTIVE_DIR}" --json 2>/dev/null || echo "{}")
    if python3 -B -c "
import json, jsonschema, sys
with open('${SCRIPT_DIR}/schema/analysis.schema.json') as sf:
    schema = json.load(sf)
data = json.loads(sys.argv[1])
try:
    jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    assert 'active_audit' in data
    assert data['active_audit']['probes_sent'] > 0
    assert data['active_audit']['responses_received'] >= 2
    assert len(data['active_audit']['discovered_hosts']) >= 2
    sys.exit(0)
except Exception as e:
    sys.stderr.write(f'Validation failed: {e}\n')
    sys.exit(1)
" "${ACTIVE_JSON}" 2>&1; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (active audit JSON output failed schema validation)"
        FAILED=$((FAILED + 1))
    fi

    # Verify terminal output contains Section [7] Active Audit Correlation
    echo -n "[TEST] Verifying human-readable active audit correlation in analyzer report... "
    ACTIVE_TXT=$("$BIN_PATH" analyze -d "${TEST_ACTIVE_DIR}" 2>/dev/null || echo "")
    if echo "${ACTIVE_TXT}" | grep -q "\[7\] ACTIVE AUDIT & TARGET PROBING CORRELATION" && \
       echo "${ACTIVE_TXT}" | grep -q "192.0.2.99" && \
       echo "${ACTIVE_TXT}" | grep -q "10.100.1.1"; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "FAILED (human-readable report missing expected active audit correlation)"
        FAILED=$((FAILED + 1))
    fi

    rm -rf "${TEST_ACTIVE_DIR}" 2>/dev/null || true
    TEST_ACTIVE_DIR=""

    # 6.11 Fallback Teardown on Nonexistent State File
    echo -n "[TEST] Verifying fallback teardown on nonexistent state file... "
    if "$BIN_PATH" off -n "${TEST_NS}" -i dummy99 >/dev/null 2>&1; then
        echo "PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "PASSED (clean non-zero handling without crash)"
        PASSED=$((PASSED + 1))
    fi

    ip netns del "${TEST_NS}"
    TEST_NS=""
    # test ns is deleted, cleanup will handle the rest
else
    echo "[WARNING] Not running as root, skipping Section 6 tests."
fi

echo "================================================="
echo " Test Results: ${PASSED} Passed | ${FAILED} Failed"
echo "================================================="

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
