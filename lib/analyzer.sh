#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2001,SC2317

analyze_session() {
    verify_dependencies

    local target_dir="${OUT_DIR}"

    if [[ ! -d "${target_dir}" ]]; then
        log_err "Specified directory does not exist: ${target_dir}"
        exit 1
    fi

    local pcap_files=()
    while IFS= read -r -d $'\0' f; do
        pcap_files+=("$f")
    done < <(find "${target_dir}" -maxdepth 1 -type f \( -name "*_trace.pcap*" -o -name "*.pcap*" \) -print0 2>/dev/null)

    if [[ ${#pcap_files[@]} -eq 0 ]]; then
        log_err "No PCAP trace files found in ${target_dir}."
        exit 1
    fi

    # Deduplicate: If merged traces exist, analyze only the merged trace to avoid double-counting
    local files_to_analyze=()
    local has_merged=0
    for f in "${pcap_files[@]}"; do
        if [[ "${f}" =~ _merged_trace\.pcap ]]; then
            has_merged=1
            files_to_analyze+=("$f")
        fi
    done
    if [[ ${has_merged} -eq 0 ]]; then
        files_to_analyze=("${pcap_files[@]}")
    fi

    log_info "Analyzing ${#files_to_analyze[@]} capture file(s) in ${C_BOLD}${target_dir}${C_RESET}..."

    local total_pcap_kb=0
    for pf in "${files_to_analyze[@]}"; do
        if [[ -f "${pf}" ]]; then
            local sz_kb
            sz_kb=$(du -k "${pf}" 2>/dev/null | awk '{print $1}')
            total_pcap_kb=$((total_pcap_kb + ${sz_kb:-0}))
        fi
    done
    local total_pcap_mb=$(( (total_pcap_kb + 1023) / 1024 ))
    local required_mb=$(( total_pcap_mb * 3 ))
    if [[ "${required_mb}" -lt 50 ]]; then
        required_mb=50
    fi

    local avail_tmp_mb
    avail_tmp_mb=$(df -Pm "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2 {print $4}')
    if [[ -n "${avail_tmp_mb}" && "${avail_tmp_mb}" -lt "${required_mb}" ]]; then
        log_err "Critically low disk space in ${TMPDIR:-/tmp} (${avail_tmp_mb}MB available, required ${required_mb}MB for 3x PCAP expansion). Aborting analysis."
        exit 1
    fi

    # Create temporary consolidated inspection directory
    TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/net-tap-analysis.XXXXXX")
    cleanup_analyzer() {
        if [[ "${JSON_OUT:-0}" == "1" ]] && { true >&3; } 2>/dev/null; then
            exec 1>&3
            exec 3>&-
        fi
        if [[ -n "${TEMP_DIR:-}" ]]; then
            rm -rf "${TEMP_DIR}" 2>/dev/null || true
        fi
    }
    trap cleanup_analyzer EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP

    if [[ "${JSON_OUT}" == "1" ]]; then
        exec 3>&1
        exec 1>/dev/null
    fi

    # =========================================================================
    # 1. PHYSICAL & OPTICAL LAYER ANALYSIS
    # =========================================================================
    echo -e "\n${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD} [1] PHYSICAL LAYER & CARRIER STABILITY ANALYSIS${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}"

    # Search for DDM files
    local ddm_files=()
    while IFS= read -r -d $'\0' df; do
        ddm_files+=("$df")
    done < <(find "${target_dir}" -maxdepth 1 -name "*_sfp_ddm.txt" -print0 2>/dev/null)
    if [[ ${#ddm_files[@]} -gt 0 ]]; then
        echo -e "${C_CYAN}SFP Optical Diagnostics Detected:${C_RESET}"
        for df in "${ddm_files[@]}"; do
            grep -Ei "(Receiver signal average optical power|Optical receive power|Laser output power|Laser bias current|Rx LOS|Tx fault|temperature|Module voltage)" "${df}" | sed 's/^/  /' || true
        done
    else
        echo "  No SFP optical diagnostic dumps found (Standard copper Ethernet or non-DDM optic)."
    fi

    # Inspect Link Event & Dmesg Logs
    local link_logs=()
    while IFS= read -r -d $'\0' lf; do
        link_logs+=("$lf")
    done < <(find "${target_dir}" -maxdepth 1 -name "*_link_events.log" -print0 2>/dev/null)

    if [[ ${#link_logs[@]} -gt 0 ]]; then
        local flaps=0
        for lf in "${link_logs[@]}"; do
            local cnt
            cnt=$(grep -c "state DOWN" "${lf}" 2>/dev/null || true)
            flaps=$((flaps + cnt))
        done
        echo -e "\n${C_CYAN}Link Flap & Carrier State History:${C_RESET}"
        if [[ "${flaps}" -gt 0 ]]; then
            echo -e "  ${C_RED}${C_BOLD}WARNING:${C_RESET} Detected ${flaps} carrier drop/down transitions in link history."
            for lf in "${link_logs[@]}"; do
                tail -n 6 "${lf}" | sed 's/^/    /'
            done
        else
            echo -e "  ${C_GREEN}Physical link remained stable without carrier drops during monitoring.${C_RESET}"
        fi
    fi

    # =========================================================================
    # 2. LAYER 2: MAC ADDRESSES & 802.1Q VLAN TAGGING
    # =========================================================================
    echo -e "\n${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD} [2] LAYER 2: ETHERNET & VLAN SEGMENTATION${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}"

    # Cache all headers to tmpfs with support for compressed (.gz) PCAPs and verbose decode
    local dump_file="${TEMP_DIR}/all_headers.txt"
    log_info "Caching packet headers to tmpfs for high-speed analysis..."
    for pf in "${files_to_analyze[@]}"; do
        if [[ "${pf}" =~ \.gz$ ]]; then
            gzip -dc "${pf}" 2>/dev/null | tcpdump -r - -e -nn -v 2>/dev/null >> "${dump_file}" || true
        else
            tcpdump -r "${pf}" -e -nn -v 2>/dev/null >> "${dump_file}" || true
        fi
    done

    # Perform consolidated streaming dissection pass with per-packet boundary tracking
    local qinq_count arp_count ndp_count ndp_ns ndp_na ndp_rs ndp_ra ndp_redirect vxlan_count gtp_u_count gtp_c_count geneve_count gre_count six_in_four_count four_in_six_count srv6_count sctp_count mpls_count isis_count bfd_count pmtud_count
    local ipv6_hbh ipv6_routing ipv6_frag ipv6_esp ipv6_ah
    local tcp_syn tcp_synack tcp_rst tcp_fin tcp_psh tcp_urg tcp_zero_win tcp_retrans
    local tcp_mss tcp_wscale tcp_sack_perm tcp_out_of_order
    local lldp_count cdp_count stp_count vrrp_count hsrp_count eapol_count dhcp_count
    read -r qinq_count arp_count ndp_count ndp_ns ndp_na ndp_rs ndp_ra ndp_redirect vxlan_count gtp_u_count gtp_c_count geneve_count gre_count six_in_four_count four_in_six_count srv6_count sctp_count mpls_count isis_count bfd_count pmtud_count \
            ipv6_hbh ipv6_routing ipv6_frag ipv6_esp ipv6_ah \
            tcp_syn tcp_synack tcp_rst tcp_fin tcp_psh tcp_urg tcp_zero_win tcp_retrans \
            tcp_mss tcp_wscale tcp_sack_perm tcp_out_of_order \
            lldp_count cdp_count stp_count vrrp_count hsrp_count eapol_count dhcp_count < <(
        awk '
            /^[0-9]{2}:[0-9]{2}:[0-9]{2}/ {
                in_qinq=0; in_arp=0; in_ndp=0; in_vxlan=0; in_gtp_u=0; in_gtp_c=0; in_geneve=0; in_gre=0; in_6in4=0; in_4in6=0; in_srv6=0; in_sctp=0; in_mpls=0; in_isis=0; in_bfd=0; in_pmtud=0
                in_lldp=0; in_cdp=0; in_stp=0; in_vrrp=0; in_hsrp=0; in_eapol=0; in_dhcp=0
                in_hbh=0; in_rtg=0; in_frag=0; in_esp=0; in_ah=0
            }
            /ethertype 802.1Q.*ethertype 802.1Q|0x88a8|0x9100|0x9200|QinQ/ { if (!in_qinq) { qinq++; in_qinq=1 } }
            /ethertype ARP|Request who-has|Reply .* is-at|ARP,/ { if (!in_arp) { arp++; in_arp=1 } }
            /neighbor solicitation/ { ndp_ns++; if (!in_ndp) { ndp++; in_ndp=1 } }
            /neighbor advertisement/ { ndp_na++; if (!in_ndp) { ndp++; in_ndp=1 } }
            /router advertisement/ { ndp_ra++; if (!in_ndp) { ndp++; in_ndp=1 } }
            /router solicitation/ { ndp_rs++; if (!in_ndp) { ndp++; in_ndp=1 } }
            /ICMP6, redirect/ { ndp_redirect++; if (!in_ndp) { ndp++; in_ndp=1 } }
            /(\.|[[:space:]])(4789|8472|4790):|(\.|[[:space:]])(4789|8472|4790) >|VXLAN/ { if (!in_vxlan) { vxlan++; in_vxlan=1 } }
            /(\.|[[:space:]])2152:|(\.|[[:space:]])2152 >|GTP-U|GTPv1-U/ { if (!in_gtp_u) { gtp_u++; in_gtp_u=1 } }
            /(\.|[[:space:]])2123:|(\.|[[:space:]])2123 >|GTP-C|GTPv1-C|GTPv2-C/ { if (!in_gtp_c) { gtp_c++; in_gtp_c=1 } }
            /(\.|[[:space:]])6081:|(\.|[[:space:]])6081 >|Geneve/ { if (!in_geneve) { geneve++; in_geneve=1 } }
            /GREv|(proto|next-header) GRE \(47\)/ { if (!in_gre) { gre++; in_gre=1 } }
            /proto IPv6 \(41\)|next-header IPv6 \(41\)/ { if (!in_6in4) { six_in_four++; in_6in4=1 } }
            /next-header (IPIP|IPv4) \(4\)/ { if (!in_4in6) { four_in_six++; in_4in6=1 } }
            /RT6.*type=4|srcrt.*type 4|srh/ { if (!in_srv6) { srv6++; in_srv6=1 } }
            /(proto|next-header) SCTP \(132\)|sctp \(132\)|: sctp/ { if (!in_sctp) { sctp++; in_sctp=1 } }
            /ethertype MPLS|0x8847|0x8848|MPLS,/ { if (!in_mpls) { mpls++; in_mpls=1 } }
            /IS-IS|ethertype 0x00fe|dsap OSI \(0xfe\)/ { if (!in_isis) { isis++; in_isis=1 } }
            /(\.|[[:space:]])(3784|4784|3785|7784):|(\.|[[:space:]])(3784|4784|3785|7784) >|BFD/ { if (!in_bfd) { bfd++; in_bfd=1 } }
            /ICMP6, packet too big|need to frag/ { if (!in_pmtud) { pmtud++; in_pmtud=1 } }
            /next-header (Options|HBH) \(0\)|: HBH/ { if (!in_hbh) { ipv6_hbh++; in_hbh=1 } }
            /next-header (Routing) \(43\)|: srcrt/ { if (!in_rtg) { ipv6_routing++; in_rtg=1 } }
            /next-header (Frag|Fragment) \(44\)|: frag \(|fragment header/ { if (!in_frag) { ipv6_frag++; in_frag=1 } }
            /next-header (ESP) \(50\)|: ESP\(/ { if (!in_esp) { ipv6_esp++; in_esp=1 } }
            /next-header (AH) \(51\)|: AH\(/ { if (!in_ah) { ipv6_ah++; in_ah=1 } }
            /Flags \[S\]/ { tcp_syn++ }
            /Flags \[S\.\]/ { tcp_synack++ }
            /Flags \[R/ { tcp_rst++ }
            /Flags \[F/ { tcp_fin++ }
            /Flags \[.*P.*\]/ { tcp_psh++ }
            /Flags \[.*U.*\]/ { tcp_urg++ }
            /win 0/ { tcp_zero_win++ }
            /\[tcp retrans\]|retransmission/ { tcp_retrans++ }
            /mss [0-9]+/ { tcp_mss++ }
            /wscale [0-9]+/ { tcp_wscale++ }
            /sackOK/ { tcp_sack_perm++ }
            /out-of-order|out of order/ { tcp_out_of_order++ }
            /LLDP|0x88cc/ { if (!in_lldp) { lldp++; in_lldp=1 } }
            /CDPv/ { if (!in_cdp) { cdp++; in_cdp=1 } }
            /STP 802.1|802.3.*STP|ethertype.*0x0027/ { if (!in_stp) { stp++; in_stp=1 } }
            /VRRPv/ { if (!in_vrrp) { vrrp++; in_vrrp=1 } }
            /HSRPv/ { if (!in_hsrp) { hsrp++; in_hsrp=1 } }
            /EAPOL/ { if (!in_eapol) { eapol++; in_eapol=1 } }
            /BOOTP\/DHCP|DHCPv6|dhcp6|\.546 >|\.547 >/ { if (!in_dhcp) { dhcp++; in_dhcp=1 } }
            END {
                print qinq+0, arp+0, ndp+0, ndp_ns+0, ndp_na+0, ndp_rs+0, ndp_ra+0, ndp_redirect+0, vxlan+0, gtp_u+0, gtp_c+0, geneve+0, gre+0, six_in_four+0, four_in_six+0, srv6+0, sctp+0, mpls+0, isis+0, bfd+0, pmtud+0, \
                      ipv6_hbh+0, ipv6_routing+0, ipv6_frag+0, ipv6_esp+0, ipv6_ah+0, \
                      tcp_syn+0, tcp_synack+0, tcp_rst+0, tcp_fin+0, tcp_psh+0, tcp_urg+0, tcp_zero_win+0, tcp_retrans+0, \
                      tcp_mss+0, tcp_wscale+0, tcp_sack_perm+0, tcp_out_of_order+0, \
                      lldp+0, cdp+0, stp+0, vrrp+0, hsrp+0, eapol+0, dhcp+0
            }
        ' "${dump_file}"
    )

    echo -e "${C_CYAN}Discovered IEEE 802.1Q VLAN Tags:${C_RESET}"
    local vlan_ids
    vlan_ids=$(grep -oE "vlan [0-9]+" "${dump_file}" | awk '{print $2}' | sort -nu || true)
    
    if [[ "${qinq_count}" -gt 0 ]]; then
        echo -e "  ${C_CYAN}[FOUND] QinQ Double-Tagging (802.1ad):${C_RESET} ${qinq_count} nested VLAN frame(s) observed."
    fi

    if [[ -n "${vlan_ids}" ]]; then
        echo -e "  ${C_GREEN}${C_BOLD}Trunk Port Detected!${C_RESET} Active 802.1Q VLAN IDs observed:"
        while IFS= read -r vid; do
            [[ -z "${vid}" ]] && continue
            echo -e "    -> VLAN ID: ${C_BOLD}${vid}${C_RESET}"
        done <<< "${vlan_ids}"
    else
        echo -e "  ${C_YELLOW}No 802.1Q tagged frames observed.${C_RESET} Interface is likely connected to an untagged Access Port."
    fi

    echo -e "\n${C_CYAN}Active Unicast MAC Addresses Observed:${C_RESET}"
    # Bit-accurate L2 unicast check: Least significant bit of first octet must be 0: [02468aceACE]
    local unicast_macs
    unicast_macs=$(awk '{print $2, $4}' "${dump_file}" | tr -d ',' | tr ' ' '\n' | \
        grep -iE '^[0-9a-f][02468ace]:([0-9a-f]{2}:){4}[0-9a-f]{2}$' | grep -ivE '^ff:ff:ff:ff:ff:ff$' | sort -u || true)

    local mac_count=0
    if [[ -n "${unicast_macs}" ]]; then
        mac_count=$(echo "${unicast_macs}" | wc -l)
    fi
    if [[ "${mac_count}" -gt 0 ]]; then
        echo -e "  Found ${C_BOLD}${mac_count}${C_RESET} unique Layer 2 host MAC address(es):"
        echo "${unicast_macs}" | head -n 15 | sed 's/^/    /'
        if [[ "${mac_count}" -gt 15 ]]; then
            echo "    ... (displaying first 15 of ${mac_count})"
        fi
    else
        echo "  No unicast MAC addresses observed."
    fi

    # =========================================================================
    # 3. LAYER 3: DUAL-STACK IPv4 & IPv6 DISCOVERY & PROTOCOL PARSING
    # =========================================================================
    echo -e "\n${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD} [3] LAYER 3: DUAL-STACK IPv4 & IPv6 ALLOCATIONS${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}"

    # --- 3.1 Strict IPv4 Extraction & Subnet Mapping ---
    awk '
        function check_ipv4(str,   clean, n, octets, o1, o2, o3, o4) {
            clean = str
            sub(/[:,\)]+$/, "", clean)
            n = split(clean, octets, ".")
            if (n >= 4) {
                o1 = octets[1]; o2 = octets[2]; o3 = octets[3]; o4 = octets[4];
                if (o1 ~ /^[0-9]+$/ && o2 ~ /^[0-9]+$/ && o3 ~ /^[0-9]+$/ && o4 ~ /^[0-9]+$/) {
                    if (o1 >= 0 && o1 <= 255 && o2 >= 0 && o2 <= 255 && o3 >= 0 && o3 <= 255 && o4 >= 0 && o4 <= 255) {
                        if ((o1 == "0" || o1 !~ /^0/) && (o2 == "0" || o2 !~ /^0/) && (o3 == "0" || o3 !~ /^0/) && (o4 == "0" || o4 !~ /^0/)) {
                            print o1 "." o2 "." o3 "." o4
                        }
                    }
                }
            }
        }
        {
            for (i = 1; i <= NF; i++) {
                if ($i == ">") {
                    check_ipv4($(i-1))
                    check_ipv4($(i+1))
                } else if ($i == "who-has" || $i == "tell" || $i == "Reply" || $i == "unreachable") {
                    check_ipv4($(i+1))
                }
            }
        }
    ' "${dump_file}" | sort -u > "${TEMP_DIR}/observed_ipv4.txt"
    # Filter multicast (224.0.0.0/4), loopback (127/8), APIPA (169.254/16), broadcast (255.255.255.255), 0.0.0.0/8
    grep -vE '(^(22[4-9]|23[0-9])\.|^255\.255\.255\.255$|^0\.|^127\.|^169\.254\.)' \
        "${TEMP_DIR}/observed_ipv4.txt" | sort -u > "${TEMP_DIR}/clean_ipv4.txt" || true

    local ip_count
    ip_count=$(wc -l < "${TEMP_DIR}/clean_ipv4.txt")

    if [[ "${ip_count}" -gt 0 ]]; then
        echo -e "${C_CYAN}Inferred IPv4 Network Subnets (/24 approximations):${C_RESET}"
        awk -F'.' '{print $1"."$2"."$3".0/24"}' "${TEMP_DIR}/clean_ipv4.txt" | sort | uniq -c | sort -nr | while read -r count subnet; do
            echo -e "  Subnet: ${C_GREEN}${C_BOLD}${subnet}${C_RESET} (${count} active host IP(s) detected)"
        done

        echo -e "\n${C_CYAN}Identified IPv4 Host IPs:${C_RESET}"
        head -n 20 "${TEMP_DIR}/clean_ipv4.txt" | sed 's/^/    /'
        if [[ "${ip_count}" -gt 20 ]]; then
            echo "    ... (displaying first 20 of ${ip_count})"
        fi
    else
        echo "  No IPv4 addresses identified from traffic."
    fi

    # Inferred Default Gateways
    echo -e "\n${C_CYAN}Inferred Default Gateway Candidates:${C_RESET}"
    local gateways
    gateways=$(grep -E '(\.1$|\.254$)' "${TEMP_DIR}/clean_ipv4.txt" || true)
    local arp_gws
    arp_gws=$(awk '/Reply .* is-at/ {
        for (i = 1; i <= NF; i++) {
            if ($i == "Reply") {
                cand = $(i+1)
                sub(/[:,\)]+$/, "", cand)
                n = split(cand, octets, ".")
                if (n == 4) {
                    if (octets[1] ~ /^[0-9]+$/ && octets[2] ~ /^[0-9]+$/ && octets[3] ~ /^[0-9]+$/ && octets[4] ~ /^[0-9]+$/) {
                        if (octets[1] >= 0 && octets[1] <= 255 && octets[2] >= 0 && octets[2] <= 255 && octets[3] >= 0 && octets[3] <= 255 && octets[4] >= 0 && octets[4] <= 255) {
                            if ((octets[1] == "0" || octets[1] !~ /^0/) && (octets[2] == "0" || octets[2] !~ /^0/) && (octets[3] == "0" || octets[3] !~ /^0/) && (octets[4] == "0" || octets[4] !~ /^0/)) {
                                print cand
                            }
                        }
                    }
                }
            }
        }
    }' "${dump_file}" | sort -u || true)
    local all_gws
    all_gws=$(echo -e "${gateways}\n${arp_gws}" | grep -v '^$' | grep -vE '(^(22[4-9]|23[0-9])\.|^255\.255\.255\.255$|^0\.|^127\.|^169\.254\.)' | sort -u || true)
    
    if [[ -n "${all_gws}" ]]; then
        while IFS= read -r gw; do
            [[ -z "${gw}" ]] && continue
            echo -e "  Likely Gateway: ${C_GREEN}${C_BOLD}${gw}${C_RESET}"
        done <<< "${all_gws}"
        gateways="${all_gws}"
    else
        echo "  No conventional gateway addresses (.1 or .254) or active ARP queries observed."
    fi

    # --- 3.2 Dual-Stack IPv6 Extraction & 6-Tier Classification ---
    # Extract RFC 4291 compliant 128-bit addresses (excluding prefix lengths)
    sed -E 's/^[^:]+:[^:]+:[^:]+ [0-9a-fA-F:]{17} > [0-9a-fA-F:]{17},? //' "${dump_file}" | \
        grep -oE '(\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|\b([0-9a-fA-F]{1,4}:)+:[0-9a-fA-F:]*|\b::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}|\bfe80::[0-9a-fA-F:]+)(/[0-9]+)?' | \
        grep -vE '/[0-9]+' | \
        sed -E 's/([^:]):$/\1/' | grep -vE '^(:|::)$' | grep -vE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$' | sort -u > "${TEMP_DIR}/observed_ipv6.txt" || true
    # Exclude multicast (ff00::/8), loopback (::1), unspecified (::)
    grep -ivE '(^ff[0-9a-f]{2}:|^::1$|^::$)' "${TEMP_DIR}/observed_ipv6.txt" > "${TEMP_DIR}/clean_ipv6.txt" || true

    local ipv6_count
    ipv6_count=$(wc -l < "${TEMP_DIR}/clean_ipv6.txt")

    echo -e "\n${C_CYAN}Discovered IPv6 Host Addresses:${C_RESET}"
    if [[ "${ipv6_count}" -gt 0 ]]; then
        echo -e "  Found ${C_BOLD}${ipv6_count}${C_RESET} active IPv6 host address(es):"
        head -n 15 "${TEMP_DIR}/clean_ipv6.txt" | sed 's/^/    -> /'
        if [[ "${ipv6_count}" -gt 15 ]]; then
            echo "    ... (displaying first 15 of ${ipv6_count})"
        fi
        local gua_count ula_count ll_count
        gua_count=$(grep -c -iE '^(2|3)[0-9a-f]{3}:' "${TEMP_DIR}/clean_ipv6.txt" || true)
        ula_count=$(grep -c -iE '^(fc|fd)[0-9a-f]{2}:' "${TEMP_DIR}/clean_ipv6.txt" || true)
        ll_count=$(grep -c -iE '^fe[89ab][0-9a-f]:' "${TEMP_DIR}/clean_ipv6.txt" || true)
        echo -e "  Classification: Global Unicast (GUA): ${gua_count} | Unique Local (ULA): ${ula_count} | Link-Local: ${ll_count}"
    else
        echo "  [ -- ] No IPv6 unicast host addresses observed."
    fi

    if [[ "${ipv6_count}" -gt 0 ]]; then
        echo -e "\n${C_CYAN}Inferred IPv6 Subnets (/64 approximations):${C_RESET}"
        awk '
            function norm_hex(h) {
                sub(/^0+/, "", h);
                return (h == "") ? "0" : tolower(h);
            }
            function expand_v6(ip, parts, left, right, l_arr, r_arr, nl, nr, zeros, i, full) {
                ip = tolower(ip);
                if (ip ~ /::/) {
                    split(ip, parts, "::");
                    left = parts[1]; right = parts[2];
                    nl = (left == "") ? 0 : split(left, l_arr, ":");
                    nr = (right == "") ? 0 : split(right, r_arr, ":");
                    zeros = 8 - nl - nr;
                    full = "";
                    for (i = 1; i <= nl; i++) full = (full == "" ? "" : full ":") norm_hex(l_arr[i]);
                    for (i = 1; i <= zeros; i++) full = (full == "" ? "" : full ":") "0";
                    for (i = 1; i <= nr; i++) full = (full == "" ? "" : full ":") norm_hex(r_arr[i]);
                    return full;
                }
                split(ip, l_arr, ":");
                full = "";
                for (i = 1; i <= 8; i++) full = (full == "" ? "" : full ":") norm_hex(l_arr[i]);
                return full;
            }
            function subnet64(ip, expanded, arr, h1, h2, h3, h4) {
                expanded = expand_v6(ip);
                split(expanded, arr, ":");
                h1 = arr[1]; h2 = arr[2]; h3 = arr[3]; h4 = arr[4];
                if (h2 == "0" && h3 == "0" && h4 == "0") return h1 "::/64";
                if (h3 == "0" && h4 == "0") return h1 ":" h2 "::/64";
                if (h4 == "0") return h1 ":" h2 ":" h3 "::/64";
                return h1 ":" h2 ":" h3 ":" h4 "::/64";
            }
            NF == 0 || $0 !~ /^[0-9a-fA-F:]+$/ || $0 ~ /^[fF][eE][89abAB][0-9a-fA-F]:/ { next }
            { print subnet64($0); }
        ' "${TEMP_DIR}/clean_ipv6.txt" | sort | uniq -c | sort -nr | while read -r count subnet; do
            echo -e "  Subnet: ${C_GREEN}${C_BOLD}${subnet}${C_RESET} (${count} active host IP(s) detected)"
        done
    fi

    # IPv6 SLAAC Prefixes & Router Advertisements
    echo -e "\n${C_CYAN}IPv6 Router Advertisements & SLAAC Prefixes:${C_RESET}"
    local ipv6_prefixes
    ipv6_prefixes=$(awk -F': ' '/prefix info option/ {print $2}' "${dump_file}" 2>/dev/null | awk -F',' '{print $1}' | sort -u || true)
    if [[ -z "${ipv6_prefixes}" ]]; then
        ipv6_prefixes=$(grep -i "prefix info" "${dump_file}" 2>/dev/null | grep -oE "prefix [0-9a-fA-F:]+/[0-9]+" | awk '{print $2}' | sort -u || true)
    fi

    local ipv6_ras
    ipv6_ras=$(awk -F': ' '/ICMP6, router advertisement/ {for(i=1;i<=NF;i++) if($i ~ /> ff02::1/) print $i}' "${dump_file}" | awk -F' > ' '{print $1}' | awk '{print $NF}' | tr -d '!' | sort -u || true)
    if [[ -z "${ipv6_ras}" ]]; then
        ipv6_ras=$(awk '/router advertisement/ {for(i=1;i<=NF;i++) if($i==">") {ip=$(i-1); sub(/\..*$/, "", ip); print ip}}' "${dump_file}" | tr -d '!,' | grep -iE '^[0-9a-f:]+$' | grep -vE '^[0-9]+$' | sort -u || true)
    fi
    
    if [[ -n "${ipv6_prefixes}" ]]; then
        echo -e "  ${C_GREEN}[FOUND] Advertised SLAAC Subnet Prefixes (/64):${C_RESET}"
        while IFS= read -r pfx; do
            [[ -z "${pfx}" ]] && continue
            echo -e "    -> Prefix: ${C_BOLD}${pfx}${C_RESET}"
        done <<< "${ipv6_prefixes}"
    fi
    if [[ -n "${ipv6_ras}" ]]; then
        echo -e "  ${C_GREEN}[FOUND] IPv6 Router Advertisements originating from:${C_RESET}"
        while IFS= read -r ra; do
            [[ -z "${ra}" ]] && continue
            echo -e "    -> Router: ${C_BOLD}${ra}${C_RESET}"
        done <<< "${ipv6_ras}"
    elif [[ -z "${ipv6_prefixes}" ]]; then
        echo "  [ -- ] IPv6 RAs: Not observed."
    fi

    # IPv6 Extension Headers
    echo -e "\n${C_CYAN}IPv6 Extension Headers Observed:${C_RESET}"
    local v6_ext_total=$((ipv6_hbh + ipv6_routing + ipv6_frag + ipv6_esp + ipv6_ah))
    if [[ ${v6_ext_total} -gt 0 ]]; then
        echo -e "  Hop-by-Hop (0) : ${ipv6_hbh} | Routing (43) : ${ipv6_routing} | Fragment (44) : ${ipv6_frag}"
        echo -e "  IPsec ESP (50) : ${ipv6_esp} | IPsec AH (51) : ${ipv6_ah}"
    else
        echo -e "  [ -- ] No IPv6 extension headers observed."
    fi

    # Address Resolution (ARP & NDP)
    echo -e "\n${C_CYAN}Address Resolution Protocol Activity:${C_RESET}"
    echo -e "  IPv4 ARP Resolution Frames  : ${arp_count}"
    echo -e "  IPv6 NDP Resolution Frames  : ${ndp_count} (NS: ${ndp_ns:-0}, NA: ${ndp_na:-0}, RS: ${ndp_rs:-0}, RA: ${ndp_ra:-0}, Redirect: ${ndp_redirect:-0})"

    # Overlay Networks & Tunnels
    echo -e "\n${C_CYAN}Network Tunnels & Overlay Encapsulation:${C_RESET}"
    local tunnels_found=0
    if [[ "${vxlan_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] VXLAN Overlay Tunnels:${C_RESET} ${vxlan_count} UDP/4789 packet(s)."
        tunnels_found=1
    fi
    if [[ "${gtp_u_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] GTP-U Mobile User Plane Tunnels:${C_RESET} ${gtp_u_count} UDP/2152 packet(s)."
        tunnels_found=1
    fi
    if [[ "${gtp_c_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] GTP-C Mobile Control Plane Tunnels:${C_RESET} ${gtp_c_count} UDP/2123 packet(s)."
        tunnels_found=1
    fi
    if [[ "${geneve_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] Geneve Overlay Tunnels:${C_RESET} ${geneve_count} UDP/6081 packet(s)."
        tunnels_found=1
    fi
    if [[ "${gre_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] GRE Tunnels Detected:${C_RESET} ${gre_count} IP/47 encapsulation packet(s)."
        tunnels_found=1
    fi
    if [[ "${mpls_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] MPLS Transport Labeling:${C_RESET} ${mpls_count} frame(s) observed."
        tunnels_found=1
    fi
    if [[ "${six_in_four_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] 6in4 IPv6 Encapsulation:${C_RESET} ${six_in_four_count} IP/41 packet(s)."
        tunnels_found=1
    fi
    if [[ "${four_in_six_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] 4in6 IPv4 Encapsulation:${C_RESET} ${four_in_six_count} IPv6/4 packet(s)."
        tunnels_found=1
    fi
    if [[ "${srv6_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] SRv6 Segment Routing:${C_RESET} ${srv6_count} Routing Type 4 frame(s)."
        tunnels_found=1
    fi
    if [[ "${sctp_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}[ALERT] SCTP Telecom Signaling:${C_RESET} ${sctp_count} IP/132 carrier packet(s)."
        tunnels_found=1
    fi
    if [[ "${isis_count}" -gt 0 ]]; then
        echo -e "  ${C_GREEN}[FOUND] IS-IS Routing Protocol:${C_RESET} ${isis_count} frame(s) observed."
        tunnels_found=1
    fi
    if [[ "${bfd_count}" -gt 0 ]]; then
        echo -e "  ${C_CYAN}[FOUND] BFD Fault Detection:${C_RESET} ${bfd_count} frame(s) observed."
        tunnels_found=1
    fi
    if [[ "${pmtud_count}" -gt 0 ]]; then
        echo -e "  ${C_YELLOW}[WARN] Path MTU Discovery (PTB/Frag Needed):${C_RESET} ${pmtud_count} frame(s) observed."
        tunnels_found=1
    fi
    if [[ "${tunnels_found}" -eq 0 ]]; then
        echo "  [ -- ] No common overlay tunnels (VXLAN, GTP-U/C, Geneve, GRE, MPLS) observed."
    fi

    # TCP Flag Profiling & Options
    echo -e "\n${C_CYAN}TCP Connection State Matrix & Options:${C_RESET}"
    echo -e "  SYN Requests : ${tcp_syn} | SYN-ACK Handshakes : ${tcp_synack} | RST Aborts : ${tcp_rst} | FIN Closes : ${tcp_fin}"
    if [[ "${tcp_psh}" -gt 0 || "${tcp_urg}" -gt 0 || "${tcp_zero_win}" -gt 0 || "${tcp_retrans}" -gt 0 ]]; then
        echo -e "  PSH Flags    : ${tcp_psh} | URG Flags : ${tcp_urg} | Zero-Window Events : ${tcp_zero_win} | Retransmissions : ${tcp_retrans}"
    fi
    if [[ "${tcp_mss}" -gt 0 || "${tcp_wscale}" -gt 0 || "${tcp_sack_perm}" -gt 0 || "${tcp_out_of_order}" -gt 0 ]]; then
        echo -e "  TCP Options  : MSS (${tcp_mss}) | WScale (${tcp_wscale}) | SACK Perm (${tcp_sack_perm}) | Out-of-Order (${tcp_out_of_order})"
    fi

    # Top Talkers & Flow Matrix Generation
    python3 -B -c '
import re, sys, json
from collections import Counter
import ipaddress

ipv4_counter = Counter()
ipv6_counter = Counter()
flow_counter = Counter()

dump_path = sys.argv[1]
out_json = sys.argv[2]

def parse_endpoint(ep):
    ep = ep.strip().rstrip(":,")
    if "." in ep:
        last_dot = ep.rfind(".")
        cand_ip = ep[:last_dot]
        cand_port = ep[last_dot+1:]
        if cand_port.isdigit():
            try:
                ipaddress.ip_address(cand_ip)
                return cand_ip, cand_port
            except ValueError:
                pass
    try:
        ipaddress.ip_address(ep)
        return ep, None
    except ValueError:
        pass
    return None, None

try:
    with open(dump_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if " > " not in line:
                continue
            cleaned = re.sub(r"^[0-9:.]+ +[0-9a-fA-F:]{17} +> +[0-9a-fA-F:]{17},? *", "", line)
            cleaned = re.sub(r"\([^)]+\)", "", cleaned)
            for match in re.finditer(r"([0-9a-fA-F:.]+)\s+>\s+([0-9a-fA-F:.]+)", cleaned):
                left, right = match.group(1), match.group(2)
                ip1, p1 = parse_endpoint(left)
                ip2, p2 = parse_endpoint(right)
                if ip1 and ip2:
                    try:
                        addr1 = ipaddress.ip_address(ip1)
                        addr2 = ipaddress.ip_address(ip2)
                        if addr1.version == 4 and addr2.version == 4:
                            if not (addr1.is_multicast or addr2.is_multicast or addr1.is_loopback or addr2.is_loopback or str(addr1)=="0.0.0.0" or str(addr2)=="255.255.255.255"):
                                ipv4_counter[str(addr1)] += 1
                                ipv4_counter[str(addr2)] += 1
                                f_ep1 = f"{ip1}:{p1}" if p1 else ip1
                                f_ep2 = f"{ip2}:{p2}" if p2 else ip2
                                flow = f"{f_ep1} <-> {f_ep2}"
                                flow_counter[flow] += 1
                        elif addr1.version == 6 and addr2.version == 6:
                            if not (addr1.is_multicast or addr2.is_multicast or addr1.is_loopback or addr2.is_loopback or addr1.is_unspecified or addr2.is_unspecified):
                                ipv6_counter[str(addr1)] += 1
                                ipv6_counter[str(addr2)] += 1
                                f_ep1 = f"[{ip1}]:{p1}" if p1 else f"[{ip1}]"
                                f_ep2 = f"[{ip2}]:{p2}" if p2 else f"[{ip2}]"
                                flow = f"{f_ep1} <-> {f_ep2}"
                                flow_counter[flow] += 1
                    except Exception:
                        pass
except Exception:
    pass

top_v4 = [{"ip": ip, "packets": count} for ip, count in ipv4_counter.most_common(10)]
top_v6 = [{"ip": ip, "packets": count} for ip, count in ipv6_counter.most_common(10)]
top_flows = [{"flow": fl, "packets": count} for fl, count in flow_counter.most_common(10)]

result = {
    "ipv4": top_v4,
    "ipv6": top_v6,
    "flows": top_flows
}
with open(out_json, "w", encoding="utf-8") as out_f:
    json.dump(result, out_f, indent=2)
' "${dump_file}" "${TEMP_DIR}/top_talkers.json" 2>/dev/null || true

    if [[ -f "${TEMP_DIR}/top_talkers.json" ]]; then
        python3 -B -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    v4 = data.get("ipv4", [])
    v6 = data.get("ipv6", [])
    flows = data.get("flows", [])
    if v4 or v6 or flows:
        print(f"\n{sys.argv[2]}Top Active Host Talkers & Conversations:{sys.argv[3]}")
        if v4:
            print("  Top IPv4 Hosts : " + " | ".join(f"{h[\"ip\"]} ({h[\"packets\"]} pkts)" for h in v4[:5]))
        if v6:
            print("  Top IPv6 Hosts : " + " | ".join(f"{h[\"ip\"]} ({h[\"packets\"]} pkts)" for h in v6[:5]))
        if flows:
            print("  Top Flows      : " + " | ".join(f"{fl[\"flow\"]} ({fl[\"packets\"]} pkts)" for fl in flows[:3]))
except Exception:
    pass
' "${TEMP_DIR}/top_talkers.json" "${C_CYAN}" "${C_RESET}" 2>/dev/null || true
    fi

    # =========================================================================
    # 4. INFRASTRUCTURE & SWITCH DISCOVERY PROTOCOLS
    # =========================================================================
    echo -e "\n${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD} [4] INFRASTRUCTURE PROTOCOLS (LLDP, CDP, STP, FHRP)${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}"

    # LLDP (EtherType 0x88cc)
    if [[ "${lldp_count}" -gt 0 ]]; then
        echo -e "  ${C_GREEN}[FOUND] LLDP (Link Layer Discovery Protocol):${C_RESET} ${lldp_count} frames observed."
        grep -iE "LLDP.*length" "${dump_file}" | head -n 6 | sed 's/^/    /' || true
    else
        echo "  [ -- ] LLDP: Not observed."
    fi

    # CDP (Cisco Discovery Protocol)
    if [[ "${cdp_count}" -gt 0 ]]; then
        echo -e "  ${C_GREEN}[FOUND] CDP (Cisco Discovery Protocol):${C_RESET} ${cdp_count} frames observed."
        grep -i "CDPv" "${dump_file}" | head -n 6 | sed 's/^/    /' || true
    else
        echo "  [ -- ] CDP: Not observed."
    fi

    # STP BPDUs (01:80:c2:00:00:00)
    if [[ "${stp_count}" -gt 0 ]]; then
        echo -e "  ${C_GREEN}[FOUND] Spanning Tree Protocol (STP):${C_RESET} ${stp_count} BPDUs observed."
    else
        echo "  [ -- ] STP BPDUs: Not observed (PortFast/BPDU filter may be active)."
    fi

    # FHRP (HSRP / VRRP)
    if [[ "${vrrp_count}" -gt 0 ]]; then
        echo -e "  ${C_GREEN}[FOUND] VRRP (Virtual Router Redundancy):${C_RESET} ${vrrp_count} frames observed."
    fi
    if [[ "${hsrp_count}" -gt 0 ]]; then
        echo -e "  ${C_GREEN}[FOUND] Cisco HSRP:${C_RESET} ${hsrp_count} frames observed."
    fi

    # =========================================================================
    # 5. SECURITY CONTROLS & ADMISSION POLICIES
    # =========================================================================
    echo -e "\n${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD} [5] LAYER 2 SECURITY & ADMISSION CONTROL PROFILE${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}"

    # IEEE 802.1X Check (EAPOL: EtherType 0x888e)
    if [[ "${eapol_count}" -gt 0 ]]; then
        echo -e "  ${C_RED}${C_BOLD}[ALERT] IEEE 802.1X Port Control DETECTED!${C_RESET}"
        echo -e "    Observed ${eapol_count} EAPOL frame(s). The switch is running 802.1X Network Access Control."
        echo -e "    Unauthenticated active traffic will be dropped or trigger port quarantine."
    else
        echo -e "  [PASS] IEEE 802.1X (EAPOL): No EAPOL identity requests observed."
    fi

    # DHCP Snooping / DHCP Analysis
    if [[ "${dhcp_count}" -gt 0 ]]; then
        echo -e "  ${C_CYAN}DHCP Infrastructure Active:${C_RESET} ${dhcp_count} DHCP broadcast/relay packets observed."
    else
        echo "  [ -- ] DHCP: No DHCP Discover/Offer packets observed."
    fi

    # Port Security Risk Evaluation
    echo -e "\n${C_CYAN}Port Security / MAC Limit Risk Assessment:${C_RESET}"
    if [[ "${mac_count}" -eq 1 ]]; then
        echo -e "  ${C_YELLOW}${C_BOLD}[CAUTION] High Likelihood of MAC Limit / Sticky Port Security!${C_RESET}"
        echo -e "  Only a SINGLE unicast MAC address (${unicast_macs}) was observed."
        echo -e "  If this port is configured for 'switchport port-security maximum 1', sending traffic"
        echo -e "  with any other MAC address will trigger an ${C_RED}err-disable shutdown${C_RESET}."
    elif [[ "${mac_count}" -gt 1 ]]; then
        echo -e "  ${C_GREEN}[LOW RISK]${C_RESET} Multiple MAC addresses (${mac_count}) observed. The switchport is"
        echo -e "  not restricted to a single sticky MAC address."
    else
        echo "  Insufficient traffic captured to evaluate MAC constraints."
    fi

    # =========================================================================
    # 6. DEEP PROTOCOL INSPECTION (L4-L7)
    # =========================================================================
    local snmp_strings="" ospf_routers="" bgp_asns="" dhcp_hosts="" dns_names="" tls_sni=""

    if command -v tshark >/dev/null 2>&1; then
        echo -e "\n${C_BOLD}======================================================================${C_RESET}"
        echo -e "${C_MAGENTA}${C_BOLD} [6] DEEP PROTOCOL INSPECTION (L4-L7 via TSHARK)${C_RESET}"
        echo -e "${C_BOLD}======================================================================${C_RESET}"

        local tshark_dump="${TEMP_DIR}/all_tshark.txt"
        log_info "Caching Deep Protocol Inspection data (L4-L7)..."
        for pf in "${files_to_analyze[@]}"; do
            tshark -r "${pf}" -T fields \
                -e snmp.community \
                -e ospf.srcrouter \
                -e ospf.advrouter \
                -e bgp.open.myas \
                -e bgp.update.path_attribute.as_path_segment.as4 \
                -e bgp.update.path_attribute.as_path_segment.as2 \
                -e dhcp.option.hostname \
                -e dhcp.fqdn.name \
                -e dns.qry.name \
                -e tls.handshake.extensions_server_name 2>/dev/null >> "${tshark_dump}" || true
        done

        local tshark_retrans=0
        for pf in "${files_to_analyze[@]}"; do
            local rc
            rc=$( (tshark -r "${pf}" -Y "tcp.analysis.retransmission" 2>/dev/null || true) | wc -l)
            tshark_retrans=$((tshark_retrans + rc))
        done
        if [[ ${tshark_retrans} -gt ${tcp_retrans} ]]; then
            tcp_retrans=${tshark_retrans}
        fi

        # SNMP Community Strings
        snmp_strings=$(awk -F'\t' '{if ($1 != "") print $1}' "${tshark_dump}" | sort -u || true)
        if [[ -n "${snmp_strings}" ]]; then
            echo -e "${C_RED}${C_BOLD}[ALERT] SNMP Cleartext Community Strings Detected:${C_RESET}"
            while IFS= read -r snmp; do
                [[ -z "${snmp}" ]] && continue
                echo -e "  -> ${C_BOLD}${snmp}${C_RESET}"
            done <<< "${snmp_strings}"
        else
            echo -e "${C_CYAN}SNMP:${C_RESET} No cleartext community strings observed."
        fi

        # Routing Protocols (OSPF / OSPFv3 / BGP)
        ospf_routers=$(awk -F'\t' '{print $2"\n"$3}' "${tshark_dump}" | grep -v '^$' | sort -u || true)
        if [[ -n "${ospf_routers}" ]]; then
            echo -e "\n${C_GREEN}OSPF/OSPFv3 Neighbors (Router IDs):${C_RESET}"
            echo "${ospf_routers}" | sed 's/^/  -> /'
        fi

        bgp_asns=$(awk -F'\t' '{print $4"\n"$5"\n"$6}' "${tshark_dump}" | tr ',' '\n' | grep -v '^$' | sort -u || true)
        if [[ -n "${bgp_asns}" ]]; then
            echo -e "\n${C_GREEN}BGP Autonomous Systems (ASNs):${C_RESET}"
            echo "${bgp_asns}" | sed 's/^/  -> AS/'
        fi

        # DHCP Hostnames
        dhcp_hosts=$(awk -F'\t' '{print $7"\n"$8}' "${tshark_dump}" | grep -v '^$' | sort -u || true)
        if [[ -n "${dhcp_hosts}" ]]; then
            echo -e "\n${C_GREEN}DHCP Hostnames Detected:${C_RESET}"
            echo "${dhcp_hosts}" | sed 's/^/  -> /'
        fi

        # DNS / mDNS / LLMNR Namespace
        dns_names=$(awk -F'\t' '{if ($9 != "") print $9}' "${tshark_dump}" | sort -u | head -n 15 || true)
        if [[ -n "${dns_names}" ]]; then
            echo -e "\n${C_CYAN}Top DNS / mDNS / LLMNR Queries:${C_RESET}"
            echo "${dns_names}" | sed 's/^/  -> /'
        fi

        # TLS SNI (Server Name Indication)
        tls_sni=$(awk -F'\t' '{if ($10 != "") print $10}' "${tshark_dump}" | sort -u | head -n 15 || true)
        if [[ -n "${tls_sni}" ]]; then
            echo -e "\n${C_CYAN}Top TLS SNI Destinations:${C_RESET}"
            echo "${tls_sni}" | sed 's/^/  -> /'
        fi
        
    else
        echo -e "\n${C_BOLD}======================================================================${C_RESET}"
        echo -e "${C_MAGENTA}${C_BOLD} [6] DEEP PROTOCOL INSPECTION (L4-L7 via TCPDUMP FALLBACK)${C_RESET}"
        echo -e "${C_BOLD}======================================================================${C_RESET}"
        echo -e "  tshark is not installed; operating in native tcpdump decode mode."

        # Routing Protocols (OSPF / OSPFv3 / BGP)
        ospf_routers=$(grep -oE "(Router-ID|Advertising Router) [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "${dump_file}" 2>/dev/null | awk '{print $NF}' | sort -u || true)
        if [[ -n "${ospf_routers}" ]]; then
            echo -e "\n${C_GREEN}OSPF/OSPFv3 Neighbors (Router IDs):${C_RESET}"
            echo "${ospf_routers}" | sed 's/^/  -> /'
        fi

        bgp_asns=$(sed -nE 's/.*my AS ([0-9]+).*/\1/p; s/.*AS Path.*:[[:space:]]*([0-9]+).*/\1/p' "${dump_file}" 2>/dev/null | sort -u || true)
        if [[ -n "${bgp_asns}" ]]; then
            echo -e "\n${C_GREEN}BGP Autonomous Systems (ASNs):${C_RESET}"
            echo "${bgp_asns}" | sed 's/^/  -> AS/'
        fi

        # DHCP Hostnames
        dhcp_hosts=$(sed -nE 's/.*(Hostname \([0-9]+\)|FQDN \([0-9]+\)),.*: "([^"]+)".*/\2/p' "${dump_file}" 2>/dev/null | sort -u || true)
        if [[ -n "${dhcp_hosts}" ]]; then
            echo -e "\n${C_GREEN}DHCP Hostnames Detected:${C_RESET}"
            echo "${dhcp_hosts}" | sed 's/^/  -> /'
        fi

        # DNS / mDNS / LLMNR Namespace
        dns_names=$(sed -nE 's/.*[0-9]+\+? [A-Z0-9]+\? ([a-zA-Z0-9\._-]+)\. .*/\1/p' "${dump_file}" 2>/dev/null | sort -u | head -n 15 || true)
        if [[ -n "${dns_names}" ]]; then
            echo -e "\n${C_CYAN}Top DNS / mDNS / LLMNR Queries:${C_RESET}"
            echo "${dns_names}" | sed 's/^/  -> /'
        fi

        # SNMP Community Strings
        for pf in "${files_to_analyze[@]}"; do
            local sc
            if [[ "${pf}" =~ \.gz$ ]]; then
                sc=$(gzip -dc "${pf}" 2>/dev/null | tcpdump -r - -s 0 -A "udp port 161" 2>/dev/null | tr -d '\000-\010\013\014\016-\037' | grep -oE "public|private|[a-zA-Z0-9_]{3,32}" | grep -vE '^(IP|GetRequest|GetNextRequest|SetRequest|SNMP|udp)$' | sort -u || true)
            else
                sc=$(tcpdump -r "${pf}" -s 0 -A "udp port 161" 2>/dev/null | tr -d '\000-\010\013\014\016-\037' | grep -oE "public|private|[a-zA-Z0-9_]{3,32}" | grep -vE '^(IP|GetRequest|GetNextRequest|SetRequest|SNMP|udp)$' | sort -u || true)
            fi
            if [[ -n "${sc}" ]]; then
                snmp_strings=$(echo -e "${snmp_strings}\n${sc}" | grep -v '^$' | sort -u || true)
            fi
        done
        if [[ -n "${snmp_strings}" ]]; then
            echo -e "${C_RED}${C_BOLD}[ALERT] SNMP Cleartext Community Strings Detected:${C_RESET}"
            while IFS= read -r snmp; do
                [[ -z "${snmp}" ]] && continue
                echo -e "  -> ${C_BOLD}${snmp}${C_RESET}"
            done <<< "${snmp_strings}"
        fi

        # TLS SNI
        for pf in "${files_to_analyze[@]}"; do
            local sni
            if [[ "${pf}" =~ \.gz$ ]]; then
                sni=$(gzip -dc "${pf}" 2>/dev/null | tcpdump -r - -s 0 -A "tcp port 443" 2>/dev/null | grep -oE "[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9\.]+" | grep -E "\.(com|net|org|io|internal|corp|edu|gov)$" | sort -u || true)
            else
                sni=$(tcpdump -r "${pf}" -s 0 -A "tcp port 443" 2>/dev/null | grep -oE "[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9\.]+" | grep -E "\.(com|net|org|io|internal|corp|edu|gov)$" | sort -u || true)
            fi
            if [[ -n "${sni}" ]]; then
                tls_sni=$(echo -e "${tls_sni}\n${sni}" | grep -v '^$' | sort -u | head -n 15 || true)
            fi
        done
        if [[ -n "${tls_sni}" ]]; then
            echo -e "\n${C_CYAN}Top TLS SNI Destinations:${C_RESET}"
            echo "${tls_sni}" | sed 's/^/  -> /'
        fi
    fi

    # =========================================================================
    # 7. ACTIVE AUDIT & TARGET PROBING CORRELATION
    # =========================================================================
    local audit_files=()
    while IFS= read -r -d $'\0' af; do
        audit_files+=("$af")
    done < <(find "${target_dir}" -maxdepth 1 -name "*_probe_audit.jsonl" -print0 2>/dev/null | sort -z)

    if [[ ${#audit_files[@]} -gt 0 ]]; then
        python3 -B -c '
import json, os, re, sys

dump_path = sys.argv[1]
out_json = sys.argv[2]
audit_paths = sys.argv[3:]

audit_files = []
probes_sent = 0
vlans_probed_set = set()
probed_ips = set()
probed_types = set()

for p in audit_paths:
    audit_files.append(os.path.basename(p))
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    probes_sent += 1
                    ptype = record.get("probe_type")
                    if ptype:
                        probed_types.add(ptype)
                    target = record.get("target")
                    if target:
                        probed_ips.add(str(target))
                    v = record.get("vlan")
                    if v is not None:
                        vlans_probed_set.add(str(v))
                    else:
                        vlans_probed_set.add("untagged")
                except Exception:
                    pass
    except Exception:
        pass

vlans_probed = sorted(list(vlans_probed_set), key=lambda x: (x != "untagged", int(x) if x.isdigit() else x))
responses_received = 0
discovered_hosts_dict = {}

current_vlan = "untagged"
if os.path.exists(dump_path):
    with open(dump_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            vlan_match = re.search(r"\bvlan\s+(\d+)\b", line)
            if vlan_match:
                current_vlan = vlan_match.group(1)
            elif not line.startswith(" ") and not line.startswith("\t"):
                current_vlan = "untagged"
            pkt_vlan = current_vlan

            arp_match = re.search(r"Reply\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+is-at\s+([0-9a-fA-F:]{17})", line)
            if arp_match:
                ip = arp_match.group(1)
                mac = arp_match.group(2).lower()
                if not probed_ips or ip in probed_ips:
                    responses_received += 1
                    key = (ip, pkt_vlan)
                    if key not in discovered_hosts_dict:
                        discovered_hosts_dict[key] = mac
                continue

            if "ICMP echo reply" in line or "need to frag" in line or "packet too big" in line or "echo reply" in line:
                responses_received += 1
                continue

            if "BOOTP/DHCP, Reply" in line or ("dhcp" in probed_types and "BOOTP/DHCP" in line and ">" in line):
                dhcp_ip_m = re.search(r"Your-IP\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                dhcp_mac_m = re.search(r"Client-Ethernet-Address\s+([0-9a-fA-F:]{17})", line)
                if dhcp_ip_m and dhcp_mac_m:
                    ip = dhcp_ip_m.group(1)
                    mac = dhcp_mac_m.group(2).lower()
                    key = (ip, pkt_vlan)
                    discovered_hosts_dict[key] = mac
                responses_received += 1
                continue

            if "DHCPv6" in line and ("reply" in line.lower() or "advertise" in line.lower()):
                responses_received += 1
                continue

            if "Flags [S.]" in line or "Flags [R" in line:
                for ip in probed_ips:
                    if ip and f"{ip}." in line:
                        responses_received += 1
                        break
                continue

            if "neighbor advertisement" in line:
                responses_received += 1
                tgt_m = re.search(r"tgt\s+is\s+([0-9a-fA-F:]+)", line)
                mac_m = re.search(r"([0-9a-fA-F:]{17})\s+>", line)
                if not mac_m:
                    mac_m = re.search(r">\s+([0-9a-fA-F:]{17})", line)
                if tgt_m:
                    tgt_ip = tgt_m.group(1).lower()
                    if not probed_ips or tgt_ip in probed_ips:
                        tgt_mac = mac_m.group(1).lower() if mac_m else "unknown"
                        key = (tgt_ip, pkt_vlan)
                        if key not in discovered_hosts_dict:
                            discovered_hosts_dict[key] = tgt_mac
                continue

discovered_hosts = [
    {"ip": ip, "mac": mac, "vlan": vlan}
    for (ip, vlan), mac in sorted(discovered_hosts_dict.items())
]

result = {
    "audit_files": audit_files,
    "probes_sent": probes_sent,
    "responses_received": responses_received,
    "vlans_probed": vlans_probed,
    "discovered_hosts": discovered_hosts
}

with open(out_json, "w", encoding="utf-8") as out_f:
    json.dump(result, out_f, indent=2)
' "${dump_file}" "${TEMP_DIR}/active_audit.json" "${audit_files[@]}" 2>/dev/null || true

        echo -e "\n${C_BOLD}======================================================================${C_RESET}"
        echo -e "${C_MAGENTA}${C_BOLD} [7] ACTIVE AUDIT & TARGET PROBING CORRELATION${C_RESET}"
        echo -e "${C_BOLD}======================================================================${C_RESET}"

        if [[ -f "${TEMP_DIR}/active_audit.json" ]]; then
            local p_sent p_resp
            p_sent=$(grep -o '"probes_sent": [0-9]*' "${TEMP_DIR}/active_audit.json" | awk '{print $2}')
            p_resp=$(grep -o '"responses_received": [0-9]*' "${TEMP_DIR}/active_audit.json" | awk '{print $2}')
            echo -e "  Audit Trail Logs     : ${C_BOLD}${#audit_files[@]}${C_RESET} audit file(s) found in capture dir"
            echo -e "  Probes Transmitted   : ${C_CYAN}${C_BOLD}${p_sent:-0}${C_RESET} packet(s)"
            echo -e "  Responses Received   : ${C_GREEN}${C_BOLD}${p_resp:-0}${C_RESET} packet(s)"

            python3 -B -c '
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    vlans = data.get("vlans_probed", [])
    if vlans:
        print(f"  VLAN Profiles Tested : {sys.argv[2]}{sys.argv[3]}" + ", ".join(vlans) + f"{sys.argv[4]}")
    hosts = data.get("discovered_hosts", [])
    if hosts:
        print(f"\n  {sys.argv[5]}Discovered Responsive Hosts:{sys.argv[4]}")
        for h in hosts:
            print(f"    -> {sys.argv[3]}{h[\"ip\"]}{sys.argv[4]} [{h[\"mac\"]}] (VLAN: {h[\"vlan\"]})")
except Exception:
    pass
' "${TEMP_DIR}/active_audit.json" "${C_CYAN}" "${C_BOLD}" "${C_RESET}" "${C_GREEN}" 2>/dev/null || true
        fi
    fi

    echo -e "\n${C_BOLD}======================================================================${C_RESET}"
    echo -e "${C_GREEN}${C_BOLD}                      ANALYSIS COMPLETE${C_RESET}"
    echo -e "${C_BOLD}======================================================================${C_RESET}\n"

    if [[ "${JSON_OUT}" == "1" ]]; then
        exec 1>&3
        exec 3>&-
        
        local raw_ipv4; raw_ipv4=$(cat "${TEMP_DIR}/clean_ipv4.txt" 2>/dev/null || true)
        local raw_ipv6; raw_ipv6=$(cat "${TEMP_DIR}/clean_ipv6.txt" 2>/dev/null || true)
        
        to_jarr() {
            local input="$1"
            if [[ -z "${input//[[:space:]]/}" ]]; then
                echo "[]"
                return
            fi
            local clean_input
            clean_input=$(printf "%s" "${input}" | tr -d '\001-\010\013\014\016-\037\177')
            local out="[" first=1 item
            while IFS= read -r item; do
                [[ -z "${item}" ]] && continue
                # Escape backslash and double quote
                item="${item//\\/\\\\}"
                item="${item//\"/\\\"}"
                # Escape RFC 8259 required control characters
                item="${item//$'\t'/\\t}"
                item="${item//$'\r'/\\r}"
                item="${item//$'\n'/\\n}"
                if [[ ${first} -eq 1 ]]; then
                    out+="\"${item}\""
                    first=0
                else
                    out+=", \"${item}\""
                fi
            done <<< "${clean_input}"
            out+="]"
            echo "${out}"
        }

        cat <<EOF
{
  "vlans": $(to_jarr "$vlan_ids"),
  "qinq_frames": ${qinq_count:-0},
  "mac_addresses": $(to_jarr "$unicast_macs"),
  "ipv4_addresses": $(to_jarr "$raw_ipv4"),
  "ipv4_gateways": $(to_jarr "$gateways"),
  "ipv6_addresses": $(to_jarr "$raw_ipv6"),
  "ipv6_prefixes": $(to_jarr "$ipv6_prefixes"),
  "ipv6_routers": $(to_jarr "$ipv6_ras"),
  "resolution": {
    "arp_frames": ${arp_count:-0},
    "ndp_frames": ${ndp_count:-0},
    "ndp_details": {
      "neighbor_solicitation": ${ndp_ns:-0},
      "neighbor_advertisement": ${ndp_na:-0},
      "router_solicitation": ${ndp_rs:-0},
      "router_advertisement": ${ndp_ra:-0},
      "redirect": ${ndp_redirect:-0}
    }
  },
  "tunnels": {
    "vxlan": ${vxlan_count:-0},
    "gtp_u": ${gtp_u_count:-0},
    "gtp_c": ${gtp_c_count:-0},
    "geneve": ${geneve_count:-0},
    "gre": ${gre_count:-0},
    "mpls": ${mpls_count:-0},
    "six_in_four": ${six_in_four_count:-0},
    "four_in_six": ${four_in_six_count:-0},
    "srv6": ${srv6_count:-0}
  },
  "protocols": {
    "sctp": ${sctp_count:-0},
    "pmtud": ${pmtud_count:-0},
    "ipv6_extension_headers": {
      "hop_by_hop": ${ipv6_hbh:-0},
      "routing": ${ipv6_routing:-0},
      "fragment": ${ipv6_frag:-0},
      "esp": ${ipv6_esp:-0},
      "ah": ${ipv6_ah:-0}
    },
    "tcp_options": {
      "mss": ${tcp_mss:-0},
      "wscale": ${tcp_wscale:-0},
      "sack_permitted": ${tcp_sack_perm:-0},
      "out_of_order": ${tcp_out_of_order:-0}
    },
    "tcp_flags": {
      "syn": ${tcp_syn:-0},
      "syn_ack": ${tcp_synack:-0},
      "rst": ${tcp_rst:-0},
      "fin": ${tcp_fin:-0},
      "psh": ${tcp_psh:-0},
      "urg": ${tcp_urg:-0},
      "zero_window": ${tcp_zero_win:-0},
      "retransmission": ${tcp_retrans:-0}
    }
  },
  "infrastructure_frames": {
    "lldp": ${lldp_count:-0},
    "cdp": ${cdp_count:-0},
    "stp": ${stp_count:-0},
    "vrrp": ${vrrp_count:-0},
    "hsrp": ${hsrp_count:-0},
    "isis": ${isis_count:-0},
    "bfd": ${bfd_count:-0}
  },
  "security_frames": {
    "eapol": ${eapol_count:-0},
    "dhcp": ${dhcp_count:-0}
  },
  "dpi": {
    "snmp_community_strings": $(to_jarr "$snmp_strings"),
    "ospf_routers": $(to_jarr "$ospf_routers"),
    "bgp_asns": $(to_jarr "$bgp_asns"),
    "dhcp_hostnames": $(to_jarr "$dhcp_hosts"),
    "dns_queries": $(to_jarr "$dns_names"),
    "tls_sni": $(to_jarr "$tls_sni")
  },
  "top_talkers": $(cat "${TEMP_DIR}/top_talkers.json" 2>/dev/null || echo '{"ipv4":[],"ipv6":[],"flows":[]}')$(if [[ -f "${TEMP_DIR}/active_audit.json" ]]; then echo "  , \"active_audit\": "; cat "${TEMP_DIR}/active_audit.json"; fi)
}
EOF
    fi
    cleanup_analyzer
    trap - EXIT INT TERM HUP
}
