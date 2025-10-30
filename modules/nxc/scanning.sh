#!/bin/bash
#
# NXC Scanning Module
# Network Scanning and Discovery Operations
#
# This module requires the following functions from main script:
# - build_auth()
# - get_target_for_command()
# - run_command()
# - show_menu()
#
# Required global variables:
# - DOMAIN, USERNAME, PASSWORD, HASH, TARGET
# - RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, NC (colors)
#

# Handle network scanning operations
handle_scanning() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    subchoice=$(show_menu "scanning" "Select Scan Type: ")

    case "$subchoice" in
        "Scan Current Target")
            run_command "nxc smb $target $auth"
            ;;
        "Password Spray")
            read -p "User file: " users
            read -p "Password: " pass
            run_command "nxc smb $target -u $users -p '$pass' --no-bruteforce --continue-on-success"
            ;;
        "Find Admin Access")
            run_command "nxc smb $target $auth -x whoami"
            ;;
        "Multi-Protocol Scan")
            run_command "nxc smb $target $auth && nxc winrm $target $auth && nxc mssql $target $auth"
            ;;
        "Nmap TCP Scan (Service Detection)")
            # Get scan parameters
            echo -e "${CYAN}Nmap TCP Scan with Service Detection${NC}"
            echo ""
            read -p "Scan name [default: tcp_scan_$(date +%Y%m%d_%H%M%S)]: " scan_name
            [[ -z "$scan_name" ]] && scan_name="tcp_scan_$(date +%Y%m%d_%H%M%S)"

            output_file="$NMAP_RESULTS_DIR/${scan_name}.xml"

            # Run nmap with full TCP scan and service detection
            cmd="nmap $target -p- -sV -sC --min-rate 3950 --max-rtt-timeout 4.2 -oX '$output_file'"
            run_command "$cmd"

            # Parse results and auto-detect services
            if [[ -f "$output_file" ]]; then
                echo ""
                echo -e "${GREEN}Scan complete! Parsing results and detecting services...${NC}"
                echo ""
                parse_nmap_results "$output_file" "--detailed"
                echo ""
                echo -e "${YELLOW}Auto-detecting services (web, SMB, LDAP, SSH, RDP, WinRM, MSSQL)...${NC}"
                import_services_from_nmap "$output_file"
                echo ""
                read -p "Press Enter to continue..."
            fi
            ;;
        "Nmap UDP Scan")
            echo -e "${CYAN}Nmap UDP Scan${NC}"
            echo ""
            read -p "Port range [default: top 100 UDP ports]: " ports
            if [[ -z "$ports" ]]; then
                port_arg="--top-ports 100"
            else
                port_arg="-p $ports"
            fi

            read -p "Scan name [default: udp_scan_$(date +%Y%m%d_%H%M%S)]: " scan_name
            [[ -z "$scan_name" ]] && scan_name="udp_scan_$(date +%Y%m%d_%H%M%S)"

            output_file="$NMAP_RESULTS_DIR/${scan_name}.xml"

            # Run nmap UDP scan
            cmd="nmap $target -sU $port_arg -sV --min-rate 3950 --max-rtt-timeout 4.2 -oX '$output_file'"
            run_command "$cmd"

            # Parse results
            if [[ -f "$output_file" ]]; then
                echo ""
                echo -e "${GREEN}Scan complete! Parsing results...${NC}"
                echo ""
                parse_nmap_results "$output_file" "--detailed"
                echo ""
                echo -e "${YELLOW}Auto-detecting services...${NC}"
                import_services_from_nmap "$output_file"
                echo ""
                read -p "Press Enter to continue..."
            fi
            ;;
        "View Nmap Results")
            view_nmap_results
            ;;
    esac
}
