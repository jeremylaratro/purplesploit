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
        "Nmap Port Scan (Auto Web Detection)")
            # Get scan parameters
            echo -e "${CYAN}Nmap Port Scan with Auto Web Detection${NC}"
            echo ""
            read -p "Port range [default: 1-10000]: " ports
            [[ -z "$ports" ]] && ports="1-10000"

            read -p "Scan name [default: scan_$(date +%Y%m%d_%H%M%S)]: " scan_name
            [[ -z "$scan_name" ]] && scan_name="scan_$(date +%Y%m%d_%H%M%S)"

            output_file="$NMAP_RESULTS_DIR/${scan_name}.xml"

            # Run nmap with service detection
            cmd="nmap -sV -p $ports -oX '$output_file' $target"
            run_command "$cmd"

            # Parse results and auto-detect web servers
            if [[ -f "$output_file" ]]; then
                echo ""
                echo -e "${GREEN}Scan complete! Parsing results...${NC}"
                echo ""
                parse_nmap_results "$output_file" "--detailed"
                echo ""
                echo -e "${YELLOW}Auto-detecting web servers and adding to web targets...${NC}"
                import_web_targets_from_nmap "$output_file"
                echo ""
                read -p "Press Enter to continue..."
            fi
            ;;
        "Nmap Service Detection")
            echo -e "${CYAN}Nmap Service Detection (Top 1000 Ports)${NC}"
            echo ""
            read -p "Scan name [default: svc_scan_$(date +%Y%m%d_%H%M%S)]: " scan_name
            [[ -z "$scan_name" ]] && scan_name="svc_scan_$(date +%Y%m%d_%H%M%S)"

            output_file="$NMAP_RESULTS_DIR/${scan_name}.xml"

            # Run nmap with aggressive service detection
            cmd="nmap -sV -sC -O --version-intensity 5 -oX '$output_file' $target"
            run_command "$cmd"

            # Parse results and auto-detect web servers
            if [[ -f "$output_file" ]]; then
                echo ""
                echo -e "${GREEN}Scan complete! Parsing results...${NC}"
                echo ""
                parse_nmap_results "$output_file" "--detailed"
                echo ""
                echo -e "${YELLOW}Auto-import web servers to web targets?${NC}"
                read -p "Continue? (y/n): " confirm
                if [[ "$confirm" == "y" ]]; then
                    import_web_targets_from_nmap "$output_file"
                fi
                echo ""
                read -p "Press Enter to continue..."
            fi
            ;;
        "Nmap Vulnerability Scan")
            echo -e "${CYAN}Nmap Vulnerability Scan (NSE Scripts)${NC}"
            echo ""
            read -p "Port range [default: 1-1000]: " ports
            [[ -z "$ports" ]] && ports="1-1000"

            read -p "Scan name [default: vuln_scan_$(date +%Y%m%d_%H%M%S)]: " scan_name
            [[ -z "$scan_name" ]] && scan_name="vuln_scan_$(date +%Y%m%d_%H%M%S)"

            output_file="$NMAP_RESULTS_DIR/${scan_name}.xml"

            # Run nmap with vuln scripts
            cmd="nmap -sV --script vuln -p $ports -oX '$output_file' $target"
            run_command "$cmd"

            # Parse results
            if [[ -f "$output_file" ]]; then
                echo ""
                echo -e "${GREEN}Scan complete! Parsing results...${NC}"
                echo ""
                parse_nmap_results "$output_file" "--detailed"
                echo ""
                echo -e "${YELLOW}Auto-import web servers to web targets?${NC}"
                read -p "Continue? (y/n): " confirm
                if [[ "$confirm" == "y" ]]; then
                    import_web_targets_from_nmap "$output_file"
                fi
                echo ""
                read -p "Press Enter to continue..."
            fi
            ;;
        "View Nmap Results")
            view_nmap_results
            ;;
    esac
}
