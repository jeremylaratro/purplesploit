#!/bin/bash
#
# HTTPX Module - HTTP Probing and Discovery
# Part of PurpleSploit Web Testing Framework
#
# This module handles all httpx-related operations including:
# - Single URL probing with detailed information
# - Bulk URL probing from file lists
# - HTTP service discovery from nmap results
# - Page title extraction
# - Technology detection (web frameworks, CMS, etc.)
# - Full discovery scans with JSON output
# - Website screenshot capture
# - Custom probe configurations
#
# Dependencies:
# - httpx (must be installed)
# - Chrome/Chromium (for screenshot functionality)
# - Global variables from plat02.sh (colors, run_command, show_menu)
#

handle_httpx() {
    while true; do
        subchoice=$(show_menu "httpx" "Select HTTPX Operation: ")
        [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break

        case "$subchoice" in
            "Probe Single URL")
                read -p "URL to probe: " url
                echo -e "${CYAN}Probing single URL${NC}"
                run_command "httpx -u '$url' -status-code -title -tech-detect -follow-redirects"
                ;;
            "Probe from URL List")
                read -p "File containing URLs: " urlfile
                if [[ ! -f "$urlfile" ]]; then
                    echo -e "${RED}File not found!${NC}"
                    sleep 2
                    continue
                fi
                echo -e "${CYAN}Probing URLs from file${NC}"
                run_command "httpx -l '$urlfile' -status-code -title -tech-detect"
                ;;
            "Probe from Nmap IPs")
                read -p "File with IP addresses (one per line): " ipfile
                if [[ ! -f "$ipfile" ]]; then
                    echo -e "${RED}File not found!${NC}"
                    sleep 2
                    continue
                fi
                read -p "Ports to check [default: 80,443,8000,8080,8443]: " ports
                [[ -z "$ports" ]] && ports="80,443,8000,8080,8443"

                echo -e "${CYAN}Discovering web servers from nmap IPs${NC}"
                run_command "cat '$ipfile' | httpx -ports '$ports' -status-code -title -tech-detect -follow-redirects"
                ;;
            "Extract Page Titles")
                read -p "URL or file with URLs: " input
                if [[ -f "$input" ]]; then
                    echo -e "${CYAN}Extracting titles from URL file${NC}"
                    run_command "httpx -l '$input' -title -silent"
                else
                    echo -e "${CYAN}Extracting title from single URL${NC}"
                    run_command "httpx -u '$input' -title"
                fi
                ;;
            "Technology Detection")
                read -p "URL or file with URLs: " input
                if [[ -f "$input" ]]; then
                    echo -e "${CYAN}Detecting technologies from URL file${NC}"
                    run_command "httpx -l '$input' -tech-detect -status-code"
                else
                    echo -e "${CYAN}Detecting technologies from single URL${NC}"
                    run_command "httpx -u '$input' -tech-detect -status-code"
                fi
                ;;
            "Full Discovery Scan")
                read -p "File with URLs/IPs: " input
                read -p "Output file [default: httpx-results.txt]: " output
                [[ -z "$output" ]] && output="httpx-results.txt"

                echo -e "${CYAN}Running full discovery scan${NC}"
                echo -e "${GREEN}Results will be saved to: $output${NC}"
                run_command "httpx -l '$input' -status-code -title -tech-detect -web-server -content-type -content-length -follow-redirects -json -o '$output'"
                ;;
            "Screenshot Websites")
                read -p "URL or file with URLs: " input
                read -p "Screenshot directory [default: ./screenshots]: " outdir
                [[ -z "$outdir" ]] && outdir="./screenshots"

                echo -e "${CYAN}Taking screenshots${NC}"
                echo -e "${YELLOW}Requires Chrome/Chromium to be installed${NC}"

                if [[ -f "$input" ]]; then
                    run_command "httpx -l '$input' -screenshot -screenshot-path '$outdir'"
                else
                    run_command "httpx -u '$input' -screenshot -screenshot-path '$outdir'"
                fi
                ;;
            "Custom Probe")
                read -p "Full httpx command (without 'httpx'): " custom_cmd
                run_command "httpx $custom_cmd"
                ;;
        esac
    done
}

# Export function for use in main script
export -f handle_httpx
