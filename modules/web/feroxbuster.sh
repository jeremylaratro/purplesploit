#!/bin/bash
#
# Feroxbuster Module - Directory and File Discovery
# Part of PurpleSploit Web Testing Framework
#
# This module handles all feroxbuster-related operations including:
# - Basic directory scanning with thorough mode
# - Deep scanning with custom file extensions
# - Custom wordlist scanning
# - Burp Suite integration for testing
# - API endpoint discovery
# - Backup file discovery
# - Custom scan configurations
#
# Dependencies:
# - feroxbuster (must be installed)
# - Global variables from plat02.sh (colors, run_command, show_menu, get_web_target_url)
#

handle_feroxbuster() {
    while true; do
        subchoice=$(show_menu "feroxbuster" "Select Feroxbuster Operation: ")
        [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break

        url=$(get_web_target_url)
        if [[ -z "$url" ]]; then
            echo -e "${RED}No URL provided!${NC}"
            sleep 2
            continue
        fi

        case "$subchoice" in
            "Basic Directory Scan")
                echo -e "${CYAN}Running basic scan with thorough mode${NC}"
                run_command "feroxbuster -u '$url' --thorough --methods GET,POST"
                ;;
            "Deep Scan with Extensions")
                read -p "Extensions (e.g., php,html,js,txt) [default: php,html,js,txt,asp,aspx,jsp]: " exts
                [[ -z "$exts" ]] && exts="php,html,js,txt,asp,aspx,jsp"
                echo -e "${CYAN}Deep scan with extensions: $exts${NC}"
                run_command "feroxbuster -u '$url' --thorough --methods GET,POST -x '$exts' -t 50"
                ;;
            "Custom Wordlist Scan")
                read -p "Wordlist path: " wordlist
                if [[ ! -f "$wordlist" ]]; then
                    echo -e "${RED}Wordlist not found!${NC}"
                    sleep 2
                    continue
                fi
                run_command "feroxbuster -u '$url' --thorough --methods GET,POST -w '$wordlist'"
                ;;
            "Burp Integration Scan")
                read -p "Burp proxy [default: http://127.0.0.1:8080]: " proxy
                [[ -z "$proxy" ]] && proxy="http://127.0.0.1:8080"
                echo -e "${CYAN}Scanning with Burp integration${NC}"
                echo -e "${YELLOW}Make sure Burp is running and listening!${NC}"
                run_command "feroxbuster -u '$url' --thorough --methods GET,POST --proxy '$proxy'"
                ;;
            "API Discovery")
                echo -e "${CYAN}Scanning for API endpoints${NC}"
                run_command "feroxbuster -u '$url' --thorough --methods GET,POST,PUT,DELETE,PATCH -x json,xml"
                ;;
            "Backup File Discovery")
                echo -e "${CYAN}Scanning for backup files${NC}"
                run_command "feroxbuster -u '$url' --thorough -x bak,old,backup,zip,tar,gz,sql,db,config"
                ;;
            "Custom Scan")
                read -p "Additional feroxbuster flags: " custom_flags
                run_command "feroxbuster -u '$url' --thorough --methods GET,POST $custom_flags"
                ;;
        esac
    done
}

# Export function for use in main script
export -f handle_feroxbuster
