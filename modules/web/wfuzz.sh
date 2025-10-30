#!/bin/bash
#
# WFUZZ Module - Web Fuzzing Operations
# Part of PurpleSploit Web Testing Framework
#
# This module handles all wfuzz-related operations including:
# - VHOST fuzzing for virtual host discovery
# - Parameter fuzzing (GET and POST methods)
# - DNS subdomain enumeration
# - Directory and file fuzzing
# - HTTP header fuzzing
# - Custom fuzzing configurations
#
# Dependencies:
# - wfuzz (must be installed)
# - Global variables from plat02.sh (colors, run_command, show_menu)
#

handle_wfuzz() {
    while true; do
        subchoice=$(show_menu "wfuzz" "Select WFUZZ Operation: ")
        [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break

        case "$subchoice" in
            "VHOST Fuzzing")
                read -p "Target IP: " target_ip
                read -p "Base domain (e.g., example.com): " domain
                read -p "Wordlist [default: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: " wordlist
                [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

                if [[ ! -f "$wordlist" ]]; then
                    echo -e "${RED}Wordlist not found!${NC}"
                    sleep 2
                    continue
                fi

                echo -e "${CYAN}Fuzzing VHOSTs for $domain on $target_ip${NC}"
                run_command "wfuzz -c -w '$wordlist' -H 'Host: FUZZ.$domain' --hc 404 --hw 0 http://$target_ip/"
                ;;
            "Parameter Fuzzing (GET)")
                read -p "Base URL (with FUZZ, e.g., http://example.com/page?FUZZ=test): " url
                read -p "Wordlist [default: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt]: " wordlist
                [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

                echo -e "${CYAN}Fuzzing GET parameters${NC}"
                run_command "wfuzz -c -w '$wordlist' --hc 404 '$url'"
                ;;
            "Parameter Fuzzing (POST)")
                read -p "Target URL: " url
                read -p "POST data (use FUZZ, e.g., username=admin&FUZZ=test): " postdata
                read -p "Wordlist [default: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt]: " wordlist
                [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

                echo -e "${CYAN}Fuzzing POST parameters${NC}"
                run_command "wfuzz -c -w '$wordlist' --hc 404 -d '$postdata' '$url'"
                ;;
            "DNS Subdomain Fuzzing")
                read -p "Domain (e.g., example.com): " domain
                read -p "Wordlist [default: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: " wordlist
                [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

                echo -e "${CYAN}Fuzzing DNS subdomains for $domain${NC}"
                run_command "wfuzz -c -w '$wordlist' -Z --hc 404 -H 'Host: FUZZ.$domain' http://$domain/"
                ;;
            "Directory Fuzzing")
                read -p "Base URL: " url
                read -p "Wordlist [default: /usr/share/seclists/Discovery/Web-Content/common.txt]: " wordlist
                [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"

                echo -e "${CYAN}Fuzzing directories${NC}"
                run_command "wfuzz -c -w '$wordlist' --hc 404 '$url/FUZZ'"
                ;;
            "Header Fuzzing")
                read -p "Target URL: " url
                read -p "Header name (e.g., X-Forwarded-For): " header
                read -p "Wordlist for values: " wordlist

                echo -e "${CYAN}Fuzzing HTTP headers${NC}"
                run_command "wfuzz -c -w '$wordlist' --hc 404 -H '$header: FUZZ' '$url'"
                ;;
            "Custom Fuzzing")
                read -p "Full wfuzz command (without 'wfuzz'): " custom_cmd
                run_command "wfuzz $custom_cmd"
                ;;
        esac
    done
}

# Export function for use in main script
export -f handle_wfuzz
