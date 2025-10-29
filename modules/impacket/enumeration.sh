#!/bin/bash
#
# Impacket Enumeration Module
# Contains Active Directory and network enumeration tools
#
# This module provides functions for enumerating Windows and Active Directory
# environments using various Impacket tools:
#   - GetADUsers: Enumerate Active Directory user accounts
#   - lookupsid: SID enumeration via RPC
#   - rpcdump: RPC endpoint enumeration
#   - samrdump: SAM database enumeration
#   - smbclient: SMB share listing
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

# Handle Impacket enumeration operations
handle_enum() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_enum" "Select Enumeration Tool: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Enumerate Users (GetADUsers)")
            echo -e "${CYAN}Enumerating Active Directory users${NC}"
            run_command "impacket-GetADUsers $impacket_auth -all"
            ;;
        "SID Lookup (lookupsid)")
            echo -e "${CYAN}Looking up SIDs via RPC${NC}"
            run_command "impacket-lookupsid $impacket_auth"
            ;;
        "RPC Endpoints (rpcdump)")
            echo -e "${CYAN}Dumping RPC endpoints${NC}"
            run_command "impacket-rpcdump $impacket_auth"
            ;;
        "SAM Dump (samrdump)")
            echo -e "${CYAN}Dumping SAM via SAMR${NC}"
            run_command "impacket-samrdump $impacket_auth"
            ;;
        "List Shares (smbclient)")
            echo -e "${CYAN}Listing SMB shares${NC}"
            run_command "impacket-smbclient $impacket_auth -list"
            ;;
        "Get Domain Info")
            echo -e "${CYAN}Getting domain information${NC}"
            run_command "impacket-GetADUsers $impacket_auth -all -dc-ip $target"
            ;;
    esac
}
