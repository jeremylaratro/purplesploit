#!/bin/bash
#
# Impacket SMB Client Module
# Contains interactive SMB client operations
#
# This module provides functions for interacting with SMB shares using
# Impacket's smbclient tool. Capabilities include:
#   - Interactive SMB browsing
#   - Share listing
#   - File upload and download
#   - Command execution via SMB
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
# - RUN_MODE: Execution mode (single/all)
#
# And these functions to be available:
# - get_target_for_command(): Gets target(s) based on run mode
# - show_menu(): Displays menu using fzf
# - run_command(): Executes command with preview and confirmation

# Handle SMB client operations
handle_smbclient() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_smbclient" "Select SMB Client Operation: ")

    if [[ "$RUN_MODE" == "all" ]]; then
        echo -e "${YELLOW}SMB Client only works with single target.${NC}"
        sleep 2
        return
    fi

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Interactive SMB Client")
            echo -e "${CYAN}Opening interactive SMB client${NC}"
            echo -e "${CYAN}Commands: shares, use <share>, ls, cd, get, put, etc.${NC}"
            read -p "Press Enter to continue..."
            run_command "impacket-smbclient $impacket_auth"
            ;;
        "List Shares")
            run_command "impacket-smbclient $impacket_auth -list"
            ;;
        "Download File")
            read -p "Share name: " share
            read -p "Remote file path: " remote_file
            read -p "Local path to save: " local_path
            echo -e "${CYAN}Opening SMB client, then: use $share; get $remote_file $local_path${NC}"
            run_command "impacket-smbclient $impacket_auth"
            ;;
        "Upload File")
            read -p "Share name: " share
            read -p "Local file to upload: " local_file
            read -p "Remote path: " remote_path
            echo -e "${CYAN}Opening SMB client, then: use $share; put $local_file $remote_path${NC}"
            run_command "impacket-smbclient $impacket_auth"
            ;;
        "Execute Command via SMB")
            read -p "Command to execute: " cmd
            run_command "impacket-smbclient $impacket_auth -exec '$cmd'"
            ;;
    esac
}
