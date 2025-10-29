#!/bin/bash
#
# Impacket Services Module
# Contains Windows service management operations
#
# This module provides functions for managing Windows services remotely
# using Impacket's services tool. Capabilities include:
#   - Listing services
#   - Starting and stopping services
#   - Creating new services
#   - Deleting services
#   - Querying service status
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

# Handle Windows service management operations
handle_services() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_services" "Select Service Operation: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "List Services")
            run_command "impacket-services $impacket_auth list"
            ;;
        "Start Service")
            read -p "Service name: " svc
            run_command "impacket-services $impacket_auth start -name '$svc'"
            ;;
        "Stop Service")
            read -p "Service name: " svc
            run_command "impacket-services $impacket_auth stop -name '$svc'"
            ;;
        "Create Service")
            read -p "Service name: " svc
            read -p "Binary path: " binpath
            run_command "impacket-services $impacket_auth create -name '$svc' -display '$svc' -path '$binpath'"
            ;;
        "Delete Service")
            read -p "Service name: " svc
            run_command "impacket-services $impacket_auth delete -name '$svc'"
            ;;
        "Query Service Status")
            read -p "Service name: " svc
            run_command "impacket-services $impacket_auth status -name '$svc'"
            ;;
    esac
}
