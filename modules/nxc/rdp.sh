#!/bin/bash
#
# NXC RDP Module
# Remote Desktop Protocol Operations
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

# Handle RDP operations
handle_rdp() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    # Get port argument if using non-standard port
    port_arg=$(get_port_arg "$target" "rdp")

    subchoice=$(show_menu "rdp" "Select RDP Operation: ")

    case "$subchoice" in
        "Test Authentication")
            run_command "nxc rdp $target $auth $port_arg"
            ;;
        "RDP Scanner")
            run_command "nxc rdp $target $auth $port_arg -M rdp-scanner"
            ;;
        "Take Screenshot")
            run_command "nxc rdp $target $auth $port_arg -M rdp-screenshot"
            ;;
    esac
}
