#!/bin/bash
#
# NXC Scanning Module
# Network Scanning and Discovery Operations
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

# Handle network scanning operations
handle_scanning() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    subchoice=$(show_menu "scanning" "Select Scan Type: ")

    case "$subchoice" in
        "Scan Current Target")
            run_command "nxc smb $target $auth"
            ;;
        "Password Spray")
            read -p "User file: " users
            read -p "Password: " pass
            run_command "nxc smb $target -u $users -p '$pass' --no-bruteforce --continue-on-success"
            ;;
        "Find Admin Access")
            run_command "nxc smb $target $auth -x whoami"
            ;;
        "Multi-Protocol Scan")
            run_command "nxc smb $target $auth && nxc winrm $target $auth && nxc mssql $target $auth"
            ;;
    esac
}
