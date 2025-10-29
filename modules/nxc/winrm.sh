#!/bin/bash
#
# NXC WinRM Module
# Windows Remote Management Operations
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

# Handle WinRM operations
handle_winrm() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    subchoice=$(show_menu "winrm" "Select WinRM Operation: ")

    case "$subchoice" in
        "Test Authentication")
            run_command "nxc winrm $target $auth"
            ;;
        "Execute Command")
            read -p "Command: " cmd
            run_command "nxc winrm $target $auth -x '$cmd'"
            ;;
        "Execute PowerShell")
            read -p "PowerShell command: " ps
            run_command "nxc winrm $target $auth -X '$ps'"
            ;;
        "Get System Info")
            run_command "nxc winrm $target $auth -x systeminfo"
            ;;
        "Check Privileges")
            run_command "nxc winrm $target $auth -x 'whoami /priv'"
            ;;
        "List Local Users")
            run_command "nxc winrm $target $auth -x 'net user'"
            ;;
        "Network Configuration")
            run_command "nxc winrm $target $auth -x 'ipconfig /all'"
            ;;
    esac
}
