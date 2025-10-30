#!/bin/bash
#
# NXC SSH Module
# Secure Shell Operations
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

# Handle SSH operations
handle_ssh() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    # Get port argument if using non-standard port
    port_arg=$(get_port_arg "$target" "ssh")

    subchoice=$(show_menu "ssh" "Select SSH Operation: ")

    case "$subchoice" in
        "Test Authentication")
            run_command "nxc ssh $target $auth $port_arg"
            ;;
        "Execute Command")
            read -p "Command: " cmd
            run_command "nxc ssh $target $auth $port_arg -x '$cmd'"
            ;;
        "Get System Info")
            run_command "nxc ssh $target $auth $port_arg -x 'uname -a'"
            ;;
        "Check Sudo Privileges")
            run_command "nxc ssh $target $auth $port_arg -x 'sudo -l'"
            ;;
    esac
}
