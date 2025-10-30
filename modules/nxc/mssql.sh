#!/bin/bash
#
# NXC MSSQL Module
# Microsoft SQL Server Operations
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

# Handle MSSQL operations
handle_mssql() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1

    # Get port argument if using non-standard port
    port_arg=$(get_port_arg "$target" "mssql")

    subchoice=$(show_menu "mssql" "Select MSSQL Operation: ")

    case "$subchoice" in
        "Test Authentication")
            run_command "nxc mssql $target $auth $port_arg"
            ;;
        "Get MSSQL Version")
            run_command "nxc mssql $target $auth $port_arg -q 'SELECT @@version'"
            ;;
        "List Databases")
            run_command "nxc mssql $target $auth $port_arg -q 'SELECT name FROM sys.databases'"
            ;;
        "List Tables")
            read -p "Database name: " db
            run_command "nxc mssql $target $auth $port_arg -q 'SELECT * FROM ${db}.INFORMATION_SCHEMA.TABLES'"
            ;;
        "Check Privileges")
            run_command "nxc mssql $target $auth $port_arg -M mssql_priv"
            ;;
        "Execute Command (xp_cmdshell)")
            read -p "Command: " cmd
            run_command "nxc mssql $target $auth $port_arg -x '$cmd'"
            ;;
        "Enable xp_cmdshell")
            run_command "nxc mssql $target $auth $port_arg -q \"EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\""
            ;;
    esac
}
