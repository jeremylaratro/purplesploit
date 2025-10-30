#!/bin/bash
#
# Impacket Execution Module
# Contains remote execution tools: PSExec, WMIExec, SMBExec, ATExec, DcomExec
#
# This module provides functions for remote command execution on Windows systems
# using various Impacket tools. Each tool uses different techniques:
#   - PSExec: Service-based execution
#   - WMIExec: WMI-based execution
#   - SMBExec: SMB-based execution
#   - ATExec: Scheduled task execution
#   - DcomExec: DCOM-based execution
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

# Handle PSExec operations
handle_psexec() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_psexec" "Select PSExec Operation: ")

    # Build auth for impacket (different format)
    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Execute Command")
            read -p "Command to execute: " cmd
            run_command "impacket-psexec $impacket_auth '$cmd'"
            ;;
        "Interactive Shell")
            echo -e "${CYAN}This will drop you into an interactive shell.${NC}"
            echo -e "${CYAN}Type 'exit' to return to the TUI.${NC}"
            read -p "Press Enter to continue..."
            run_command "impacket-psexec $impacket_auth"
            ;;
        "Execute as SYSTEM")
            read -p "Command to execute: " cmd
            run_command "impacket-psexec $impacket_auth -system '$cmd'"
            ;;
        "Upload and Execute")
            read -p "Local file to upload: " local_file
            read -p "Remote path (e.g., C:\\\\Windows\\\\Temp\\\\file.exe): " remote_path
            run_command "impacket-psexec $impacket_auth -file '$local_file' -path '$remote_path'"
            ;;
        "Execute with Specific Service Name")
            read -p "Service name: " service
            read -p "Command to execute: " cmd
            run_command "impacket-psexec $impacket_auth -service-name '$service' '$cmd'"
            ;;
    esac
}

# Handle WMIExec operations
handle_wmiexec() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_wmiexec" "Select WMIExec Operation: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Execute Command")
            read -p "Command to execute: " cmd
            run_command "impacket-wmiexec $impacket_auth '$cmd'"
            ;;
        "Interactive Shell")
            echo -e "${CYAN}This will drop you into an interactive shell.${NC}"
            echo -e "${CYAN}Type 'exit' to return to the TUI.${NC}"
            read -p "Press Enter to continue..."
            run_command "impacket-wmiexec $impacket_auth"
            ;;
        "Execute with Output")
            read -p "Command to execute: " cmd
            run_command "impacket-wmiexec $impacket_auth -codec utf-8 '$cmd'"
            ;;
        "Silent Execution (No Output)")
            read -p "Command to execute: " cmd
            run_command "impacket-wmiexec $impacket_auth -nooutput '$cmd'"
            ;;
    esac
}

# Handle SMBExec operations
handle_smbexec() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_smbexec" "Select SMBExec Operation: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Execute Command")
            read -p "Command to execute: " cmd
            run_command "impacket-smbexec $impacket_auth '$cmd'"
            ;;
        "Interactive Shell")
            echo -e "${CYAN}This will drop you into an interactive shell.${NC}"
            read -p "Press Enter to continue..."
            run_command "impacket-smbexec $impacket_auth"
            ;;
        "Execute with Custom Share")
            read -p "Share name (e.g., C$): " share
            read -p "Command to execute: " cmd
            run_command "impacket-smbexec $impacket_auth -share '$share' '$cmd'"
            ;;
        "Execute without Deleting")
            read -p "Command to execute: " cmd
            run_command "impacket-smbexec $impacket_auth -mode SERVER '$cmd'"
            ;;
    esac
}

# Handle ATExec operations
handle_atexec() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_atexec" "Select ATExec Operation: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Execute Command (Scheduled Task)")
            read -p "Command to execute: " cmd
            run_command "impacket-atexec $impacket_auth '$cmd'"
            ;;
        "Execute with Custom Task Name")
            read -p "Task name: " taskname
            read -p "Command to execute: " cmd
            run_command "impacket-atexec $impacket_auth -task-name '$taskname' '$cmd'"
            ;;
        "Execute and Wait for Output")
            read -p "Command to execute: " cmd
            echo -e "${CYAN}Note: ATExec may take time to return output${NC}"
            run_command "impacket-atexec $impacket_auth '$cmd'"
            ;;
    esac
}

# Handle DcomExec operations
handle_dcomexec() {
    target=$(get_target_for_command) || return
    subchoice=$(show_menu "impacket_dcomexec" "Select DcomExec Method: ")

    if [[ -n "$HASH" ]]; then
        impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
    else
        impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
    fi

    case "$subchoice" in
        "Execute Command (ShellWindows)")
            read -p "Command to execute: " cmd
            run_command "impacket-dcomexec $impacket_auth -object ShellWindows '$cmd'"
            ;;
        "Execute Command (ShellBrowserWindow)")
            read -p "Command to execute: " cmd
            run_command "impacket-dcomexec $impacket_auth -object ShellBrowserWindow '$cmd'"
            ;;
        "Execute Command (MMC20)")
            read -p "Command to execute: " cmd
            run_command "impacket-dcomexec $impacket_auth -object MMC20 '$cmd'"
            ;;
    esac
}
