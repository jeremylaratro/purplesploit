#!/bin/bash
#
# PurpleSploit - Modular Penetration Testing Framework
# Main Entry Point
#
# A modular TUI-based penetration testing framework that provides
# an organized interface for common pentesting tools including:
#   - Web application testing (feroxbuster, wfuzz, sqlmap, httpx)
#   - Network exploitation (NetExec/NXC for SMB, LDAP, WinRM, etc.)
#   - Impacket suite (PSExec, WMIExec, Kerberos attacks, etc.)
#
# Architecture:
#   core/       - Core functionality (config, database, UI)
#   lib/        - Library functions (credentials, targets, utilities)
#   modules/    - Tool modules (web, nxc, impacket)
#
# Usage:
#   ./purplesploit.sh
#
# Author: Purple Team
# License: MIT
#

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================================================
# Source Core Modules
# ============================================================================
echo "Loading PurpleSploit modules..."

# Core functionality
source "${SCRIPT_DIR}/core/config.sh"
source "${SCRIPT_DIR}/core/database.sh"
source "${SCRIPT_DIR}/core/ui.sh"

# Library functions
source "${SCRIPT_DIR}/lib/credentials.sh"
source "${SCRIPT_DIR}/lib/targets.sh"
source "${SCRIPT_DIR}/lib/web_targets.sh"
source "${SCRIPT_DIR}/lib/ad_targets.sh"
source "${SCRIPT_DIR}/lib/nmap_results.sh"
source "${SCRIPT_DIR}/lib/database_management.sh"
source "${SCRIPT_DIR}/lib/utils.sh"

# ============================================================================
# Source Tool Modules
# ============================================================================

# Web testing modules
source "${SCRIPT_DIR}/modules/web/feroxbuster.sh"
source "${SCRIPT_DIR}/modules/web/wfuzz.sh"
source "${SCRIPT_DIR}/modules/web/sqlmap.sh"
source "${SCRIPT_DIR}/modules/web/httpx.sh"

# NXC (NetExec) modules
source "${SCRIPT_DIR}/modules/nxc/smb.sh"
source "${SCRIPT_DIR}/modules/nxc/ldap.sh"
source "${SCRIPT_DIR}/modules/nxc/winrm.sh"
source "${SCRIPT_DIR}/modules/nxc/mssql.sh"
source "${SCRIPT_DIR}/modules/nxc/rdp.sh"
source "${SCRIPT_DIR}/modules/nxc/ssh.sh"
source "${SCRIPT_DIR}/modules/nxc/scanning.sh"

# Impacket modules
source "${SCRIPT_DIR}/modules/impacket/execution.sh"
source "${SCRIPT_DIR}/modules/impacket/credentials.sh"
source "${SCRIPT_DIR}/modules/impacket/kerberos.sh"
source "${SCRIPT_DIR}/modules/impacket/enumeration.sh"
source "${SCRIPT_DIR}/modules/impacket/smbclient.sh"
source "${SCRIPT_DIR}/modules/impacket/services.sh"
source "${SCRIPT_DIR}/modules/impacket/registry.sh"

# ============================================================================
# Main Menu Function
# ============================================================================
main_menu() {
    while true; do
        clear

        # Capture both key press and selection from fzf --expect
        local output=$(show_menu "main" "Select Category: ")
        local key=$(echo "$output" | head -n1)
        local choice=$(echo "$output" | tail -n1)

        # Handle keybind shortcuts first
        case "$key" in
            "t")
                manage_targets
                continue
                ;;
            "c")
                manage_credentials
                continue
                ;;
            "w")
                manage_web_targets
                continue
                ;;
            "d")
                manage_ad_targets
                continue
                ;;
            "a")
                select_credentials
                continue
                ;;
            "s")
                select_target
                continue
                ;;
            "m")
                toggle_run_mode
                continue
                ;;
        esac

        # Handle menu selections
        case "$choice" in
            "Exit"|"")
                exit 0
                ;;

            # ===== MANAGEMENT =====
            "Switch Credentials")
                select_credentials
                ;;
            "Switch Target")
                select_target
                ;;
            "Toggle Run Mode (Single/All)")
                toggle_run_mode
                ;;
            "Manage Credentials")
                manage_credentials
                ;;
            "Manage Targets")
                manage_targets
                ;;
            "Manage Web Targets")
                manage_web_targets
                ;;
            "Manage AD Targets")
                manage_ad_targets
                ;;
            "Select AD Target")
                select_ad_target
                ;;
            "Database Management (Reset/Clear)")
                manage_databases
                ;;

            # ===== WEB TESTING TOOLS =====
            "Feroxbuster (Directory/File Discovery)")
                handle_feroxbuster
                ;;
            "WFUZZ (Fuzzing)")
                handle_wfuzz
                ;;
            "SQLMap (SQL Injection)")
                handle_sqlmap
                ;;
            "HTTPX (HTTP Probing)")
                handle_httpx
                ;;

            # ===== NXC SMB OPERATIONS =====
            "SMB Authentication")
                handle_smb_auth
                ;;
            "SMB Enumeration")
                handle_smb_enum
                ;;
            "SMB Shares")
                handle_smb_shares
                ;;
            "SMB Execution")
                handle_smb_exec
                ;;
            "SMB Credentials")
                handle_smb_creds
                ;;
            "SMB Vulnerabilities")
                handle_smb_vulns
                ;;

            # ===== NXC LDAP OPERATIONS =====
            "LDAP Enumeration")
                handle_ldap
                ;;
            "LDAP BloodHound")
                handle_bloodhound
                ;;

            # ===== NXC OTHER PROTOCOLS =====
            "WinRM Operations")
                handle_winrm
                ;;
            "MSSQL Operations")
                handle_mssql
                ;;
            "RDP Operations")
                handle_rdp
                ;;
            "SSH Operations")
                handle_ssh
                ;;
            "Network Scanning")
                handle_scanning
                ;;

            # ===== IMPACKET EXECUTION =====
            "Impacket PSExec")
                handle_psexec
                ;;
            "Impacket WMIExec")
                handle_wmiexec
                ;;
            "Impacket SMBExec")
                handle_smbexec
                ;;
            "Impacket ATExec")
                handle_atexec
                ;;
            "Impacket DcomExec")
                handle_dcomexec
                ;;

            # ===== IMPACKET CREDENTIALS =====
            "Impacket SecretsDump"|"Impacket SAM/LSA/NTDS Dump")
                handle_secretsdump
                ;;

            # ===== IMPACKET KERBEROS =====
            "Kerberoasting (GetUserSPNs)")
                handle_kerberoast
                ;;
            "AS-REP Roasting (GetNPUsers)")
                handle_asreproast
                ;;
            "Golden/Silver Tickets")
                handle_tickets
                ;;

            # ===== IMPACKET OTHER =====
            "Impacket Enumeration")
                handle_enum
                ;;
            "Impacket SMB Client")
                handle_smbclient
                ;;
            "Service Management")
                handle_services
                ;;
            "Registry Operations")
                handle_registry
                ;;

            *)
                echo -e "${RED}Unknown selection: $choice${NC}"
                sleep 2
                ;;
        esac
    done
}

# ============================================================================
# Initialization
# ============================================================================

echo "Initializing databases..."

# Initialize all databases
init_all_databases

# Load default credentials
load_creds "Null Auth"

# Check if targets exist, if not prompt to add one
if [[ $(list_target_names | wc -l) -eq 0 ]]; then
    clear
    echo -e "${YELLOW}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  No targets configured!                   ║${NC}"
    echo -e "${YELLOW}║  Let's add your first target.             ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    add_target
fi

# ============================================================================
# Start Application
# ============================================================================

clear
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                           ║${NC}"
echo -e "${CYAN}║  ${MAGENTA}██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗${CYAN}  ║${NC}"
echo -e "${CYAN}║  ${MAGENTA}██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝${CYAN}  ║${NC}"
echo -e "${CYAN}║  ${MAGENTA}██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗${CYAN}    ║${NC}"
echo -e "${CYAN}║  ${MAGENTA}██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝${CYAN}    ║${NC}"
echo -e "${CYAN}║  ${MAGENTA}██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗${CYAN}  ║${NC}"
echo -e "${CYAN}║  ${MAGENTA}╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝${CYAN}  ║${NC}"
echo -e "${CYAN}║                                                           ║${NC}"
echo -e "${CYAN}║  ${YELLOW}Modular Penetration Testing Framework${CYAN}                ║${NC}"
echo -e "${CYAN}║  ${GREEN}Version 2.0 - Refactored Architecture${CYAN}                ║${NC}"
echo -e "${CYAN}║                                                           ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
sleep 2

# Run main menu
main_menu
