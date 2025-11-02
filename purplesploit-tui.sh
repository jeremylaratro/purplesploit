#!/bin/bash
#
# PurpleSploit Comprehensive TUI
# Combines framework backend with full menu coverage
#

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source framework engine  
source "$SCRIPT_DIR/framework/core/engine.sh"

# Source original lite version components for comprehensive tool coverage
source "$SCRIPT_DIR/core/config.sh" 2>/dev/null || true
source "$SCRIPT_DIR/core/database.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/credentials.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/targets.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/web_targets.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/ad_targets.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/services.sh" 2>/dev/null || true

# Source tool modules from lite version
for module in modules/web/*.sh modules/nxc/*.sh modules/impacket/*.sh; do
    [[ -f "$module" ]] && source "$module" 2>/dev/null || true
done

# Initialize framework
framework_init_silent() {
    declare -gA MODULE_REGISTRY MODULE_METADATA
    declare -ga MODULE_LIST
    
    source "$FRAMEWORK_DIR/core/variable_manager.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/module_registry.sh" 2>/dev/null  
    source "$FRAMEWORK_DIR/core/command_engine.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/workspace_manager.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/fzf_integration.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/credential_manager.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/mythic_integration.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/service_analyzer.sh" 2>/dev/null
    
    var_init
    workspace_init
    command_engine_init  
    credential_init
    service_analyzer_init
    mythic_init
    module_registry_init "$SCRIPT_DIR/modules" >/dev/null 2>&1
    
    # Also init lite version DB
    init_database 2>/dev/null || true
}

# Build comprehensive header
build_header() {
    local workspace=$(workspace_current 2>/dev/null || echo "default")
    local target=$(var_get "RHOST" 2>/dev/null || echo "${TARGET:-<none>}")
    local creds="${CURRENT_CRED_NAME:-<none>}"
    local run_mode="${RUN_MODE:-single}"
    
    echo "WS: $workspace | Target: $target | Creds: $creds | Mode: $run_mode"
}

# Service highlighting helper
highlight_if_active() {
    local target="$1"
    local service="$2"
    local text="$3"
    
    if [[ -n "$target" ]] && service_check "$target" "$service" 2>/dev/null; then
        echo "● $text"
    else
        echo "$text"
    fi
}

# Main menu
show_main_menu() {
    local header=$(build_header)
    local target="${TARGET:-$(var_get RHOST 2>/dev/null)}"
    
    # Build dynamic menu with service highlighting
    local menu="┌ WEB TESTING ───────────────────────────
Feroxbuster (Directory/File Discovery)
WFUZZ (Fuzzing)
SQLMap (SQL Injection)
HTTPX (HTTP Probing)
┌ NETWORK TESTING - NXC ─────────────────
$(highlight_if_active "$target" "smb" "SMB Authentication")
$(highlight_if_active "$target" "smb" "SMB Enumeration")
$(highlight_if_active "$target" "smb" "SMB Shares")
$(highlight_if_active "$target" "smb" "SMB Execution")
$(highlight_if_active "$target" "smb" "SMB Credentials")
$(highlight_if_active "$target" "smb" "SMB Vulnerabilities")
$(highlight_if_active "$target" "ldap" "LDAP Enumeration")
$(highlight_if_active "$target" "ldap" "LDAP BloodHound")
$(highlight_if_active "$target" "winrm" "WinRM Operations")
$(highlight_if_active "$target" "mssql" "MSSQL Operations")
$(highlight_if_active "$target" "rdp" "RDP Operations")
$(highlight_if_active "$target" "ssh" "SSH Operations")
Network Scanning
┌ NETWORK TESTING - IMPACKET ────────────
Impacket PSExec
Impacket WMIExec
Impacket SMBExec
Impacket ATExec
Impacket DcomExec
Impacket SecretsDump
Impacket SAM/LSA/NTDS Dump
Kerberoasting (GetUserSPNs)
AS-REP Roasting (GetNPUsers)
Golden/Silver Tickets
Impacket Enumeration
Impacket SMB Client
Service Management
Registry Operations
┌ SETTINGS ─────────────────────────────
Manage Web Targets
Manage AD Targets
Switch Credentials
Switch Target
Select AD Target
Toggle Run Mode (Single/All)
Manage Credentials
Manage Targets
Database Management (Reset/Clear)
Exit"

    echo "$menu" | fzf \
        --prompt="Select Category: " \
        --height=100% \
        --reverse \
        --header="$header
───────────────────────────────────────
Keybinds: [t]argets [c]reds [w]eb [d] AD [a]uthSwitch [s]TargetSwitch [m]ode
● = Service detected on target" \
        --header-first \
        --expect=t,c,w,d,a,s,m
}

# Initialize and run
main() {
    clear
    show_banner
    echo -e "${CYAN}[*] Initializing comprehensive TUI...${NC}"
    framework_init_silent
    echo -e "${GREEN}[+] Ready! Framework + Lite handlers loaded${NC}"
    sleep 1
    
    while true; do
        clear
        show_banner
        
        local output=$(show_main_menu)
        local key=$(echo "$output" | head -n1)
        local choice=$(echo "$output" | tail -n1)
        
        # Handle keybinds
        case "$key" in
            t) manage_targets; continue ;;
            c) manage_credentials; continue ;;
            w) manage_web_targets; continue ;;
            d) manage_ad_targets; continue ;;
            a) select_credentials; continue ;;
            s) select_target; continue ;;
            m) toggle_run_mode; continue ;;
        esac
        
        # Handle menu selections
        case "$choice" in
            "Exit"|"") exit 0 ;;
            
            # Web Testing
            "Feroxbuster (Directory/File Discovery)") handle_feroxbuster ;;
            "WFUZZ (Fuzzing)") handle_wfuzz ;;
            "SQLMap (SQL Injection)") handle_sqlmap ;;
            "HTTPX (HTTP Probing)") handle_httpx ;;
            
            # NXC
            *"SMB Authentication"*) handle_smb_auth ;;
            *"SMB Enumeration"*) handle_smb_enum ;;
            *"SMB Shares"*) handle_smb_shares ;;
            *"SMB Execution"*) handle_smb_exec ;;
            *"SMB Credentials"*) handle_smb_creds ;;
            *"SMB Vulnerabilities"*) handle_smb_vulns ;;
            *"LDAP Enumeration"*) handle_ldap ;;
            *"LDAP BloodHound"*) handle_bloodhound ;;
            *"WinRM Operations"*) handle_winrm ;;
            *"MSSQL Operations"*) handle_mssql ;;
            *"RDP Operations"*) handle_rdp ;;
            *"SSH Operations"*) handle_ssh ;;
            "Network Scanning") handle_scanning ;;
            
            # Impacket
            "Impacket PSExec") handle_psexec ;;
            "Impacket WMIExec") handle_wmiexec ;;
            "Impacket SMBExec") handle_smbexec ;;
            "Impacket ATExec") handle_atexec ;;
            "Impacket DcomExec") handle_dcomexec ;;
            "Impacket SecretsDump"|"Impacket SAM/LSA/NTDS Dump") handle_secretsdump ;;
            "Kerberoasting (GetUserSPNs)") handle_kerberoast ;;
            "AS-REP Roasting (GetNPUsers)") handle_asreproast ;;
            "Golden/Silver Tickets") handle_tickets ;;
            "Impacket Enumeration") handle_enum ;;
            "Impacket SMB Client") handle_smbclient ;;
            "Service Management") handle_services ;;
            "Registry Operations") handle_registry ;;
            
            # Management
            "Manage Web Targets") manage_web_targets ;;
            "Manage AD Targets") manage_ad_targets ;;
            "Switch Credentials") select_credentials ;;
            "Switch Target") select_target ;;
            "Select AD Target") select_ad_target ;;
            "Toggle Run Mode (Single/All)") toggle_run_mode ;;
            "Manage Credentials") manage_credentials ;;
            "Manage Targets") manage_targets ;;
            "Database Management (Reset/Clear)") manage_databases ;;
        esac
    done
}

main "$@"
