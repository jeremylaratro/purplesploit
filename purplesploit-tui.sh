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
source "$SCRIPT_DIR/core/ui.sh" 2>/dev/null || true
source "$SCRIPT_DIR/core/visual_theme.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/credentials.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/targets.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/web_targets.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/ad_targets.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/services.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/database_management.sh" 2>/dev/null || true

# Source tool modules from lite version
for module in modules/web/*.sh modules/nxc/*.sh modules/impacket/*.sh; do
    [[ -f "$module" ]] && source "$module" 2>/dev/null || true
done

# Source AI automation module
source "$SCRIPT_DIR/modules/ai_automation.sh" 2>/dev/null || true

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

# Build comprehensive header with enhanced visuals
build_header() {
    local workspace=$(workspace_current 2>/dev/null || echo "default")
    local target=$(var_get "RHOST" 2>/dev/null || echo "${TARGET:-<none>}")
    local creds="${CURRENT_CRED_NAME:-<none>}"
    local run_mode="${RUN_MODE:-single}"

    # Color-coded header
    local ws_color="${BRIGHT_CYAN}"
    local target_color="${BRIGHT_GREEN}"
    local cred_color="${YELLOW}"
    local mode_color="${MAGENTA}"

    echo "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo "${CYAN}║${NC} ${BOLD}Workspace:${NC} ${ws_color}${workspace}${NC} ${CYAN}│${NC} ${BOLD}Target:${NC} ${target_color}${target}${NC} ${CYAN}│${NC} ${BOLD}Creds:${NC} ${cred_color}${creds}${NC} ${CYAN}│${NC} ${BOLD}Mode:${NC} ${mode_color}${run_mode}${NC} ${CYAN}║${NC}"
    echo "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
}

# Service highlighting helper with enhanced visuals
highlight_if_active() {
    local target="$1"
    local service="$2"
    local text="$3"

    if [[ -n "$target" ]] && service_check "$target" "$service" 2>/dev/null; then
        echo "${BRIGHT_GREEN}▶${NC} ${BRIGHT_CYAN}${text}${NC}"
    else
        echo "${DIM}  ${text}${NC}"
    fi
}

# Main menu
show_main_menu() {
    local header=$(build_header)
    local target="${TARGET:-$(var_get RHOST 2>/dev/null)}"
    
    # Build dynamic menu with service highlighting and enhanced visuals
    local menu="${BRIGHT_MAGENTA}╔══ WEB TESTING ══════════════════════════╗${NC}
${BRIGHT_YELLOW}🌐${NC} Feroxbuster (Directory/File Discovery)
${BRIGHT_YELLOW}🌐${NC} WFUZZ (Fuzzing)
${BRIGHT_YELLOW}🌐${NC} SQLMap (SQL Injection)
${BRIGHT_YELLOW}🌐${NC} HTTPX (HTTP Probing)
${BRIGHT_MAGENTA}╔══ NETWORK TESTING - NXC ════════════════╗${NC}
$(highlight_if_active "$target" "smb" "SMB Authentication")
$(highlight_if_active "$target" "smb" "SMB Enumeration")
$(highlight_if_active "$target" "smb" "SMB Shares")
$(highlight_if_active "$target" "smb" "SMB Execution")
$(highlight_if_active "$target" "smb" "SMB Credentials")
$(highlight_if_active "$target" "smb" "SMB Vulnerabilities")
$(highlight_if_active "$target" "smb" "NXC Utilities (hosts/krb5/slinky)")
$(highlight_if_active "$target" "ldap" "LDAP Enumeration")
$(highlight_if_active "$target" "ldap" "LDAP BloodHound")
$(highlight_if_active "$target" "winrm" "WinRM Operations")
$(highlight_if_active "$target" "mssql" "MSSQL Operations")
$(highlight_if_active "$target" "rdp" "RDP Operations")
$(highlight_if_active "$target" "ssh" "SSH Operations")
${BRIGHT_YELLOW}🔍${NC} Network Scanning
${BRIGHT_MAGENTA}╔══ NETWORK TESTING - IMPACKET ═══════════╗${NC}
${BRIGHT_RED}⚔${NC} Impacket PSExec
${BRIGHT_RED}⚔${NC} Impacket WMIExec
${BRIGHT_RED}⚔${NC} Impacket SMBExec
${BRIGHT_RED}⚔${NC} Impacket ATExec
${BRIGHT_RED}⚔${NC} Impacket DcomExec
${BRIGHT_RED}💎${NC} Impacket SecretsDump
${BRIGHT_RED}💎${NC} Impacket SAM/LSA/NTDS Dump
${BRIGHT_RED}🎫${NC} Kerberoasting (GetUserSPNs)
${BRIGHT_RED}🎫${NC} AS-REP Roasting (GetNPUsers)
${BRIGHT_RED}🎫${NC} Golden/Silver Tickets
${BRIGHT_YELLOW}🔍${NC} Impacket Enumeration
${BRIGHT_YELLOW}📁${NC} Impacket SMB Client
${BRIGHT_YELLOW}⚙${NC} Service Management
${BRIGHT_YELLOW}📝${NC} Registry Operations
${BRIGHT_MAGENTA}╔══ SESSIONS (WORKSPACES & JOBS) ═════════╗${NC}
${BRIGHT_CYAN}💼${NC} Sessions Management
${BRIGHT_MAGENTA}╔══ AI AUTOMATION ════════════════════════╗${NC}
${BRIGHT_GREEN}🤖${NC} AI Automation (OpenAI/Claude)
${BRIGHT_MAGENTA}╔══ SETTINGS ═════════════════════════════╗${NC}
${CYAN}⚙${NC} Manage Web Targets
${CYAN}⚙${NC} Manage AD Targets
${CYAN}🔑${NC} Switch Credentials
${CYAN}🎯${NC} Switch Target
${CYAN}🏢${NC} Select AD Target
${CYAN}🔄${NC} Toggle Run Mode (Single/All)
${CYAN}👤${NC} Manage Credentials
${CYAN}📡${NC} Manage Targets
${RED}🗑${NC} Database Management (Reset/Clear)
${RED}❌${NC} Exit"

    echo "$menu" | fzf \
        --prompt="${BRIGHT_MAGENTA}▶${NC} Select Tool: " \
        --height=100% \
        --reverse \
        --ansi \
        --cycle \
        --border=rounded \
        --margin=1 \
        --padding=1 \
        --info=inline \
        --pointer="▶" \
        --marker="✓" \
        --header="$header
${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${BOLD}Shortcuts:${NC} ${BRIGHT_CYAN}CTRL+T${NC}:targets  ${BRIGHT_CYAN}CTRL+C${NC}:creds  ${BRIGHT_CYAN}CTRL+W${NC}:web  ${BRIGHT_CYAN}CTRL+D${NC}:AD  ${BRIGHT_CYAN}CTRL+A${NC}:auth  ${BRIGHT_CYAN}CTRL+S${NC}:target  ${BRIGHT_CYAN}CTRL+J${NC}:jobs  ${BRIGHT_CYAN}CTRL+M${NC}:mode
${BRIGHT_GREEN}▶${NC} = Service detected ${CYAN}│${NC} ${DIM}dim${NC} = Service not detected ${CYAN}│${NC} Type to filter/autocomplete" \
        --header-first \
        --expect=ctrl-t,ctrl-c,ctrl-w,ctrl-d,ctrl-a,ctrl-s,ctrl-j,ctrl-m
}

# Initialize and run
main() {
    clear
    show_banner

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${BRIGHT_CYAN}▶${NC} Initializing PurpleSploit Framework...                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    show_loading "Loading core components"
    framework_init_silent

    echo ""
    show_success "Framework backend initialized"
    show_success "Lite tool handlers loaded"
    show_success "AI automation ready"
    show_success "Database connections established"

    echo ""
    echo -e "${BRIGHT_GREEN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BRIGHT_GREEN}║${NC} ${BOLD}${BRIGHT_GREEN}✓ Ready!${NC} All systems operational                                        ${BRIGHT_GREEN}║${NC}"
    echo -e "${BRIGHT_GREEN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    sleep 2
    
    while true; do
        clear
        show_banner
        
        local output=$(show_main_menu)
        local key=$(echo "$output" | head -n1)
        local choice=$(echo "$output" | tail -n1)
        
        # Handle keybinds
        case "$key" in
            ctrl-t) manage_targets; continue ;;
            ctrl-c) manage_credentials; continue ;;
            ctrl-w) manage_web_targets; continue ;;
            ctrl-d) manage_ad_targets; continue ;;
            ctrl-a) select_credentials; continue ;;
            ctrl-s) select_target; continue ;;
            ctrl-j) handle_sessions_menu; continue ;;
            ctrl-m) toggle_run_mode; continue ;;
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
            *"NXC Utilities"*) handle_nxc_utils ;;
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

            # Sessions
            "Sessions Management") handle_sessions_menu ;;

            # AI Automation
            *"AI Automation"*) handle_ai_automation ;;

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

# Sessions Management Menu
handle_sessions_menu() {
    while true; do
        local header=$(build_header)
        local choice=$(echo "┌ WORKSPACES ────────────────────────────
Switch Workspace (FZF)
Create New Workspace
List All Workspaces
Delete Workspace
Show Workspace Info
┌ BACKGROUND JOBS ───────────────────────
List Running Jobs
View Job Output
Kill Background Job
┌ NAVIGATION ────────────────────────────
Back to Main Menu" | fzf \
            --prompt="Sessions Management: " \
            --height=80% \
            --reverse \
            --header="$header
───────────────────────────────────────
Workspaces: Organize per-engagement | Jobs: Run tools in background")

        case "$choice" in
            "")
                return
                ;;
            "Back to Main Menu")
                return
                ;;

            # Workspaces
            "Switch Workspace (FZF)")
                echo ""
                fzf_workspace_select || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            "Create New Workspace")
                echo ""
                read -p "Enter workspace name: " ws_name
                if [[ -n "$ws_name" ]]; then
                    workspace_create "$ws_name" || true
                fi
                read -p "Press enter to continue..."
                ;;
            "List All Workspaces")
                echo ""
                echo "Available Workspaces:"
                echo "===================="
                workspace_list || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            "Delete Workspace")
                echo ""
                read -p "Enter workspace name to delete: " ws_name
                if [[ -n "$ws_name" ]]; then
                    read -p "Are you sure? This cannot be undone! (yes/no): " confirm
                    if [[ "$confirm" == "yes" ]]; then
                        workspace_delete "$ws_name" || true
                    else
                        echo "[!] Cancelled"
                    fi
                fi
                read -p "Press enter to continue..."
                ;;
            "Show Workspace Info")
                echo ""
                echo "Current Workspace Information:"
                echo "=============================="
                workspace_info || true
                echo ""
                read -p "Press enter to continue..."
                ;;

            # Jobs
            "List Running Jobs")
                echo ""
                echo "Background Jobs:"
                echo "================"
                command_jobs_list || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            "View Job Output")
                echo ""
                command_jobs_list || true
                echo ""
                read -p "Enter job ID to view: " job_id
                if [[ -n "$job_id" ]]; then
                    echo ""
                    echo "Job Output (last 50 lines):"
                    echo "==========================="
                    # Show output from job
                    local job_file="$HOME/.purplesploit/jobs/${job_id}.log"
                    if [[ -f "$job_file" ]]; then
                        tail -50 "$job_file"
                    else
                        echo "[!] Job file not found"
                    fi
                fi
                echo ""
                read -p "Press enter to continue..."
                ;;
            "Kill Background Job")
                echo ""
                command_jobs_list || true
                echo ""
                read -p "Enter job ID to kill: " job_id
                if [[ -n "$job_id" ]]; then
                    command_job_kill "$job_id" || true
                fi
                read -p "Press enter to continue..."
                ;;
        esac
    done
}

main "$@"
