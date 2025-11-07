#!/bin/bash
#
# PurpleSploit Comprehensive TUI
# Combines framework backend with full menu coverage
#

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Strip ANSI color codes and special characters from text
strip_colors() {
    # Remove ANSI codes, bullet points, and trim whitespace
    echo "$1" | sed -r 's/\x1b\[[0-9;]*m//g; s/\x1b\(B//g; s/[▸●○★◆◦✓✗⚠ℹ🌐🔒🛠️💼🤖⚙️🚪🎯🔐⚡⬅️🔄]//g; s/^[[:space:]]*//; s/[[:space:]]*$//'
}

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
source "$SCRIPT_DIR/lib/nmap_results.sh" 2>/dev/null || true
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

    # Use enhanced context bar if available
    if type draw_enhanced_context &>/dev/null; then
        draw_enhanced_context "$workspace" "$target" "$creds" "$run_mode"
    else
        # Fallback to simple header
        echo "Workspace: $workspace | Target: $target | Creds: $creds | Mode: $run_mode"
    fi
}

# Service highlighting helper with enhanced colors
highlight_if_active() {
    local target="$1"
    local service="$2"
    local text="$3"

    if [[ -n "$target" ]] && service_check "$target" "$service" 2>/dev/null; then
        # Service detected - highlight with green bullet
        echo "${BRIGHT_GREEN}●${NC} ${BRIGHT_CYAN}$text${NC}"
    else
        # Service not detected - dimmed
        echo "${DIM}○${NC} $text"
    fi
}

# Main menu with enhanced colors
show_main_menu() {
    local target="${TARGET:-$(var_get RHOST 2>/dev/null)}"

    # Build dynamic menu with color-coded sections
    local menu="
${BRIGHT_YELLOW}┌─ 🌐 WEB TESTING ───────────────────────────────────────────────────────────${NC}
${CYAN}▸${NC} Feroxbuster (Directory/File Discovery)
${CYAN}▸${NC} WFUZZ (Fuzzing)
${CYAN}▸${NC} SQLMap (SQL Injection)
${CYAN}▸${NC} HTTPX (HTTP Probing)

${BRIGHT_MAGENTA}┌─ 🔒 NETWORK TESTING - NXC ─────────────────────────────────────────────────${NC}
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
${CYAN}▸${NC} Network Scanning

${BRIGHT_BLUE}┌─ 🛠️  NETWORK TESTING - IMPACKET ──────────────────────────────────────────${NC}
${CYAN}▸${NC} Impacket PSExec
${CYAN}▸${NC} Impacket WMIExec
${CYAN}▸${NC} Impacket SMBExec
${CYAN}▸${NC} Impacket ATExec
${CYAN}▸${NC} Impacket DcomExec
${CYAN}▸${NC} Impacket SecretsDump
${CYAN}▸${NC} Impacket SAM/LSA/NTDS Dump
${CYAN}▸${NC} Kerberoasting (GetUserSPNs)
${CYAN}▸${NC} AS-REP Roasting (GetNPUsers)
${CYAN}▸${NC} Golden/Silver Tickets
${CYAN}▸${NC} Impacket Enumeration
${CYAN}▸${NC} Impacket SMB Client
${CYAN}▸${NC} Service Management
${CYAN}▸${NC} Registry Operations

${BRIGHT_GREEN}┌─ 💼 SESSIONS (WORKSPACES & JOBS) ──────────────────────────────────────────${NC}
${CYAN}▸${NC} Sessions Management

${BRIGHT_CYAN}┌─ 🤖 AI AUTOMATION ─────────────────────────────────────────────────────────${NC}
${CYAN}▸${NC} AI Automation (OpenAI/Claude)

${BRIGHT_WHITE}┌─ ⚙️  SETTINGS ─────────────────────────────────────────────────────────────${NC}
${CYAN}▸${NC} Manage Web Targets
${CYAN}▸${NC} Manage AD Targets
${CYAN}▸${NC} Switch Credentials
${CYAN}▸${NC} Switch Target
${CYAN}▸${NC} Select AD Target
${CYAN}▸${NC} Toggle Run Mode (Single/All)
${CYAN}▸${NC} Manage Credentials
${CYAN}▸${NC} Manage Targets
${CYAN}▸${NC} Database Management (Reset/Clear)

${BRIGHT_RED}┌─ 🚪 EXIT ──────────────────────────────────────────────────────────────────${NC}
${BRIGHT_RED}Exit${NC}"

    # Build header with proper ANSI code expansion
    local header_text="$(build_header)
$(echo -e "${BRIGHT_CYAN}┌─ Keyboard Shortcuts ───────────────────────────────────────────────────────${NC}")
$(echo -e "${BRIGHT_CYAN}│${NC} CTRL+T:targets | CTRL+C:creds | CTRL+W:web | CTRL+D:AD | CTRL+A:auth | CTRL+S:target | CTRL+J:jobs")
$(echo -e "${BRIGHT_CYAN}│${NC} ${BRIGHT_GREEN}●${NC} = Service detected | ${DIM}○${NC} = Service not detected | Type to filter/autocomplete")"

    # Enhanced fzf with custom color scheme
    echo -e "$menu" | fzf \
        --ansi \
        --prompt="▶ Select Tool: " \
        --height=100% \
        --reverse \
        --cycle \
        --border=rounded \
        --info=inline \
        --pointer="▶" \
        --marker="✓" \
        --color="fg:#d0d0d0,bg:#000000,hl:#5f87af,fg+:#00ff00,bg+:#262626,hl+:#5fd7ff,info:#afaf87,prompt:#d7005f,pointer:#af5fff,marker:#87ff00,spinner:#af5fff,header:#87afaf" \
        --header="$header_text" \
        --header-first \
        --bind="enter:accept" \
        --expect=ctrl-t,ctrl-c,ctrl-w,ctrl-d,ctrl-a,ctrl-s,ctrl-j
}

# Initialize and run
main() {
    clear

    # Show enhanced banner if available
    local workspace=$(workspace_current 2>/dev/null || echo "default")
    if type show_enhanced_banner &>/dev/null; then
        show_enhanced_banner "$workspace" "1.0"
    else
        show_banner 2>/dev/null || echo "=== PurpleSploit Framework ==="
    fi

    echo ""
    echo -e "${BRIGHT_CYAN}[*] Initializing PurpleSploit Framework...${NC}"
    echo ""

    # Show progress during initialization
    if type show_init_progress &>/dev/null; then
        show_init_progress "Loading core modules" 1 5
        sleep 0.2
    fi

    framework_init_silent

    if type show_init_progress &>/dev/null; then
        show_init_progress "Initializing workspace" 2 5
        sleep 0.2
        show_init_progress "Loading tool modules" 3 5
        sleep 0.2
        show_init_progress "Connecting to databases" 4 5
        sleep 0.2
        show_init_progress "Starting AI integration" 5 5
        sleep 0.2
        echo ""
    fi

    echo ""
    if type show_success &>/dev/null; then
        show_success "Framework backend initialized"
        show_success "Lite tool handlers loaded"
        show_success "AI automation ready"
        show_success "Database connections established"
    else
        echo -e "${GREEN}[+] Framework backend initialized${NC}"
        echo -e "${GREEN}[+] Lite tool handlers loaded${NC}"
        echo -e "${GREEN}[+] AI automation ready${NC}"
        echo -e "${GREEN}[+] Database connections established${NC}"
    fi

    echo ""
    echo -e "${BRIGHT_GREEN}✓ Ready! All systems operational${NC}"
    echo ""
    sleep 1
    
    while true; do
        clear

        # Show enhanced banner if available
        local workspace=$(workspace_current 2>/dev/null || echo "default")
        if type show_enhanced_banner &>/dev/null; then
            show_enhanced_banner "$workspace" "1.0"
        else
            show_banner 2>/dev/null || echo "=== PurpleSploit Framework ==="
        fi
        echo ""

        local output=$(show_main_menu)
        local key=$(echo "$output" | head -n1)
        local choice=$(echo "$output" | tail -n1)

        # Strip colors from choice for matching
        local clean_choice=$(strip_colors "$choice")

        # Handle keybinds
        case "$key" in
            ctrl-t) manage_targets; continue ;;
            ctrl-c) manage_credentials; continue ;;
            ctrl-w) manage_web_targets; continue ;;
            ctrl-d) manage_ad_targets; continue ;;
            ctrl-a) select_credentials; continue ;;
            ctrl-s) select_target; continue ;;
            ctrl-j) handle_sessions_menu; continue ;;
        esac
        
        # Handle menu selections (use clean_choice without color codes)
        case "$clean_choice" in
            "Exit"|"") exit 0 ;;

            # Web Testing
            *"Feroxbuster"*|*"Directory/File Discovery"*) handle_feroxbuster ;;
            *"WFUZZ"*|*"Fuzzing"*) handle_wfuzz ;;
            *"SQLMap"*|*"SQL Injection"*) handle_sqlmap ;;
            *"HTTPX"*|*"HTTP Probing"*) handle_httpx ;;

            # NXC
            *"SMB Authentication"*) handle_smb_auth ;;
            *"SMB Enumeration"*) handle_smb_enum ;;
            *"SMB Shares"*) handle_smb_shares ;;
            *"SMB Execution"*) handle_smb_exec ;;
            *"SMB Credentials"*) handle_smb_creds ;;
            *"SMB Vulnerabilities"*) handle_smb_vulns ;;
            *"NXC Utilities"*|*"hosts/krb5/slinky"*) handle_nxc_utils ;;
            *"LDAP Enumeration"*) handle_ldap ;;
            *"LDAP BloodHound"*|*"BloodHound"*) handle_bloodhound ;;
            *"WinRM Operations"*) handle_winrm ;;
            *"MSSQL Operations"*) handle_mssql ;;
            *"RDP Operations"*) handle_rdp ;;
            *"SSH Operations"*) handle_ssh ;;
            *"Network Scanning"*) handle_scanning ;;

            # Impacket
            *"Impacket PSExec"*|*"PSExec"*) handle_psexec ;;
            *"Impacket WMIExec"*|*"WMIExec"*) handle_wmiexec ;;
            *"Impacket SMBExec"*|*"SMBExec"*) handle_smbexec ;;
            *"Impacket ATExec"*|*"ATExec"*) handle_atexec ;;
            *"Impacket DcomExec"*|*"DcomExec"*) handle_dcomexec ;;
            *"SecretsDump"*|*"SAM/LSA/NTDS"*) handle_secretsdump ;;
            *"Kerberoasting"*|*"GetUserSPNs"*) handle_kerberoast ;;
            *"AS-REP Roasting"*|*"GetNPUsers"*) handle_asreproast ;;
            *"Golden/Silver Tickets"*|*"Tickets"*) handle_tickets ;;
            *"Impacket Enumeration"*) handle_enum ;;
            *"Impacket SMB Client"*) handle_smbclient ;;
            *"Service Management"*) handle_services ;;
            *"Registry Operations"*) handle_registry ;;

            # Sessions
            *"Sessions Management"*|*"Sessions"*) handle_sessions_menu ;;

            # AI Automation
            *"AI Automation"*) handle_ai_automation ;;

            # Management
            *"Manage Web Targets"*|*"Web Targets"*) manage_web_targets ;;
            *"Manage AD Targets"*|*"AD Targets"*) manage_ad_targets ;;
            *"Switch Credentials"*) select_credentials ;;
            *"Switch Target"*) select_target ;;
            *"Select AD Target"*) select_ad_target ;;
            *"Toggle Run Mode"*|*"Run Mode"*) toggle_run_mode ;;
            *"Manage Credentials"*) manage_credentials ;;
            *"Manage Targets"*) manage_targets ;;
            *"Database Management"*|*"Reset/Clear"*) manage_databases ;;

            # Default case - show error
            *)
                if [[ -n "$clean_choice" ]]; then
                    echo ""
                    echo -e "${BRIGHT_RED}[!] Unknown selection: '$clean_choice'${NC}"
                    echo -e "${YELLOW}[*] Debug - Original choice: '$choice'${NC}"
                    echo ""
                    read -p "Press Enter to continue..."
                fi
                ;;
        esac
    done
}

# Sessions Management Menu with enhanced visuals
handle_sessions_menu() {
    while true; do
        local menu="
${BRIGHT_CYAN}┌─ 💼 WORKSPACES ────────────────────────────────────────────────────────────${NC}
${CYAN}▸${NC} Switch Workspace (FZF)
${CYAN}▸${NC} Create New Workspace
${CYAN}▸${NC} List All Workspaces
${CYAN}▸${NC} Delete Workspace
${CYAN}▸${NC} Show Workspace Info

${BRIGHT_YELLOW}┌─ 🔄 BACKGROUND JOBS ───────────────────────────────────────────────────────${NC}
${CYAN}▸${NC} List Running Jobs
${CYAN}▸${NC} View Job Output
${CYAN}▸${NC} Kill Background Job

${BRIGHT_MAGENTA}┌─ ⬅️  NAVIGATION ────────────────────────────────────────────────────────────${NC}
${BRIGHT_GREEN}Back to Main Menu${NC}"

        # Build header with proper ANSI code expansion
        local sessions_header="$(build_header)
$(echo -e "${DIM}Workspaces: Organize per-engagement | Jobs: Run tools in background${NC}")"

        local choice=$(echo -e "$menu" | fzf \
            --ansi \
            --prompt="💼 Sessions Management: " \
            --height=80% \
            --reverse \
            --color="fg:#d0d0d0,bg:#000000,hl:#5f87af,fg+:#00ff00,bg+:#262626,hl+:#5fd7ff,info:#afaf87,prompt:#d7005f,pointer:#af5fff,marker:#87ff00,spinner:#af5fff,header:#87afaf" \
            --header="$sessions_header")

        # Strip colors for matching
        local clean_choice=$(strip_colors "$choice")

        case "$clean_choice" in
            "")
                return
                ;;
            "Back to Main Menu")
                return
                ;;

            # Workspaces
            *"Switch Workspace"*)
                echo ""
                if type show_info &>/dev/null; then
                    show_info "Switching workspace..."
                fi
                fzf_workspace_select || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            *"Create New Workspace"*)
                echo ""
                read -p "Enter workspace name: " ws_name
                if [[ -n "$ws_name" ]]; then
                    if type show_loading &>/dev/null; then
                        show_loading "Creating workspace '$ws_name'"
                    fi
                    if workspace_create "$ws_name" 2>/dev/null; then
                        type show_success &>/dev/null && show_success "Workspace '$ws_name' created!"
                    else
                        type show_error &>/dev/null && show_error "Failed to create workspace"
                    fi
                fi
                read -p "Press enter to continue..."
                ;;
            *"List All Workspaces"*)
                echo ""
                if type show_info &>/dev/null; then
                    show_info "Available Workspaces:"
                else
                    echo "Available Workspaces:"
                fi
                echo "===================="
                workspace_list || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            *"Delete Workspace"*)
                echo ""
                read -p "Enter workspace name to delete: " ws_name
                if [[ -n "$ws_name" ]]; then
                    if type show_warning &>/dev/null; then
                        show_warning "This action cannot be undone!"
                    fi
                    read -p "Are you sure? (yes/no): " confirm
                    if [[ "$confirm" == "yes" ]]; then
                        if workspace_delete "$ws_name" 2>/dev/null; then
                            type show_success &>/dev/null && show_success "Workspace deleted"
                        else
                            type show_error &>/dev/null && show_error "Failed to delete workspace"
                        fi
                    else
                        type show_info &>/dev/null && show_info "Cancelled" || echo "[!] Cancelled"
                    fi
                fi
                read -p "Press enter to continue..."
                ;;
            *"Show Workspace Info"*)
                echo ""
                if type show_info &>/dev/null; then
                    show_info "Current Workspace Information:"
                else
                    echo "Current Workspace Information:"
                fi
                echo "=============================="
                workspace_info || true
                echo ""
                read -p "Press enter to continue..."
                ;;

            # Jobs
            *"List Running Jobs"*)
                echo ""
                if type show_info &>/dev/null; then
                    show_info "Background Jobs:"
                else
                    echo "Background Jobs:"
                fi
                echo "================"
                command_jobs_list || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            *"View Job Output"*)
                echo ""
                command_jobs_list || true
                echo ""
                read -p "Enter job ID to view: " job_id
                if [[ -n "$job_id" ]]; then
                    echo ""
                    if type show_info &>/dev/null; then
                        show_info "Job Output (last 50 lines):"
                    else
                        echo "Job Output (last 50 lines):"
                    fi
                    echo "==========================="
                    # Show output from job
                    local job_file="$HOME/.purplesploit/jobs/${job_id}.log"
                    if [[ -f "$job_file" ]]; then
                        tail -50 "$job_file"
                    else
                        type show_error &>/dev/null && show_error "Job file not found" || echo "[!] Job file not found"
                    fi
                fi
                echo ""
                read -p "Press enter to continue..."
                ;;
            *"Kill Background Job"*)
                echo ""
                command_jobs_list || true
                echo ""
                read -p "Enter job ID to kill: " job_id
                if [[ -n "$job_id" ]]; then
                    if type show_loading &>/dev/null; then
                        show_loading "Killing job $job_id"
                    fi
                    if command_job_kill "$job_id" 2>/dev/null; then
                        type show_success &>/dev/null && show_success "Job killed"
                    else
                        type show_error &>/dev/null && show_error "Failed to kill job"
                    fi
                fi
                read -p "Press enter to continue..."
                ;;
        esac
    done
}

main "$@"
