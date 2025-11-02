#!/bin/bash
#
# PurpleSploit Framework - FZF TUI Interface
# Visual menu-driven interface with framework backend
#

set -o pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source framework engine
source "$SCRIPT_DIR/framework/core/engine.sh"

# Initialize framework
framework_init_silent() {
    # Declare global arrays for module registry
    declare -gA MODULE_REGISTRY
    declare -gA MODULE_METADATA
    declare -ga MODULE_LIST

    # Source core components silently
    source "$FRAMEWORK_DIR/core/variable_manager.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/module_registry.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/command_engine.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/workspace_manager.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/fzf_integration.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/credential_manager.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/mythic_integration.sh" 2>/dev/null
    source "$FRAMEWORK_DIR/core/service_analyzer.sh" 2>/dev/null

    # Initialize subsystems
    var_init
    workspace_init
    command_engine_init
    credential_init
    service_analyzer_init
    mythic_init
    module_registry_init "$SCRIPT_DIR/modules" >/dev/null 2>&1
}

# Build header with current status
build_header() {
    local workspace=$(workspace_current)
    local target=$(var_get "RHOST" 2>/dev/null || echo "<none>")
    local username=$(var_get "USERNAME" 2>/dev/null || echo "<none>")
    local module_count=${#MODULE_LIST[@]}

    echo "Workspace: $workspace | Target: $target | User: $username | Modules: $module_count"
}

# Highlight menu items based on detected services
highlight_if_relevant() {
    local module_path="$1"
    local menu_text="$2"
    local target=$(var_get "RHOST" 2>/dev/null)

    # If no target set, just return plain text
    if [[ -z "$target" ]]; then
        echo "$menu_text"
        return
    fi

    # Check if we have services detected for this target
    local module_category=$(echo "$module_path" | cut -d/ -f1)
    local services=$(service_get_for_target "$target" 2>/dev/null)

    # Map module category to service and highlight if detected
    case "$module_category" in
        *smb*|*nxc*)
            if echo "$services" | grep -qi "smb\|microsoft-ds\|netbios"; then
                echo "★ $menu_text"
                return
            fi
            ;;
        *web*|*http*)
            if echo "$services" | grep -qi "http\|https\|ssl"; then
                echo "★ $menu_text"
                return
            fi
            ;;
        *ldap*)
            if echo "$services" | grep -qi "ldap"; then
                echo "★ $menu_text"
                return
            fi
            ;;
        *winrm*)
            if echo "$services" | grep -qi "winrm\|wsman"; then
                echo "★ $menu_text"
                return
            fi
            ;;
        *ssh*)
            if echo "$services" | grep -qi "ssh"; then
                echo "★ $menu_text"
                return
            fi
            ;;
    esac

    echo "$menu_text"
}

# Build main menu
build_main_menu() {
    echo "┌ RECONNAISSANCE ────────────────────────"
    echo "Quick Nmap Scan (Top 1000 Ports)"
    echo "Full Nmap Scan (All Ports)"
    echo "Nmap Vulnerability Scan"
    echo "┌ WEB TESTING ───────────────────────────"
    echo "$(highlight_if_relevant "web/feroxbuster" "Feroxbuster - Basic Scan")"
    echo "$(highlight_if_relevant "web/feroxbuster" "Feroxbuster - Deep Scan")"
    echo "$(highlight_if_relevant "web/feroxbuster" "Feroxbuster - API Discovery")"
    echo "$(highlight_if_relevant "web/httpx" "HTTPx - URL Probing")"
    echo "$(highlight_if_relevant "web/sqlmap" "SQLMap - Basic Injection Test")"
    echo "$(highlight_if_relevant "web/sqlmap" "SQLMap - Database Dump")"
    echo "┌ NETWORK TESTING - SMB ─────────────────"
    echo "$(highlight_if_relevant "network/nxc/smb" "NXC SMB - Authentication Test")"
    echo "$(highlight_if_relevant "network/nxc/smb" "NXC SMB - Enumerate Shares")"
    echo "$(highlight_if_relevant "network/nxc/smb" "NXC SMB - Enumerate Users")"
    echo "$(highlight_if_relevant "network/nxc/smb" "NXC SMB - Dump SAM")"
    echo "┌ NETWORK TESTING - LDAP ────────────────"
    echo "$(highlight_if_relevant "network/nxc/ldap" "NXC LDAP - Enumerate Domain")"
    echo "┌ NETWORK TESTING - WINRM ───────────────"
    echo "$(highlight_if_relevant "network/nxc/winrm" "NXC WinRM - Command Execution")"
    echo "┌ C2 & POST-EXPLOITATION ────────────────"
    echo "Mythic C2 - Deploy via SMB"
    echo "Mythic C2 - Deploy via WinRM"
    echo "Mythic C2 - Deploy via PSExec"
    echo "Mythic C2 - Deploy via WMIExec"
    echo "┌ WORKSPACE & SETTINGS ──────────────────"
    echo "⚙️  Switch Workspace"
    echo "🎯 Manage Targets"
    echo "🔐 Manage Credentials"
    echo "📊 View Services (from scans)"
    echo "📈 Show Relevant Modules (smart filter)"
    echo "ℹ️  Framework Status"
    echo "┌ ADVANCED ──────────────────────────────"
    echo "🔍 Browse All Modules by Category"
    echo "🔍 Search All Modules"
    echo "⚡ Set Variables Manually"
    echo "📜 View Command History"
    echo "🔄 Mythic C2 Configuration"
    echo "Exit"
}

# Show main menu and get selection
show_main_menu() {
    local header=$(build_header)

    local selection=$(build_main_menu | fzf \
        --prompt="Select Action: " \
        --height=100% \
        --reverse \
        --header="$header
───────────────────────────────────────────────────────────
Keybinds: [t]argets [c]reds [w]orkspace [s]ervices [v]ars [q]uit
★ = Service detected on current target" \
        --header-first \
        --expect=t,c,w,s,v,q)

    # Parse selection (first line is key pressed, second is menu item)
    local key=$(echo "$selection" | head -n1)
    local choice=$(echo "$selection" | tail -n1)

    # Handle keybinds
    if [[ -n "$key" ]]; then
        case "$key" in
            t) handle_targets_menu; return ;;
            c) handle_credentials_menu; return ;;
            w) handle_workspace_menu; return ;;
            s) handle_services_view; return ;;
            v) handle_variables_menu; return ;;
            q) echo "Exit"; return ;;
        esac
    fi

    # Handle menu selection
    echo "$choice"
}

# Handle target management menu
handle_targets_menu() {
    local action=$(echo "Add New Target
Select Target (set RHOST)
List All Targets
Import Targets from File
Export Targets to File
Remove Target
Back" | fzf --prompt="Target Management: " --height=50% --reverse --header="$(build_header)")

    case "$action" in
        "Add New Target")
            read -p "Enter target IP/hostname: " target
            if [[ -n "$target" ]]; then
                workspace_add_target "$target" || true
                var_set "RHOST" "$target"
                echo "[+] Target added and set: $target"
                sleep 1
            fi
            ;;
        "Select Target (set RHOST)")
            fzf_target_select || true
            sleep 1
            ;;
        "List All Targets")
            workspace_list_targets || true
            read -p "Press enter to continue..."
            ;;
        "Import Targets from File")
            read -p "Enter file path: " file
            [[ -n "$file" ]] && workspace_import_targets "$file" || true
            sleep 1
            ;;
        "Export Targets to File")
            read -p "Enter file path: " file
            [[ -n "$file" ]] && workspace_export_targets "$file" || true
            sleep 1
            ;;
        "Remove Target")
            read -p "Enter target to remove: " target
            [[ -n "$target" ]] && workspace_remove_target "$target" || true
            sleep 1
            ;;
    esac
}

# Handle credentials menu
handle_credentials_menu() {
    local action=$(echo "Select Credentials (FZF)
Add New Credentials
List All Credentials
Delete Credentials
Import from File
Export to File
Back" | fzf --prompt="Credential Management: " --height=50% --reverse --header="$(build_header)")

    case "$action" in
        "Select Credentials (FZF)")
            fzf_credential_select || true
            sleep 1
            ;;
        "Add New Credentials")
            credential_add_interactive || true
            sleep 1
            ;;
        "List All Credentials")
            credential_list_all || true
            read -p "Press enter to continue..."
            ;;
        "Delete Credentials")
            read -p "Enter credential ID to delete: " cred_id
            [[ -n "$cred_id" ]] && credential_delete "$cred_id" || true
            sleep 1
            ;;
        "Import from File")
            read -p "Enter file path: " file
            [[ -n "$file" ]] && credential_import "$file" || true
            sleep 1
            ;;
        "Export to File")
            read -p "Enter file path: " file
            [[ -n "$file" ]] && credential_export "$file" || true
            sleep 1
            ;;
    esac
}

# Handle workspace menu
handle_workspace_menu() {
    local action=$(echo "Switch Workspace (FZF)
Create New Workspace
List All Workspaces
Delete Workspace
Workspace Info
Back" | fzf --prompt="Workspace Management: " --height=50% --reverse --header="$(build_header)")

    case "$action" in
        "Switch Workspace (FZF)")
            fzf_workspace_select || true
            sleep 1
            ;;
        "Create New Workspace")
            read -p "Enter workspace name: " ws_name
            [[ -n "$ws_name" ]] && workspace_create "$ws_name" || true
            sleep 1
            ;;
        "List All Workspaces")
            workspace_list || true
            read -p "Press enter to continue..."
            ;;
        "Delete Workspace")
            read -p "Enter workspace name to delete: " ws_name
            [[ -n "$ws_name" ]] && workspace_delete "$ws_name" || true
            sleep 1
            ;;
        "Workspace Info")
            workspace_info || true
            read -p "Press enter to continue..."
            ;;
    esac
}

# Handle services view
handle_services_view() {
    echo ""
    echo "Detected Services:"
    echo "=================="
    service_list_detected || true
    echo ""
    read -p "Press enter to continue..."
}

# Handle variables menu
handle_variables_menu() {
    fzf_variable_select || true
}

# Execute module
execute_module() {
    local module_name="$1"

    # Use the module
    module_use "$module_name" || return 1

    # Show module info
    echo ""
    module_info || return 1
    echo ""

    # Check if required vars are set
    local required_vars=$(module_get_field "$module_name" "REQUIRED_VARS")
    if [[ -n "$required_vars" ]]; then
        IFS=',' read -ra VARS <<< "$required_vars"
        for var_name in "${VARS[@]}"; do
            var_name=$(echo "$var_name" | xargs)
            if ! var_is_set "$var_name"; then
                read -p "Set $var_name: " var_value
                if [[ -n "$var_value" ]]; then
                    var_set "$var_name" "$var_value"
                fi
            fi
        done
    fi

    # Ask to run
    read -p "Run module? (Y/n): " confirm
    if [[ "$confirm" != "n" && "$confirm" != "N" ]]; then
        command_run || true
    fi

    echo ""
    read -p "Press enter to continue..."
}

# Main loop
main_loop() {
    while true; do
        clear
        show_banner
        echo ""

        choice=$(show_main_menu)

        [[ -z "$choice" ]] && continue

        case "$choice" in
            "Quick Nmap Scan (Top 1000 Ports)")
                execute_module "recon/nmap/quick_scan"
                ;;
            "Full Nmap Scan (All Ports)")
                execute_module "recon/nmap/full_scan"
                ;;
            "Nmap Vulnerability Scan")
                execute_module "recon/nmap/vuln_scan"
                ;;
            *"Feroxbuster - Basic Scan"*)
                execute_module "web/feroxbuster/basic_scan"
                ;;
            *"Feroxbuster - Deep Scan"*)
                execute_module "web/feroxbuster/deep_scan"
                ;;
            *"Feroxbuster - API Discovery"*)
                execute_module "web/feroxbuster/api_discovery"
                ;;
            *"HTTPx - URL Probing"*)
                execute_module "web/httpx/probe_urls"
                ;;
            *"SQLMap - Basic Injection Test"*)
                execute_module "web/sqlmap/basic_injection"
                ;;
            *"SQLMap - Database Dump"*)
                execute_module "web/sqlmap/database_dump"
                ;;
            *"NXC SMB - Authentication Test"*)
                execute_module "network/nxc/smb/auth_test"
                ;;
            *"NXC SMB - Enumerate Shares"*)
                execute_module "network/nxc/smb/enum_shares"
                ;;
            *"NXC SMB - Enumerate Users"*)
                execute_module "network/nxc/smb/enum_users"
                ;;
            *"NXC SMB - Dump SAM"*)
                execute_module "network/nxc/smb/dump_sam"
                ;;
            *"NXC LDAP - Enumerate Domain"*)
                execute_module "network/nxc/ldap/enum_domain"
                ;;
            *"NXC WinRM - Command Execution"*)
                execute_module "network/nxc/winrm/command_exec"
                ;;
            *"Mythic C2 - Deploy via SMB"*)
                execute_module "c2/mythic/deploy_smb"
                ;;
            *"Mythic C2 - Deploy via WinRM"*)
                execute_module "c2/mythic/deploy_winrm"
                ;;
            *"Mythic C2 - Deploy via PSExec"*)
                execute_module "c2/mythic/deploy_psexec"
                ;;
            *"Mythic C2 - Deploy via WMIExec"*)
                execute_module "c2/mythic/deploy_wmiexec"
                ;;
            *"Switch Workspace"*)
                handle_workspace_menu
                ;;
            *"Manage Targets"*)
                handle_targets_menu
                ;;
            *"Manage Credentials"*)
                handle_credentials_menu
                ;;
            *"View Services"*)
                handle_services_view
                ;;
            *"Show Relevant Modules"*)
                echo ""
                service_search_relevant_fzf || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            *"Framework Status"*)
                echo ""
                framework_status || true
                echo ""
                read -p "Press enter to continue..."
                ;;
            *"Browse All Modules by Category"*)
                fzf_category_browse || true
                ;;
            *"Search All Modules"*)
                fzf_module_search "" || true
                ;;
            *"Set Variables Manually"*)
                handle_variables_menu
                ;;
            *"View Command History"*)
                fzf_history_select || true
                ;;
            *"Mythic C2 Configuration"*)
                mythic_configure || true
                read -p "Press enter to continue..."
                ;;
            "Exit")
                break
                ;;
        esac
    done
}

# Main entry point
main() {
    # Clear screen
    clear

    # Show banner
    show_banner

    echo ""
    echo -e "${CYAN}[*] Initializing framework...${NC}"

    # Initialize framework silently
    framework_init_silent

    echo -e "${GREEN}[+] Loaded ${#MODULE_LIST[@]} modules${NC}"
    echo -e "${CYAN}[*] Starting TUI...${NC}"
    sleep 1

    # Enter main loop
    main_loop

    # Cleanup
    framework_cleanup
}

# Run main
main "$@"
