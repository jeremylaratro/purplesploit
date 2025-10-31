#!/bin/bash
#
# PurpleSploit Framework Engine
# Main framework initialization and core functionality
#
# This is the central engine that initializes all framework components
# and provides the main execution loop.
#

# Framework version
FRAMEWORK_VERSION="2.0.0-full"
FRAMEWORK_NAME="PurpleSploit Framework"

# Get script directory
FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Colors for output
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export MAGENTA='\033[0;35m'
export NC='\033[0m'

# Banner
show_banner() {
    # Clear screen safely
    if [[ -n "${TERM:-}" ]]; then
        clear 2>/dev/null || echo -e "\n\n\n"
    else
        echo -e "\n\n\n"
    fi

    echo -e "${MAGENTA}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗███████╗██████╗       ║
║   ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗      ║
║   ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗  ███████╗██████╔╝      ║
║   ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝  ╚════██║██╔═══╝       ║
║   ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗███████║██║           ║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝           ║
║                                                                           ║
║         ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗    ║
║         ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗   ║
║         █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║   ║
║         ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║   ║
║         ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝   ║
║         ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝    ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}Version: ${FRAMEWORK_VERSION}${NC}"
    echo -e "${CYAN}Metasploit-Style Pentesting Framework${NC}"
    echo ""
}

# Initialize framework
framework_init() {
    echo -e "${CYAN}[*] Initializing PurpleSploit Framework...${NC}"

    # Declare global arrays for module registry (must be done before sourcing)
    declare -gA MODULE_REGISTRY
    declare -gA MODULE_METADATA
    declare -ga MODULE_LIST

    # Source core components
    echo -e "${CYAN}[*] Loading core components...${NC}"

    source "$FRAMEWORK_DIR/core/variable_manager.sh"
    source "$FRAMEWORK_DIR/core/module_registry.sh"
    source "$FRAMEWORK_DIR/core/command_engine.sh"
    source "$FRAMEWORK_DIR/core/workspace_manager.sh"
    source "$FRAMEWORK_DIR/core/fzf_integration.sh"
    source "$FRAMEWORK_DIR/core/credential_manager.sh"
    source "$FRAMEWORK_DIR/core/mythic_integration.sh"
    source "$FRAMEWORK_DIR/core/service_analyzer.sh"

    # Initialize subsystems
    echo -e "${CYAN}[*] Initializing variable manager...${NC}"
    var_init

    echo -e "${CYAN}[*] Initializing workspace manager...${NC}"
    workspace_init

    echo -e "${CYAN}[*] Initializing command engine...${NC}"
    command_engine_init

    echo -e "${CYAN}[*] Initializing credential manager...${NC}"
    credential_init

    echo -e "${CYAN}[*] Initializing service analyzer...${NC}"
    service_analyzer_init

    echo -e "${CYAN}[*] Initializing Mythic C2 integration...${NC}"
    mythic_init

    echo -e "${CYAN}[*] Discovering modules...${NC}"
    module_registry_init "$SCRIPT_DIR/modules"

    # Check if FZF is available
    if check_fzf; then
        echo -e "${GREEN}[+] FZF detected - Enhanced interactive features enabled${NC}"
    else
        echo -e "${YELLOW}[*] FZF not detected - Using basic mode${NC}"
    fi

    echo -e "${GREEN}[+] Framework initialized successfully${NC}"
    echo ""
}

# Show framework status
framework_status() {
    local module_count=0
    if [[ -v MODULE_LIST ]]; then
        module_count=${#MODULE_LIST[@]}
    fi
    local current_module=$(module_get_current)
    local current_workspace=$(workspace_current)

    echo ""
    echo "Framework Status:"
    echo "================================================================================"
    echo "       Version: $FRAMEWORK_VERSION"
    echo "        Loaded: $module_count modules"
    echo "Current Module: ${current_module:-<none>}"
    echo "     Workspace: $current_workspace"
    echo "================================================================================"
    echo ""
}

# Show help
framework_help() {
    echo ""
    echo "PurpleSploit Framework Commands:"
    echo "================================================================================"
    echo ""
    echo "Module Commands:"
    echo "  use <module>              - Select a module to use"
    echo "  back                      - Deselect current module"
    echo "  search [keyword]          - 🔍 FZF: Interactive module search"
    echo "  search relevant           - 🎯 Smart: Show modules for detected services"
    echo "  browse                    - 🔍 FZF: Browse modules by category"
    echo "  info [module]             - Show module information"
    echo "  show modules              - List all available modules"
    echo "  show categories           - List module categories"
    echo ""
    echo "Service Analysis Commands:"
    echo "  services                  - List all detected services"
    echo "  services -t               - List services on current target"
    echo "  services -c               - Clear service database"
    echo "  services -i <file>        - Import from nmap output file"
    echo ""
    echo "Variable Commands:"
    echo "  set <VAR> <value>         - Set a variable"
    echo "  setg <VAR> <value>        - Set a global variable (alias for 'set')"
    echo "  unset <VAR>               - Unset a variable"
    echo "  vars                      - 🔍 FZF: Interactive variable editor"
    echo "  show options              - Show current module options"
    echo "  show vars                 - Show all variables"
    echo ""
    echo "Execution Commands:"
    echo "  run                       - Execute current module"
    echo "  run -y                    - Execute without confirmation"
    echo "  run -j                    - Execute in background (job)"
    echo "  check                     - Preview command without executing"
    echo ""
    echo "Workspace Commands:"
    echo "  workspace                 - 🔍 FZF: Interactive workspace selection"
    echo "  workspace -l              - List all workspaces"
    echo "  workspace <name>          - Switch to workspace"
    echo "  workspace -a <name>       - Create new workspace"
    echo "  workspace -d <name>       - Delete workspace"
    echo "  workspace -i [name]       - Show workspace info"
    echo ""
    echo "Target Commands:"
    echo "  targets                   - 🔍 FZF: Interactive target selection"
    echo "  targets -l                - List targets in workspace"
    echo "  targets -a <target>       - Add target to workspace"
    echo "  targets -r <target>       - Remove target from workspace"
    echo "  targets -i <file>         - Import targets from file"
    echo "  targets -e <file>         - Export targets to file"
    echo ""
    echo "Credential Commands:"
    echo "  credentials               - 🔍 FZF: Interactive credential selection"
    echo "  credentials -l            - List all credentials"
    echo "  credentials -a            - Add new credential"
    echo "  credentials -e <id>       - Edit credential"
    echo "  credentials -d <id>       - Delete credential"
    echo "  credentials -m            - Credential management menu"
    echo "  credentials -i <file>     - Import credentials from file"
    echo "  credentials -x <file>     - Export credentials to file"
    echo "  creds                     - Alias for credentials"
    echo ""
    echo "Mythic C2 Commands:"
    echo "  mythic                    - Open Mythic C2 menu"
    echo "  mythic configure          - Configure Mythic server"
    echo "  mythic test               - Test Mythic connection"
    echo "  mythic payloads           - List available payloads"
    echo ""
    echo "Job Commands:"
    echo "  jobs                      - List background jobs"
    echo "  jobs -k <id>              - Kill a background job"
    echo ""
    echo "History Commands:"
    echo "  history                   - 🔍 FZF: Interactive history selection"
    echo "  history -l [count]        - Show command history"
    echo "  history -s <keyword>      - Search command history"
    echo ""
    echo "Other Commands:"
    echo "  status                    - Show framework status"
    echo "  help                      - Show this help"
    echo "  clear                     - Clear screen"
    echo "  exit                      - Exit framework"
    echo "  quit                      - Exit framework"
    echo ""
    echo "================================================================================"
    echo ""
    echo "Tips:"
    echo "  🔍 = FZF enhanced - interactive menu-driven interface"
    echo "  - Use Tab for command completion (if available)"
    echo "  - Variables can be referenced as \${VAR} in commands"
    echo "  - Commands can be edited before execution"
    echo "  - Most commands support FZF for menu-style selection"
    echo ""
}

# Quick start guide
framework_quickstart() {
    echo ""
    echo -e "${CYAN}Quick Start Guide:${NC}"
    echo "================================================================================"
    echo ""
    echo "1. Search for a module:"
    echo "   ${GREEN}search nmap${NC}"
    echo ""
    echo "2. Select a module:"
    echo "   ${GREEN}use recon/nmap/quick_scan${NC}"
    echo ""
    echo "3. View module options:"
    echo "   ${GREEN}show options${NC}"
    echo ""
    echo "4. Set required variables:"
    echo "   ${GREEN}set RHOST 192.168.1.1${NC}"
    echo ""
    echo "5. Run the module:"
    echo "   ${GREEN}run${NC}"
    echo ""
    echo "================================================================================"
    echo ""
    echo "Type '${GREEN}help${NC}' for full command list"
    echo ""
}

# Cleanup on exit
framework_cleanup() {
    echo ""
    echo -e "${CYAN}[*] Saving workspace...${NC}"

    # Only save workspace if it's been initialized
    if [[ -n "${CURRENT_WORKSPACE:-}" ]]; then
        var_save_workspace "$CURRENT_WORKSPACE"
    fi

    echo -e "${GREEN}[+] Thank you for using PurpleSploit Framework!${NC}"
    echo ""
}

# Set trap for cleanup
trap framework_cleanup EXIT INT TERM

# Export functions
export -f show_banner
export -f framework_init
export -f framework_status
export -f framework_help
export -f framework_quickstart
export -f framework_cleanup
