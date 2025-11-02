#!/bin/bash
#
# VariableManager - Universal Variable Management System
# Part of PurpleSploit Framework
#
# This module provides centralized variable storage and substitution
# for all framework modules. Variables can be set globally or per-module.
#
# Features:
# - Global and module-scoped variables
# - Variable validation and type checking
# - Template substitution with ${VAR} syntax
# - Variable persistence across modules
# - Default value support
#
# Usage:
#   var_set "RHOST" "192.168.1.10"
#   var_get "RHOST"
#   var_substitute "nmap -sV \${RHOST} -p \${PORTS}"
#   var_unset "RHOST"
#   var_show_all
#

# Variable storage (associative arrays)
declare -A GLOBAL_VARS
declare -A MODULE_VARS
declare -A VAR_DESCRIPTIONS

# Initialize default global variables
var_init() {
    # Network targets
    GLOBAL_VARS[RHOST]=""
    VAR_DESCRIPTIONS[RHOST]="Remote host IP or hostname"

    GLOBAL_VARS[RPORT]=""
    VAR_DESCRIPTIONS[RPORT]="Remote port"

    GLOBAL_VARS[RHOSTS]=""
    VAR_DESCRIPTIONS[RHOSTS]="Multiple remote hosts (comma-separated or CIDR)"

    # Local machine
    GLOBAL_VARS[LHOST]=""
    VAR_DESCRIPTIONS[LHOST]="Local host IP (for callbacks)"

    GLOBAL_VARS[LPORT]=""
    VAR_DESCRIPTIONS[LPORT]="Local port (for listeners)"

    # Authentication
    GLOBAL_VARS[USERNAME]=""
    VAR_DESCRIPTIONS[USERNAME]="Username for authentication"

    GLOBAL_VARS[PASSWORD]=""
    VAR_DESCRIPTIONS[PASSWORD]="Password for authentication"

    GLOBAL_VARS[DOMAIN]=""
    VAR_DESCRIPTIONS[DOMAIN]="Domain name for authentication"

    GLOBAL_VARS[HASH]=""
    VAR_DESCRIPTIONS[HASH]="Password hash (NTLM, etc.)"

    # Web targets
    GLOBAL_VARS[TARGET_URL]=""
    VAR_DESCRIPTIONS[TARGET_URL]="Target URL for web attacks"

    GLOBAL_VARS[PROXY]=""
    VAR_DESCRIPTIONS[PROXY]="HTTP proxy (e.g., 127.0.0.1:8080)"

    # Common options
    GLOBAL_VARS[THREADS]="10"
    VAR_DESCRIPTIONS[THREADS]="Number of threads/concurrent connections"

    GLOBAL_VARS[TIMEOUT]="30"
    VAR_DESCRIPTIONS[TIMEOUT]="Connection timeout in seconds"

    GLOBAL_VARS[WORDLIST]="/usr/share/wordlists/dirb/common.txt"
    VAR_DESCRIPTIONS[WORDLIST]="Path to wordlist file"

    GLOBAL_VARS[OUTPUT_DIR]="$HOME/.purplesploit/output"
    VAR_DESCRIPTIONS[OUTPUT_DIR]="Directory for output files"

    # Workspace
    GLOBAL_VARS[WORKSPACE]="default"
    VAR_DESCRIPTIONS[WORKSPACE]="Current workspace name"

    # Create output directory if it doesn't exist
    mkdir -p "${GLOBAL_VARS[OUTPUT_DIR]}" 2>/dev/null
}

# Set a variable (global or module-scoped)
# Usage: var_set "VAR_NAME" "value" [scope]
var_set() {
    local var_name="$1"
    local var_value="$2"
    local scope="${3:-global}"

    if [[ -z "$var_name" ]]; then
        echo "[!] Error: Variable name cannot be empty"
        return 1
    fi

    if [[ "$scope" == "global" ]]; then
        GLOBAL_VARS[$var_name]="$var_value"
        echo "[+] $var_name => $var_value"
    else
        MODULE_VARS[$var_name]="$var_value"
        echo "[+] $var_name => $var_value (module scope)"
    fi

    return 0
}

# Get a variable value (checks module scope first, then global)
# Usage: var_get "VAR_NAME"
var_get() {
    local var_name="$1"

    # Check module scope first
    if [[ -n "${MODULE_VARS[$var_name]}" ]]; then
        echo "${MODULE_VARS[$var_name]}"
        return 0
    fi

    # Fall back to global scope
    if [[ -n "${GLOBAL_VARS[$var_name]}" ]]; then
        echo "${GLOBAL_VARS[$var_name]}"
        return 0
    fi

    # Variable not set
    return 1
}

# Unset a variable
# Usage: var_unset "VAR_NAME"
var_unset() {
    local var_name="$1"

    unset "GLOBAL_VARS[$var_name]"
    unset "MODULE_VARS[$var_name]"

    echo "[+] Unset $var_name"
    return 0
}

# Check if a variable is set
# Usage: var_is_set "VAR_NAME"
var_is_set() {
    local var_name="$1"

    if [[ -n "${MODULE_VARS[$var_name]}" ]] || [[ -n "${GLOBAL_VARS[$var_name]}" ]]; then
        return 0
    fi

    return 1
}

# Substitute variables in a command template
# Usage: var_substitute "nmap -sV \${RHOST} -p \${PORTS}"
var_substitute() {
    local template="$1"
    local result="$template"

    # Find all ${VAR} patterns
    local vars=$(echo "$template" | grep -oP '\$\{[A-Z_][A-Z0-9_]*\}' | sort -u)

    for var_pattern in $vars; do
        # Extract variable name (remove ${ and })
        local var_name="${var_pattern:2:-1}"

        # Get variable value
        local var_value=$(var_get "$var_name" 2>/dev/null)

        if [[ -z "$var_value" ]]; then
            echo "[!] Warning: Variable $var_name is not set" >&2
            # Keep the placeholder for manual editing
        else
            # Replace all occurrences using sed
            result=$(echo "$result" | sed "s/\${$var_name}/$var_value/g")
        fi
    done

    echo "$result"
}

# Validate required variables
# Usage: var_validate_required "RHOST,RPORT,USERNAME"
var_validate_required() {
    local required_vars="$1"
    local missing_vars=()

    IFS=',' read -ra VAR_ARRAY <<< "$required_vars"

    for var_name in "${VAR_ARRAY[@]}"; do
        var_name=$(echo "$var_name" | xargs)  # Trim whitespace

        if ! var_is_set "$var_name"; then
            missing_vars+=("$var_name")
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        echo "[!] Error: Missing required variables: ${missing_vars[*]}"
        return 1
    fi

    return 0
}

# Show all variables
# Usage: var_show_all
var_show_all() {
    echo ""
    echo "Global Variables:"
    echo "================================================================================"
    printf "%-20s %-50s %s\n" "Variable" "Current Value" "Description"
    echo "--------------------------------------------------------------------------------"

    # Sort variable names
    local sorted_vars=($(for key in "${!GLOBAL_VARS[@]}"; do echo "$key"; done | sort))

    for var_name in "${sorted_vars[@]}"; do
        local var_value="${GLOBAL_VARS[$var_name]}"
        local var_desc="${VAR_DESCRIPTIONS[$var_name]:-No description}"

        # Truncate long values
        if [[ ${#var_value} -gt 48 ]]; then
            var_value="${var_value:0:45}..."
        fi

        # Show "<not set>" for empty values
        [[ -z "$var_value" ]] && var_value="<not set>"

        printf "%-20s %-50s %s\n" "$var_name" "$var_value" "$var_desc"
    done

    # Show module-scoped variables if any exist
    if [[ ${#MODULE_VARS[@]} -gt 0 ]]; then
        echo ""
        echo "Module Variables:"
        echo "--------------------------------------------------------------------------------"
        for var_name in "${!MODULE_VARS[@]}"; do
            printf "%-20s %-50s\n" "$var_name" "${MODULE_VARS[$var_name]}"
        done
    fi

    echo "================================================================================"
    echo ""
}

# Clear all module-scoped variables (used when changing modules)
# Usage: var_clear_module_scope
var_clear_module_scope() {
    MODULE_VARS=()
}

# Load variables from workspace
# Usage: var_load_workspace "workspace_name"
var_load_workspace() {
    local workspace_name="$1"
    local workspace_file="$HOME/.purplesploit/workspaces/${workspace_name}/vars.conf"

    if [[ ! -f "$workspace_file" ]]; then
        return 1
    fi

    # Load variables from file
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ "$key" =~ ^#.*$ ]] && continue
        [[ -z "$key" ]] && continue

        GLOBAL_VARS[$key]="$value"
    done < "$workspace_file"

    return 0
}

# Save variables to workspace
# Usage: var_save_workspace "workspace_name"
var_save_workspace() {
    local workspace_name="$1"
    local workspace_dir="$HOME/.purplesploit/workspaces/${workspace_name}"
    local workspace_file="$workspace_dir/vars.conf"

    mkdir -p "$workspace_dir"

    # Write variables to file
    {
        echo "# PurpleSploit Workspace Variables"
        echo "# Workspace: $workspace_name"
        echo "# Generated: $(date)"
        echo ""

        for var_name in "${!GLOBAL_VARS[@]}"; do
            echo "${var_name}=${GLOBAL_VARS[$var_name]}"
        done
    } > "$workspace_file"

    return 0
}

# Export functions
export -f var_init
export -f var_set
export -f var_get
export -f var_unset
export -f var_is_set
export -f var_substitute
export -f var_validate_required
export -f var_show_all
export -f var_clear_module_scope
export -f var_load_workspace
export -f var_save_workspace
