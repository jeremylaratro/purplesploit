#!/bin/bash
#
# WorkspaceManager - Workspace and Target Management
# Part of PurpleSploit Framework
#
# This module handles:
# - Workspace creation and management
# - Target management per workspace
# - Workspace-specific variable storage
# - Engagement organization
#
# Workspaces allow you to organize different engagements/projects
# and keep their targets and variables separate.
#

# Workspace storage
WORKSPACE_DIR="$HOME/.purplesploit/workspaces"
CURRENT_WORKSPACE="default"

# Initialize workspace manager
workspace_init() {
    # Create workspace directory
    mkdir -p "$WORKSPACE_DIR"

    # Create default workspace if it doesn't exist
    if [[ ! -d "$WORKSPACE_DIR/default" ]]; then
        workspace_create "default"
    fi

    # Set current workspace
    workspace_switch "default"
}

# Create a new workspace
# Usage: workspace_create "workspace_name"
workspace_create() {
    local workspace_name="$1"

    if [[ -z "$workspace_name" ]]; then
        echo "[!] Error: Workspace name cannot be empty"
        return 1
    fi

    # Validate workspace name (alphanumeric, dash, underscore)
    if [[ ! "$workspace_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "[!] Error: Invalid workspace name. Use only letters, numbers, dash, and underscore"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"

    if [[ -d "$workspace_path" ]]; then
        echo "[!] Error: Workspace already exists: $workspace_name"
        return 1
    fi

    # Create workspace directories
    mkdir -p "$workspace_path"/{targets,output,logs,data}

    # Create empty targets file
    touch "$workspace_path/targets/hosts.txt"

    # Create workspace metadata
    cat > "$workspace_path/metadata.txt" <<EOF
# PurpleSploit Workspace
Name: $workspace_name
Created: $(date)
Description:
EOF

    # Create variables file
    touch "$workspace_path/vars.conf"

    echo "[+] Created workspace: $workspace_name"
    echo "[+] Location: $workspace_path"
    return 0
}

# Delete a workspace
# Usage: workspace_delete "workspace_name"
workspace_delete() {
    local workspace_name="$1"

    if [[ -z "$workspace_name" ]]; then
        echo "[!] Error: Workspace name cannot be empty"
        return 1
    fi

    # Prevent deletion of default workspace
    if [[ "$workspace_name" == "default" ]]; then
        echo "[!] Error: Cannot delete default workspace"
        return 1
    fi

    # Prevent deletion of current workspace
    if [[ "$workspace_name" == "$CURRENT_WORKSPACE" ]]; then
        echo "[!] Error: Cannot delete current workspace. Switch to another workspace first"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"

    if [[ ! -d "$workspace_path" ]]; then
        echo "[!] Error: Workspace not found: $workspace_name"
        return 1
    fi

    # Confirm deletion
    read -p "Are you sure you want to delete workspace '$workspace_name'? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Cancelled."
        return 0
    fi

    # Delete workspace
    rm -rf "$workspace_path"

    echo "[+] Deleted workspace: $workspace_name"
    return 0
}

# Switch to a workspace
# Usage: workspace_switch "workspace_name"
workspace_switch() {
    local workspace_name="$1"

    if [[ -z "$workspace_name" ]]; then
        echo "[!] Error: Workspace name cannot be empty"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"

    if [[ ! -d "$workspace_path" ]]; then
        echo "[!] Error: Workspace not found: $workspace_name"
        echo "[*] Use 'workspace -c <name>' to create it"
        return 1
    fi

    # Save current workspace variables
    if [[ -n "$CURRENT_WORKSPACE" ]]; then
        var_save_workspace "$CURRENT_WORKSPACE"
    fi

    # Switch workspace
    CURRENT_WORKSPACE="$workspace_name"

    # Update global variable
    var_set "WORKSPACE" "$workspace_name"

    # Update output directory
    var_set "OUTPUT_DIR" "$workspace_path/output"

    # Load workspace variables
    var_load_workspace "$workspace_name"

    echo "[+] Switched to workspace: $workspace_name"
    return 0
}

# List all workspaces
# Usage: workspace_list
workspace_list() {
    echo ""
    echo "Available Workspaces:"
    echo "================================================================================"
    printf "%-20s %-15s %s\n" "Name" "Status" "Target Count"
    echo "--------------------------------------------------------------------------------"

    for workspace_path in "$WORKSPACE_DIR"/*; do
        if [[ -d "$workspace_path" ]]; then
            local workspace_name=$(basename "$workspace_path")
            local target_count=$(wc -l < "$workspace_path/targets/hosts.txt" 2>/dev/null || echo "0")
            local status=""

            if [[ "$workspace_name" == "$CURRENT_WORKSPACE" ]]; then
                status="* (current)"
            fi

            printf "%-20s %-15s %s\n" "$workspace_name" "$status" "$target_count"
        fi
    done

    echo "================================================================================"
    echo ""
}

# Show workspace information
# Usage: workspace_info [workspace_name]
workspace_info() {
    local workspace_name="${1:-$CURRENT_WORKSPACE}"

    if [[ -z "$workspace_name" ]]; then
        echo "[!] Error: No workspace specified"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"

    if [[ ! -d "$workspace_path" ]]; then
        echo "[!] Error: Workspace not found: $workspace_name"
        return 1
    fi

    # Get metadata
    local target_count=$(wc -l < "$workspace_path/targets/hosts.txt" 2>/dev/null || echo "0")
    local output_files=$(find "$workspace_path/output" -type f 2>/dev/null | wc -l)
    local log_files=$(find "$workspace_path/logs" -type f 2>/dev/null | wc -l)
    local disk_usage=$(du -sh "$workspace_path" 2>/dev/null | awk '{print $1}')

    echo ""
    echo "Workspace Information"
    echo "================================================================================"
    echo "        Name: $workspace_name"
    echo "        Path: $workspace_path"
    echo "     Targets: $target_count"
    echo "Output Files: $output_files"
    echo "   Log Files: $log_files"
    echo "  Disk Usage: $disk_usage"
    echo ""

    # Show metadata
    if [[ -f "$workspace_path/metadata.txt" ]]; then
        echo "Metadata:"
        cat "$workspace_path/metadata.txt" | grep -v "^#" | sed 's/^/  /'
    fi

    echo "================================================================================"
    echo ""
}

# Add target to workspace
# Usage: workspace_add_target "target" [workspace_name]
workspace_add_target() {
    local target="$1"
    local workspace_name="${2:-$CURRENT_WORKSPACE}"

    if [[ -z "$target" ]]; then
        echo "[!] Error: Target cannot be empty"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"
    local targets_file="$workspace_path/targets/hosts.txt"

    if [[ ! -d "$workspace_path" ]]; then
        echo "[!] Error: Workspace not found: $workspace_name"
        return 1
    fi

    # Check if target already exists
    if grep -Fxq "$target" "$targets_file" 2>/dev/null; then
        echo "[!] Target already exists: $target"
        return 1
    fi

    # Add target
    echo "$target" >> "$targets_file"

    echo "[+] Added target: $target"
    return 0
}

# Remove target from workspace
# Usage: workspace_remove_target "target" [workspace_name]
workspace_remove_target() {
    local target="$1"
    local workspace_name="${2:-$CURRENT_WORKSPACE}"

    if [[ -z "$target" ]]; then
        echo "[!] Error: Target cannot be empty"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"
    local targets_file="$workspace_path/targets/hosts.txt"

    if [[ ! -f "$targets_file" ]]; then
        echo "[!] Error: Targets file not found"
        return 1
    fi

    # Remove target
    local temp_file=$(mktemp)
    grep -Fxv "$target" "$targets_file" > "$temp_file"
    mv "$temp_file" "$targets_file"

    echo "[+] Removed target: $target"
    return 0
}

# List targets in workspace
# Usage: workspace_list_targets [workspace_name]
workspace_list_targets() {
    local workspace_name="${1:-$CURRENT_WORKSPACE}"
    local workspace_path="$WORKSPACE_DIR/$workspace_name"
    local targets_file="$workspace_path/targets/hosts.txt"

    if [[ ! -f "$targets_file" ]]; then
        echo "No targets in workspace: $workspace_name"
        return 0
    fi

    echo ""
    echo "Targets in workspace: $workspace_name"
    echo "================================================================================"

    local count=1
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        printf "%4d  %s\n" "$count" "$target"
        ((count++))
    done < "$targets_file"

    echo "================================================================================"
    echo "Total: $((count-1)) targets"
    echo ""
}

# Import targets from file
# Usage: workspace_import_targets "file_path" [workspace_name]
workspace_import_targets() {
    local import_file="$1"
    local workspace_name="${2:-$CURRENT_WORKSPACE}"

    if [[ ! -f "$import_file" ]]; then
        echo "[!] Error: File not found: $import_file"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"
    local targets_file="$workspace_path/targets/hosts.txt"

    local count=0
    while IFS= read -r target; do
        # Skip empty lines and comments
        [[ -z "$target" || "$target" =~ ^# ]] && continue

        # Add target if not already exists
        if ! grep -Fxq "$target" "$targets_file" 2>/dev/null; then
            echo "$target" >> "$targets_file"
            ((count++))
        fi
    done < "$import_file"

    echo "[+] Imported $count targets from $import_file"
    return 0
}

# Export targets to file
# Usage: workspace_export_targets "file_path" [workspace_name]
workspace_export_targets() {
    local export_file="$1"
    local workspace_name="${2:-$CURRENT_WORKSPACE}"

    if [[ -z "$export_file" ]]; then
        echo "[!] Error: Export file path cannot be empty"
        return 1
    fi

    local workspace_path="$WORKSPACE_DIR/$workspace_name"
    local targets_file="$workspace_path/targets/hosts.txt"

    if [[ ! -f "$targets_file" ]]; then
        echo "[!] Error: No targets to export"
        return 1
    fi

    cp "$targets_file" "$export_file"

    echo "[+] Exported targets to: $export_file"
    return 0
}

# Get current workspace
# Usage: workspace_current
workspace_current() {
    echo "$CURRENT_WORKSPACE"
}

# Export functions
export -f workspace_init
export -f workspace_create
export -f workspace_delete
export -f workspace_switch
export -f workspace_list
export -f workspace_info
export -f workspace_add_target
export -f workspace_remove_target
export -f workspace_list_targets
export -f workspace_import_targets
export -f workspace_export_targets
export -f workspace_current
