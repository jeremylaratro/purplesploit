#!/bin/bash
#
# FZF Integration - Interactive Menu System
# Part of PurpleSploit Framework
#
# Provides FZF-based interactive menus for module selection,
# target selection, credential selection, and more.
#

# Check if fzf is available
check_fzf() {
    if ! command -v fzf &> /dev/null; then
        echo "[!] Warning: fzf not found. Install for enhanced menu experience."
        echo "[*] Falling back to basic mode"
        return 1
    fi
    return 0
}

# Interactive module search with fzf
# Usage: fzf_module_search [initial_query]
fzf_module_search() {
    local initial_query="$1"

    if ! check_fzf; then
        # Fallback to regular search
        module_search "$initial_query"
        return $?
    fi

    # Build module list for fzf
    local module_list=""
    for module_name in "${MODULE_LIST[@]}"; do
        local description=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
        local category=$(module_get_field "$module_name" "MODULE_CATEGORY")
        module_list+="$module_name | $category | $description"$'\n'
    done

    # Use fzf for interactive selection
    local selected=$(echo "$module_list" | fzf \
        --prompt="Select Module> " \
        --header="Press ENTER to use module, ESC to cancel" \
        --preview='echo "Module: {1}" && echo "" && echo "Category: {3}" && echo "" && echo "Description: {5..}"' \
        --preview-window=up:30% \
        --height=80% \
        --reverse \
        --border \
        --query="$initial_query" \
        --delimiter=' | ' \
        --with-nth=1,3 \
        --bind='ctrl-/:toggle-preview')

    if [[ -n "$selected" ]]; then
        local module_name=$(echo "$selected" | awk -F ' | ' '{print $1}')
        module_use "$module_name"
        return 0
    fi

    return 1
}

# Interactive target selection with fzf
# Usage: fzf_target_select
fzf_target_select() {
    if ! check_fzf; then
        workspace_list_targets
        read -p "Enter target: " target
        var_set "RHOST" "$target"
        return 0
    fi

    # Get targets from current workspace
    local workspace_name=$(workspace_current)
    local workspace_path="$WORKSPACE_DIR/$workspace_name"
    local targets_file="$workspace_path/targets/hosts.txt"

    if [[ ! -f "$targets_file" ]] || [[ ! -s "$targets_file" ]]; then
        echo "[!] No targets in workspace. Add targets first."
        read -p "Enter target: " target
        if [[ -n "$target" ]]; then
            workspace_add_target "$target"
            var_set "RHOST" "$target"
        fi
        return 0
    fi

    # Use fzf for selection
    local selected=$(cat "$targets_file" | grep -v '^#' | grep -v '^$' | fzf \
        --prompt="Select Target> " \
        --header="Select target or press ESC to cancel" \
        --height=50% \
        --reverse \
        --border \
        --preview='echo "Target: {}" && echo "" && ping -c 1 -W 1 {} 2>&1 | grep -E "(time=|unreachable)"' \
        --preview-window=up:30%)

    if [[ -n "$selected" ]]; then
        var_set "RHOST" "$selected"
        echo "[+] Selected target: $selected"
        return 0
    fi

    return 1
}

# Interactive credential selection with fzf
# Usage: fzf_credential_select
fzf_credential_select() {
    if ! check_fzf; then
        credential_list_all
        read -p "Enter credential ID: " cred_id
        credential_load "$cred_id"
        return 0
    fi

    # Build credential list
    local cred_list=""
    local cred_count=0

    while IFS='|' read -r cred_id username password domain hash description; do
        [[ "$cred_id" == "id" ]] && continue  # Skip header
        [[ -z "$cred_id" ]] && continue

        local display_pass="<hidden>"
        [[ -n "$password" ]] && display_pass="***"
        [[ -z "$password" ]] && display_pass="<none>"

        local display_hash="<none>"
        [[ -n "$hash" ]] && display_hash="<hash>"

        local display_domain="<none>"
        [[ -n "$domain" ]] && display_domain="$domain"

        cred_list+="$cred_id | $username | $display_pass | $display_domain | $display_hash | $description"$'\n'
        ((cred_count++))
    done < "$CREDENTIALS_DB"

    if [[ $cred_count -eq 0 ]]; then
        echo "[!] No credentials stored. Add credentials first."
        return 1
    fi

    # Use fzf for selection
    local selected=$(echo "$cred_list" | fzf \
        --prompt="Select Credential> " \
        --header="ID | Username | Password | Domain | Hash | Description" \
        --header-lines=0 \
        --height=50% \
        --reverse \
        --border \
        --delimiter=' | ' \
        --with-nth=1,2,4,6)

    if [[ -n "$selected" ]]; then
        local cred_id=$(echo "$selected" | awk -F ' | ' '{print $1}')
        credential_load "$cred_id"
        return 0
    fi

    return 1
}

# Interactive workspace selection with fzf
# Usage: fzf_workspace_select
fzf_workspace_select() {
    if ! check_fzf; then
        workspace_list
        read -p "Enter workspace name: " ws_name
        workspace_switch "$ws_name"
        return 0
    fi

    # Build workspace list
    local ws_list=""
    for workspace_path in "$WORKSPACE_DIR"/*; do
        if [[ -d "$workspace_path" ]]; then
            local workspace_name=$(basename "$workspace_path")
            local target_count=$(wc -l < "$workspace_path/targets/hosts.txt" 2>/dev/null || echo "0")
            local current=""
            [[ "$workspace_name" == "$CURRENT_WORKSPACE" ]] && current="[CURRENT]"

            ws_list+="$workspace_name | $target_count targets | $current"$'\n'
        fi
    done

    # Use fzf for selection
    local selected=$(echo "$ws_list" | fzf \
        --prompt="Select Workspace> " \
        --header="Workspace | Targets | Status" \
        --height=50% \
        --reverse \
        --border \
        --delimiter=' | ')

    if [[ -n "$selected" ]]; then
        local ws_name=$(echo "$selected" | awk -F ' | ' '{print $1}')
        workspace_switch "$ws_name"
        return 0
    fi

    return 1
}

# Interactive command from history with fzf
# Usage: fzf_history_select
fzf_history_select() {
    if ! check_fzf; then
        command_history_show
        return 1
    fi

    if [[ ${#COMMAND_HISTORY[@]} -eq 0 ]]; then
        echo "[!] No command history"
        return 1
    fi

    # Build history list
    local history_list=""
    for ((i=${#COMMAND_HISTORY[@]}-1; i>=0; i--)); do
        history_list+="$((i+1)) | ${COMMAND_HISTORY[$i]}"$'\n'
    done

    # Use fzf for selection
    local selected=$(echo "$history_list" | fzf \
        --prompt="Select Command from History> " \
        --header="Select command to re-run (ESC to cancel)" \
        --height=50% \
        --reverse \
        --border \
        --preview='echo "Command: {2..}"' \
        --preview-window=up:20%)

    if [[ -n "$selected" ]]; then
        local command=$(echo "$selected" | cut -d'|' -f2- | xargs)
        echo ""
        echo -e "${CYAN}Selected command:${NC}"
        echo "$command"
        echo ""
        read -p "Execute this command? [y/N]: " confirm

        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            eval "$command"
        fi
        return 0
    fi

    return 1
}

# Show variables with fzf for quick editing
# Usage: fzf_variable_select
fzf_variable_select() {
    if ! check_fzf; then
        var_show_all
        return 1
    fi

    # Build variable list
    local var_list=""
    local sorted_vars=($(for key in "${!GLOBAL_VARS[@]}"; do echo "$key"; done | sort))

    for var_name in "${sorted_vars[@]}"; do
        local var_value="${GLOBAL_VARS[$var_name]}"
        local var_desc="${VAR_DESCRIPTIONS[$var_name]:-No description}"

        [[ -z "$var_value" ]] && var_value="<not set>"

        var_list+="$var_name | $var_value | $var_desc"$'\n'
    done

    # Use fzf for selection
    local selected=$(echo "$var_list" | fzf \
        --prompt="Select Variable to Edit> " \
        --header="Variable | Current Value | Description" \
        --height=60% \
        --reverse \
        --border \
        --preview='echo "Variable: {1}" && echo "Current: {3}" && echo "" && echo "Description: {5..}"' \
        --preview-window=up:30%)

    if [[ -n "$selected" ]]; then
        local var_name=$(echo "$selected" | awk -F ' | ' '{print $1}')
        local current_value=$(echo "$selected" | awk -F ' | ' '{print $2}')

        [[ "$current_value" == "<not set>" ]] && current_value=""

        echo ""
        read -e -i "$current_value" -p "Set $var_name: " new_value

        if [[ -n "$new_value" ]]; then
            var_set "$var_name" "$new_value"
        fi
        return 0
    fi

    return 1
}

# Interactive category browser with fzf
# Usage: fzf_category_browse
fzf_category_browse() {
    if ! check_fzf; then
        module_list_by_category
        return 1
    fi

    # Get unique categories
    local -A categories
    local cat_list=""

    for module_name in "${MODULE_LIST[@]}"; do
        local cat=$(module_get_field "$module_name" "MODULE_CATEGORY")
        if [[ ! -v "categories[$cat]" ]]; then
            categories[$cat]=1
            local count=0
            for mod in "${MODULE_LIST[@]}"; do
                [[ "$(module_get_field "$mod" "MODULE_CATEGORY")" == "$cat" ]] && ((count++))
            done
            cat_list+="$cat | $count modules"$'\n'
        fi
    done

    # Select category
    local selected_cat=$(echo "$cat_list" | fzf \
        --prompt="Select Category> " \
        --header="Browse modules by category" \
        --height=50% \
        --reverse \
        --border)

    if [[ -n "$selected_cat" ]]; then
        local category=$(echo "$selected_cat" | awk -F ' | ' '{print $1}')

        # Now show modules in that category
        local module_list=""
        for module_name in "${MODULE_LIST[@]}"; do
            local cat=$(module_get_field "$module_name" "MODULE_CATEGORY")
            if [[ "$cat" == "$category" ]]; then
                local description=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
                module_list+="$module_name | $description"$'\n'
            fi
        done

        local selected_module=$(echo "$module_list" | fzf \
            --prompt="Select Module from $category> " \
            --header="Module | Description" \
            --height=50% \
            --reverse \
            --border \
            --preview='echo "Module: {1}"')

        if [[ -n "$selected_module" ]]; then
            local module_name=$(echo "$selected_module" | awk -F ' | ' '{print $1}')
            module_use "$module_name"
            return 0
        fi
    fi

    return 1
}

# Export functions
export -f check_fzf
export -f fzf_module_search
export -f fzf_target_select
export -f fzf_credential_select
export -f fzf_workspace_select
export -f fzf_history_select
export -f fzf_variable_select
export -f fzf_category_browse
