#!/bin/bash

# targets.sh - Network Target Management Module
# This module provides functions for managing network targets including
# listing, loading, saving, selecting, and managing targets with interactive
# fzf prompts. These functions reference global variables from config.sh.

# List all target names
list_target_names() {
    grep -v "^#" "$TARGETS_DB" | grep -v "^$" | cut -d'|' -f1
}

# Get all targets
get_all_targets() {
    grep -v "^#" "$TARGETS_DB" | grep -v "^$" | cut -d'|' -f2
}

# Load target
load_target() {
    local name=$1
    local line=$(grep "^${name}|" "$TARGETS_DB")

    if [[ -n "$line" ]]; then
        CURRENT_TARGET_NAME="$name"
        TARGET=$(echo "$line" | cut -d'|' -f2)
    fi
}

# Save target
save_target() {
    local name=$1
    local target=$2

    sed -i "/^${name}|/d" "$TARGETS_DB"
    echo "${name}|${target}" >> "$TARGETS_DB"
}

# Delete target
delete_target() {
    local name=$1
    sed -i "/^${name}|/d" "$TARGETS_DB"
}

# Show target selector menu
select_target() {
    local target_names=$(list_target_names)

    if [[ -z "$target_names" ]]; then
        echo -e "${YELLOW}No targets configured. Add one first.${NC}"
        sleep 2
        return
    fi

    local choice=$(echo "$target_names" | fzf --prompt="Select Target: " --height=50% --reverse --header="Current: $CURRENT_TARGET_NAME")

    if [[ -n "$choice" ]]; then
        load_target "$choice"
        RUN_MODE="single"
    fi
}

# Toggle run mode
toggle_run_mode() {
    local target_count=$(list_target_names | wc -l)

    if [[ $target_count -eq 0 ]]; then
        echo -e "${YELLOW}No targets configured. Add targets first.${NC}"
        sleep 2
        return
    fi

    local choice=$(echo "Run on Current Target Only
Run on All Targets" | fzf --prompt="Select Run Mode: " --height=40% --reverse)

    case "$choice" in
        "Run on Current Target Only")
            RUN_MODE="single"
            ;;
        "Run on All Targets")
            RUN_MODE="all"
            ;;
    esac
}

# Add new target
add_target() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     ADD NEW TARGET                        ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    read -p "Target Name: " name

    if [[ -z "$name" ]]; then
        echo -e "${RED}Name cannot be empty!${NC}"
        sleep 2
        return
    fi

    read -p "IP Address/Range/Hostname: " target

    if [[ -z "$target" ]]; then
        echo -e "${RED}Target cannot be empty!${NC}"
        sleep 2
        return
    fi

    save_target "$name" "$target"

    echo -e "\n${GREEN}✓ Target '${name}' saved!${NC}"

    # Auto-select if this is the first target
    local count=$(list_target_names | wc -l)
    if [[ $count -eq 1 ]]; then
        load_target "$name"
        echo -e "${GREEN}✓ Automatically selected as current target${NC}"
    fi

    sleep 2
}

# Edit target
edit_target() {
    local target_names=$(list_target_names)

    if [[ -z "$target_names" ]]; then
        echo -e "${YELLOW}No targets to edit.${NC}"
        sleep 2
        return
    fi

    local choice=$(echo "$target_names" | fzf --prompt="Edit Target: " --height=50% --reverse)

    if [[ -n "$choice" ]]; then
        load_target "$choice"

        clear
        echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║     EDIT TARGET                           ║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
        echo -e "${CYAN}Editing: ${choice}${NC}"
        echo ""

        read -p "IP Address/Range/Hostname [$TARGET]: " new_target

        target=${new_target:-$TARGET}

        save_target "$choice" "$target"
        load_target "$choice"

        echo -e "\n${GREEN}✓ Target updated!${NC}"
        sleep 2
    fi
}

# Delete target
delete_target_entry() {
    local target_names=$(list_target_names)

    if [[ -z "$target_names" ]]; then
        echo -e "${YELLOW}No targets to delete.${NC}"
        sleep 2
        return
    fi

    local choice=$(echo "$target_names" | fzf --prompt="Delete Target: " --height=50% --reverse)

    if [[ -n "$choice" ]]; then
        read -p "Delete '${choice}'? (y/n): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            delete_target "$choice"
            echo -e "${GREEN}✓ Deleted!${NC}"
            if [[ "$choice" == "$CURRENT_TARGET_NAME" ]]; then
                CURRENT_TARGET_NAME=""
                TARGET=""
            fi
            sleep 2
        fi
    fi
}

# Manage targets menu
manage_targets() {
    while true; do
        clear
        echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║     TARGET MANAGEMENT                     ║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
        echo ""

        local choice=$(echo "Add New Target
Edit Target
Delete Target
Back to Main Menu" | fzf --prompt="Select Action: " --height=40% --reverse)

        case "$choice" in
            "Add New Target")
                add_target
                ;;
            "Edit Target")
                edit_target
                ;;
            "Delete Target")
                delete_target_entry
                ;;
            "Back to Main Menu"|"")
                return
                ;;
        esac
    done
}

# Get target for command
get_target_for_command() {
    if [[ "$RUN_MODE" == "all" ]]; then
        # Return all targets space-separated
        echo "$(get_all_targets | tr '\n' ' ')"
    else
        # Return current target
        if [[ -z "$TARGET" ]]; then
            echo -e "${RED}No target selected!${NC}" >&2
            read -p "Press Enter to continue..." >&2
            return 1
        fi
        echo "$TARGET"
    fi
}
