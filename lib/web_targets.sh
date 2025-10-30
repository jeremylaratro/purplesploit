#!/bin/bash

# web_targets.sh - Web Target Management Module
# This module provides functions for managing web targets including
# listing, loading, selecting, and managing web targets with interactive
# fzf prompts. These functions reference global variables from config.sh.

# List all web targets
list_web_targets() {
    if [[ ! -f "$WEB_TARGETS_DB" ]]; then
        return 1
    fi
    grep -v '^#' "$WEB_TARGETS_DB" | grep -v '^$'
}

# List web target names
list_web_target_names() {
    list_web_targets | cut -d'|' -f1
}

# Add web target
add_web_target() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     ADD NEW WEB TARGET                    ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    read -p "Target name: " name
    read -p "URL (e.g., https://example.com): " url

    if [[ -z "$name" ]] || [[ -z "$url" ]]; then
        echo -e "${RED}Name and URL cannot be empty!${NC}"
        sleep 2
        return 1
    fi

    echo "$name|$url" >> "$WEB_TARGETS_DB"
    echo -e "${GREEN}Web target '$name' added!${NC}"
    sleep 2
}

# Load web target
load_web_target() {
    local name="$1"
    local entry=$(list_web_targets | grep "^$name|")

    if [[ -z "$entry" ]]; then
        return 1
    fi

    CURRENT_WEB_TARGET="$name"
    WEB_TARGET_URL=$(echo "$entry" | cut -d'|' -f2)
}

# Select web target
select_web_target() {
    local web_target_names=$(list_web_target_names)

    if [[ -z "$web_target_names" ]]; then
        echo -e "${YELLOW}No web targets configured. Add one first.${NC}"
        sleep 2
        return
    fi

    local choice=$(echo "$web_target_names" | fzf --prompt="Select Web Target: " --height=50% --reverse --header="Current: $CURRENT_WEB_TARGET")

    if [[ -n "$choice" ]]; then
        load_web_target "$choice"
    fi
}

# Get web target URL
get_web_target_url() {
    if [[ -z "$CURRENT_WEB_TARGET" ]]; then
        echo -e "${YELLOW}No web target selected.${NC}" >&2
        local choice=$(echo "Select from Database
Enter Manually
Cancel" | fzf --prompt="How to provide URL: " --height=40% --reverse)

        case "$choice" in
            "Select from Database")
                select_web_target
                if [[ -z "$CURRENT_WEB_TARGET" ]]; then
                    return 1
                fi
                echo "$WEB_TARGET_URL"
                return 0
                ;;
            "Enter Manually")
                read -p "Enter URL: " manual_url
                if [[ -z "$manual_url" ]]; then
                    return 1
                fi
                echo "$manual_url"
                return 0
                ;;
            *)
                return 1
                ;;
        esac
    fi

    echo "$WEB_TARGET_URL"
}

# Clear all web targets
clear_all_web_targets() {
    clear
    echo -e "${YELLOW}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║     CLEAR ALL WEB TARGETS                 ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}WARNING: This will delete ALL web targets!${NC}"
    echo ""

    local target_count=$(list_web_target_names | wc -l)
    echo -e "Web targets to be deleted: ${RED}$target_count${NC}"
    echo ""

    read -p "Type 'CLEAR' to confirm deletion: " confirm

    if [[ "$confirm" == "CLEAR" ]]; then
        # Reinitialize the database (empty)
        cat > "$WEB_TARGETS_DB" << 'EOF'
# Web Targets Database
# Format: NAME|URL
EOF
        chmod 600 "$WEB_TARGETS_DB"

        # Clear current selection
        CURRENT_WEB_TARGET=""
        WEB_TARGET_URL=""

        echo -e "\n${GREEN}✓ All web targets cleared!${NC}"
        sleep 2
    else
        echo -e "\n${YELLOW}Cancelled.${NC}"
        sleep 2
    fi
}

# Manage web targets menu
manage_web_targets() {
    while true; do
        clear
        echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║     WEB TARGET MANAGEMENT                 ║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
        echo ""

        local choice=$(echo "Add New Web Target
Select Web Target
List Web Targets
Delete Web Target
Back to Main Menu" | fzf --prompt="Select Action: " --height=40% --reverse)

        case "$choice" in
            "Add New Web Target")
                add_web_target
                ;;
            "Select Web Target")
                select_web_target
                ;;
            "List Web Targets")
                clear
                echo -e "${CYAN}=== Web Targets ===${NC}\n"
                list_web_targets | column -t -s'|' || echo "No web targets found"
                echo ""
                read -p "Press Enter to continue..."
                ;;
            "Delete Web Target")
                local web_target_names=$(list_web_target_names)
                if [[ -z "$web_target_names" ]]; then
                    echo -e "${YELLOW}No web targets to delete.${NC}"
                    sleep 2
                else
                    local target_choice=$(echo "$web_target_names" | fzf --prompt="Delete Web Target: " --height=50% --reverse)
                    if [[ -n "$target_choice" ]]; then
                        read -p "Delete '$target_choice'? (y/n): " confirm
                        if [[ "$confirm" == "y" ]]; then
                            sed -i "/^${target_choice}|/d" "$WEB_TARGETS_DB"
                            echo -e "${GREEN}✓ Deleted!${NC}"
                            if [[ "$target_choice" == "$CURRENT_WEB_TARGET" ]]; then
                                CURRENT_WEB_TARGET=""
                                WEB_TARGET_URL=""
                            fi
                            sleep 2
                        fi
                    fi
                fi
                ;;
            "Back to Main Menu"|"")
                return
                ;;
        esac
    done
}
