#!/bin/bash
#
# Active Directory Target Management Module
#
# This module provides functions for managing AD targets including:
# - Listing, loading, saving, and deleting AD targets
# - Interactive selection and editing via fzf
# - Target database management
#
# Dependencies:
# - Global variables from config.sh (AD_TARGETS_DB, color codes, etc.)
# - fzf for interactive selection
#

# List AD targets from database
list_ad_targets() {
    if [[ ! -f "$AD_TARGETS_DB" ]]; then
        return 1
    fi
    grep -v '^#' "$AD_TARGETS_DB" | grep -v '^$'
}

# List AD target names
list_ad_target_names() {
    list_ad_targets | cut -d'|' -f1
}

# Load AD target
load_ad_target() {
    local name=$1
    local line=$(grep "^${name}|" "$AD_TARGETS_DB")
    if [[ -n "$line" ]]; then
        CURRENT_AD_TARGET_NAME="$name"
        AD_DOMAIN=$(echo "$line" | cut -d'|' -f2)
        AD_DC_NAME=$(echo "$line" | cut -d'|' -f3)
        AD_DC_IP=$(echo "$line" | cut -d'|' -f4)
        AD_ADDITIONAL_INFO=$(echo "$line" | cut -d'|' -f5)
        return 0
    fi
    return 1
}

# Save AD target
save_ad_target() {
    local name=$1
    local domain=$2
    local dc_name=$3
    local dc_ip=$4
    local additional_info=$5

    # Check if target already exists
    if grep -q "^${name}|" "$AD_TARGETS_DB" 2>/dev/null; then
        echo -e "${RED}AD target '$name' already exists!${NC}"
        return 1
    fi

    echo "${name}|${domain}|${dc_name}|${dc_ip}|${additional_info}" >> "$AD_TARGETS_DB"
    return 0
}

# Delete AD target
delete_ad_target() {
    local name=$1
    sed -i "/^${name}|/d" "$AD_TARGETS_DB"
}

# Select AD target
select_ad_target() {
    local ad_target_names=$(list_ad_target_names)
    if [[ -z "$ad_target_names" ]]; then
        echo -e "${YELLOW}No AD targets available. Add one first!${NC}"
        sleep 2
        return 1
    fi

    local choice=$(echo "$ad_target_names" | fzf --prompt="Select AD Target: " --height=50% --reverse --header="Current: $CURRENT_AD_TARGET_NAME")

    if [[ -n "$choice" ]]; then
        load_ad_target "$choice"
        echo -e "${GREEN}AD target switched to: $choice${NC}"
        sleep 1
    fi
}

# Add AD target
add_ad_target() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     ADD NEW ACTIVE DIRECTORY TARGET       ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    read -p "Target name (e.g., CorpDomain): " name
    read -p "Domain (e.g., corp.local): " domain
    read -p "Domain Controller name (e.g., DC01): " dc_name
    read -p "Domain Controller IP: " dc_ip
    read -p "Additional info (Domain SID, notes, etc.): " additional_info

    if [[ -z "$name" ]]; then
        echo -e "${RED}Name cannot be empty!${NC}"
        sleep 2
        return 1
    fi

    if save_ad_target "$name" "$domain" "$dc_name" "$dc_ip" "$additional_info"; then
        echo -e "${GREEN}AD target '$name' added!${NC}"
        load_ad_target "$name"
        sleep 2
    else
        sleep 2
        return 1
    fi
}

# Edit AD target
edit_ad_target() {
    local ad_target_names=$(list_ad_target_names)
    if [[ -z "$ad_target_names" ]]; then
        echo -e "${YELLOW}No AD targets to edit!${NC}"
        sleep 2
        return 1
    fi

    local choice=$(echo "$ad_target_names" | fzf --prompt="Select AD Target to Edit: " --height=50% --reverse)

    if [[ -z "$choice" ]]; then
        return 1
    fi

    # Load existing values
    load_ad_target "$choice"

    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     EDIT AD TARGET: $choice${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo "Press Enter to keep current value"
    echo ""

    read -p "Domain [$AD_DOMAIN]: " new_domain
    read -p "DC Name [$AD_DC_NAME]: " new_dc_name
    read -p "DC IP [$AD_DC_IP]: " new_dc_ip
    read -p "Additional Info [$AD_ADDITIONAL_INFO]: " new_additional_info

    # Use current values if empty
    [[ -z "$new_domain" ]] && new_domain="$AD_DOMAIN"
    [[ -z "$new_dc_name" ]] && new_dc_name="$AD_DC_NAME"
    [[ -z "$new_dc_ip" ]] && new_dc_ip="$AD_DC_IP"
    [[ -z "$new_additional_info" ]] && new_additional_info="$AD_ADDITIONAL_INFO"

    # Delete old entry and add new one
    delete_ad_target "$choice"
    save_ad_target "$choice" "$new_domain" "$new_dc_name" "$new_dc_ip" "$new_additional_info"
    load_ad_target "$choice"

    echo -e "${GREEN}AD target updated!${NC}"
    sleep 2
}

# Clear all AD targets
clear_all_ad_targets() {
    clear
    echo -e "${YELLOW}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║     CLEAR ALL AD TARGETS                  ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}WARNING: This will delete ALL Active Directory targets!${NC}"
    echo ""

    local target_count=$(list_ad_target_names | wc -l)
    echo -e "AD targets to be deleted: ${RED}$target_count${NC}"
    echo ""

    read -p "Type 'CLEAR' to confirm deletion: " confirm

    if [[ "$confirm" == "CLEAR" ]]; then
        # Reinitialize the database (empty)
        cat > "$AD_TARGETS_DB" << 'EOF'
# Active Directory Targets Database
# Format: NAME|DOMAIN|DC_NAME|DC_IP|ADDITIONAL_INFO
EOF
        chmod 600 "$AD_TARGETS_DB"

        # Clear current selection
        CURRENT_AD_TARGET_NAME=""
        AD_DOMAIN=""
        AD_DC_NAME=""
        AD_DC_IP=""
        AD_ADDITIONAL_INFO=""

        echo -e "\n${GREEN}✓ All AD targets cleared!${NC}"
        sleep 2
    else
        echo -e "\n${YELLOW}Cancelled.${NC}"
        sleep 2
    fi
}

# Manage AD targets menu
manage_ad_targets() {
    while true; do
        clear
        local choice=$(echo "Add AD Target
Edit AD Target
Delete AD Target
Select AD Target
List All AD Targets
Back" | fzf --prompt="Manage AD Targets: " --height=50% --reverse)

        case "$choice" in
            "Add AD Target")
                add_ad_target
                ;;
            "Edit AD Target")
                edit_ad_target
                ;;
            "Delete AD Target")
                local ad_target_names=$(list_ad_target_names)
                if [[ -z "$ad_target_names" ]]; then
                    echo -e "${YELLOW}No AD targets to delete!${NC}"
                    sleep 2
                    continue
                fi
                local to_delete=$(echo "$ad_target_names" | fzf --prompt="Select AD Target to Delete: " --height=50% --reverse)
                if [[ -n "$to_delete" ]]; then
                    delete_ad_target "$to_delete"
                    echo -e "${GREEN}AD target '$to_delete' deleted!${NC}"
                    if [[ "$CURRENT_AD_TARGET_NAME" == "$to_delete" ]]; then
                        CURRENT_AD_TARGET_NAME=""
                        AD_DOMAIN=""
                        AD_DC_NAME=""
                        AD_DC_IP=""
                        AD_ADDITIONAL_INFO=""
                    fi
                    sleep 2
                fi
                ;;
            "Select AD Target")
                select_ad_target
                ;;
            "List All AD Targets")
                clear
                echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
                echo -e "${BLUE}║     ALL AD TARGETS                        ║${NC}"
                echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
                echo ""
                if [[ -f "$AD_TARGETS_DB" ]]; then
                    list_ad_targets | while IFS='|' read -r name domain dc_name dc_ip additional_info; do
                        echo -e "${GREEN}$name${NC}"
                        echo -e "  Domain: ${CYAN}$domain${NC}"
                        echo -e "  DC Name: ${CYAN}$dc_name${NC}"
                        echo -e "  DC IP: ${CYAN}$dc_ip${NC}"
                        if [[ -n "$additional_info" ]]; then
                            echo -e "  Info: ${YELLOW}$additional_info${NC}"
                        fi
                        echo ""
                    done
                fi
                read -p "Press Enter to continue..."
                ;;
            "Back"|"")
                return 0
                ;;
        esac
    done
}
