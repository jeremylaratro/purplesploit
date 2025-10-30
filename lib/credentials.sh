#!/bin/bash
#
# Credential Management Module
# Handles all credential operations for the penetration testing framework
#
# This module expects the following global variables to be set:
# - CREDS_DB: Path to credentials database file
# - CURRENT_CRED_NAME: Currently selected credential set name
# - USERNAME, PASSWORD, DOMAIN, HASH: Current credential values
# - RED, GREEN, YELLOW, BLUE, CYAN, NC: Color codes
#

# List all credential set names
list_cred_names() {
    grep -v "^#" "$CREDS_DB" | grep -v "^$" | cut -d'|' -f1
}

# Load credential set by name
# Usage: load_creds <name>
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

# Save credential set
# Usage: save_creds <name> <username> <password> <domain> <hash>
save_creds() {
    local name=$1
    local username=$2
    local password=$3
    local domain=$4
    local hash=$5

    sed -i "/^${name}|/d" "$CREDS_DB"
    echo "${name}|${username}|${password}|${domain}|${hash}" >> "$CREDS_DB"
}

# Delete credential set
# Usage: delete_creds <name>
delete_creds() {
    local name=$1
    sed -i "/^${name}|/d" "$CREDS_DB"
}

# Show credential selector menu with fzf
select_credentials() {
    local cred_names=$(list_cred_names)
    local choice=$(echo "$cred_names" | fzf --prompt="Select Credentials: " --height=50% --reverse --header="Current: $CURRENT_CRED_NAME")

    if [[ -n "$choice" ]]; then
        load_creds "$choice"
    fi
}

# Add new credential set interactively
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

# Edit existing credential set
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

# Delete credential set with confirmation
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

# Clear all credentials except defaults
clear_all_credentials() {
    clear
    echo -e "${YELLOW}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║     CLEAR ALL CREDENTIALS                 ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}WARNING: This will delete ALL custom credential sets!${NC}"
    echo -e "${CYAN}Default credentials (Null Auth, Guest Account) will be preserved.${NC}"
    echo ""

    local custom_count=$(list_cred_names | grep -v "^Null Auth$" | grep -v "^Guest Account$" | wc -l)
    echo -e "Custom credential sets to be deleted: ${RED}$custom_count${NC}"
    echo ""

    read -p "Type 'CLEAR' to confirm deletion: " confirm

    if [[ "$confirm" == "CLEAR" ]]; then
        # Reinitialize the database (keeps only default entries)
        cat > "$CREDS_DB" << 'EOF'
# NXC Credentials Database
# Format: NAME|USERNAME|PASSWORD|DOMAIN|HASH
Null Auth|''|''||
Guest Account|guest|''||
EOF
        chmod 600 "$CREDS_DB"

        # Reset to default
        load_creds "Null Auth"

        echo -e "\n${GREEN}✓ All custom credentials cleared!${NC}"
        sleep 2
    else
        echo -e "\n${YELLOW}Cancelled.${NC}"
        sleep 2
    fi
}

# Credential management menu
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

# Build NXC authentication string from current credentials
# Returns: Authentication string for NXC commands (e.g., "-u username -p password")
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
