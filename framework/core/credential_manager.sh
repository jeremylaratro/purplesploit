#!/bin/bash
#
# CredentialManager - Multi-Credential Storage and Management
# Part of PurpleSploit Framework
#
# Manages multiple credential sets with database storage
# and interactive selection via FZF
#

# Credential database
CREDENTIALS_DB="$HOME/.purplesploit/credentials.db"

# Initialize credential database
credential_init() {
    # Create database directory
    mkdir -p "$(dirname "$CREDENTIALS_DB")"

    # Create database if it doesn't exist
    if [[ ! -f "$CREDENTIALS_DB" ]]; then
        cat > "$CREDENTIALS_DB" <<EOF
# PurpleSploit Credential Database
# Format: id|username|password|domain|hash|description
1|''|''||''|Null Authentication (empty credentials)
2|guest|''||''|Guest Account
3|Administrator|''||''|Administrator (no password)
EOF
    fi
}

# Add credential to database
# Usage: credential_add <username> <password> <domain> <hash> <description>
credential_add() {
    local username="$1"
    local password="$2"
    local domain="$3"
    local hash="$4"
    local description="$5"

    # Get next ID
    local next_id=1
    if [[ -f "$CREDENTIALS_DB" ]]; then
        local last_id=$(grep -v '^#' "$CREDENTIALS_DB" | tail -1 | cut -d'|' -f1)
        [[ -n "$last_id" ]] && next_id=$((last_id + 1))
    fi

    # Add to database
    echo "${next_id}|${username}|${password}|${domain}|${hash}|${description}" >> "$CREDENTIALS_DB"

    echo "[+] Added credential ID $next_id: $username"
    return 0
}

# Interactive credential addition
# Usage: credential_add_interactive
credential_add_interactive() {
    echo ""
    echo "Add New Credential"
    echo "================================================================================"

    read -p "Username: " username
    read -s -p "Password (leave empty for null/hash auth): " password
    echo ""
    read -p "Domain (optional): " domain
    read -p "Hash (NTLM hash, optional): " hash
    read -p "Description: " description

    credential_add "$username" "$password" "$domain" "$hash" "$description"
}

# Load credential into environment variables
# Usage: credential_load <id>
credential_load() {
    local cred_id="$1"

    if [[ -z "$cred_id" ]]; then
        echo "[!] Error: Credential ID required"
        return 1
    fi

    # Find credential in database
    local cred_line=$(grep "^${cred_id}|" "$CREDENTIALS_DB")

    if [[ -z "$cred_line" ]]; then
        echo "[!] Error: Credential ID $cred_id not found"
        return 1
    fi

    # Parse credential
    IFS='|' read -r id username password domain hash description <<< "$cred_line"

    # Set variables
    var_set "USERNAME" "$username"
    var_set "PASSWORD" "$password"
    var_set "DOMAIN" "$domain"
    var_set "HASH" "$hash"

    echo "[+] Loaded credential: $username${domain:+@$domain}"
    [[ -n "$description" ]] && echo "[*] Description: $description"

    return 0
}

# List all credentials
# Usage: credential_list_all
credential_list_all() {
    echo ""
    echo "Stored Credentials:"
    echo "================================================================================"
    printf "%-5s %-20s %-15s %-15s %-10s %s\n" "ID" "Username" "Password" "Domain" "Hash" "Description"
    echo "--------------------------------------------------------------------------------"

    while IFS='|' read -r id username password domain hash description; do
        # Skip comments and empty lines
        [[ "$id" =~ ^#.* ]] && continue
        [[ -z "$id" ]] && continue

        # Display passwords as masked
        local display_pass="<none>"
        [[ -n "$password" ]] && [[ "$password" != "''" ]] && display_pass="***"

        local display_hash="<none>"
        [[ -n "$hash" ]] && [[ "$hash" != "''" ]] && display_hash="yes"

        local display_domain="<none>"
        [[ -n "$domain" ]] && [[ "$domain" != "" ]] && display_domain="$domain"

        printf "%-5s %-20s %-15s %-15s %-10s %s\n" "$id" "$username" "$display_pass" "$display_domain" "$display_hash" "$description"
    done < "$CREDENTIALS_DB"

    echo "================================================================================"
    echo ""
}

# Delete credential
# Usage: credential_delete <id>
credential_delete() {
    local cred_id="$1"

    if [[ -z "$cred_id" ]]; then
        echo "[!] Error: Credential ID required"
        return 1
    fi

    # Check if credential exists
    if ! grep -q "^${cred_id}|" "$CREDENTIALS_DB"; then
        echo "[!] Error: Credential ID $cred_id not found"
        return 1
    fi

    # Confirm deletion
    read -p "Delete credential ID $cred_id? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Cancelled."
        return 0
    fi

    # Remove from database
    local temp_file=$(mktemp)
    grep -v "^${cred_id}|" "$CREDENTIALS_DB" > "$temp_file"
    mv "$temp_file" "$CREDENTIALS_DB"

    echo "[+] Deleted credential ID $cred_id"
    return 0
}

# Edit credential
# Usage: credential_edit <id>
credential_edit() {
    local cred_id="$1"

    if [[ -z "$cred_id" ]]; then
        echo "[!] Error: Credential ID required"
        return 1
    fi

    # Find credential in database
    local cred_line=$(grep "^${cred_id}|" "$CREDENTIALS_DB")

    if [[ -z "$cred_line" ]]; then
        echo "[!] Error: Credential ID $cred_id not found"
        return 1
    fi

    # Parse current values
    IFS='|' read -r id username password domain hash description <<< "$cred_line"

    echo ""
    echo "Edit Credential ID $cred_id"
    echo "================================================================================"

    read -e -i "$username" -p "Username: " new_username
    read -e -i "$password" -p "Password: " new_password
    read -e -i "$domain" -p "Domain: " new_domain
    read -e -i "$hash" -p "Hash: " new_hash
    read -e -i "$description" -p "Description: " new_description

    # Update database
    local temp_file=$(mktemp)
    while IFS='|' read -r line_id rest; do
        if [[ "$line_id" == "$cred_id" ]]; then
            echo "${cred_id}|${new_username}|${new_password}|${new_domain}|${new_hash}|${new_description}"
        else
            echo "${line_id}|${rest}"
        fi
    done < "$CREDENTIALS_DB" > "$temp_file"
    mv "$temp_file" "$CREDENTIALS_DB"

    echo "[+] Updated credential ID $cred_id"
    return 0
}

# Interactive credential management menu
# Usage: credential_manage
credential_manage() {
    while true; do
        echo ""
        echo "Credential Management"
        echo "================================================================================"
        echo "  1) List all credentials"
        echo "  2) Add credential"
        echo "  3) Load credential (set in environment)"
        echo "  4) Edit credential"
        echo "  5) Delete credential"
        echo "  6) Back to main menu"
        echo ""
        read -p "Choice: " choice

        case "$choice" in
            1)
                credential_list_all
                read -p "Press Enter to continue..."
                ;;
            2)
                credential_add_interactive
                ;;
            3)
                credential_list_all
                read -p "Enter credential ID to load: " cred_id
                credential_load "$cred_id"
                ;;
            4)
                credential_list_all
                read -p "Enter credential ID to edit: " cred_id
                credential_edit "$cred_id"
                ;;
            5)
                credential_list_all
                read -p "Enter credential ID to delete: " cred_id
                credential_delete "$cred_id"
                ;;
            6|"")
                break
                ;;
            *)
                echo "[!] Invalid choice"
                ;;
        esac
    done
}

# Build authentication string for NXC/Impacket
# Usage: credential_build_auth_string
credential_build_auth_string() {
    local username=$(var_get "USERNAME" 2>/dev/null)
    local password=$(var_get "PASSWORD" 2>/dev/null)
    local domain=$(var_get "DOMAIN" 2>/dev/null)
    local hash=$(var_get "HASH" 2>/dev/null)

    local auth_string=""

    # Username
    if [[ -n "$username" ]]; then
        auth_string="-u '$username'"
    fi

    # Password or hash
    if [[ -n "$hash" && "$hash" != "''" ]]; then
        auth_string="$auth_string -H '$hash'"
    elif [[ -n "$password" ]]; then
        auth_string="$auth_string -p '$password'"
    else
        auth_string="$auth_string -p ''"
    fi

    # Domain
    if [[ -n "$domain" && "$domain" != "" ]]; then
        auth_string="$auth_string -d '$domain'"
    fi

    echo "$auth_string"
}

# Import credentials from file
# Format: username:password:domain:hash:description
# Usage: credential_import <file>
credential_import() {
    local import_file="$1"

    if [[ ! -f "$import_file" ]]; then
        echo "[!] Error: File not found: $import_file"
        return 1
    fi

    local count=0
    while IFS=':' read -r username password domain hash description; do
        # Skip comments and empty lines
        [[ "$username" =~ ^#.* ]] && continue
        [[ -z "$username" ]] && continue

        credential_add "$username" "$password" "$domain" "$hash" "$description"
        ((count++))
    done < "$import_file"

    echo "[+] Imported $count credentials"
    return 0
}

# Export credentials to file
# Usage: credential_export <file>
credential_export() {
    local export_file="$1"

    if [[ -z "$export_file" ]]; then
        echo "[!] Error: Output file required"
        return 1
    fi

    {
        echo "# PurpleSploit Credential Export"
        echo "# Format: username:password:domain:hash:description"
        echo ""

        while IFS='|' read -r id username password domain hash description; do
            [[ "$id" =~ ^#.* ]] && continue
            [[ -z "$id" ]] && continue

            echo "${username}:${password}:${domain}:${hash}:${description}"
        done < "$CREDENTIALS_DB"
    } > "$export_file"

    echo "[+] Exported credentials to: $export_file"
    return 0
}

# Export functions
export -f credential_init
export -f credential_add
export -f credential_add_interactive
export -f credential_load
export -f credential_list_all
export -f credential_delete
export -f credential_edit
export -f credential_manage
export -f credential_build_auth_string
export -f credential_import
export -f credential_export
