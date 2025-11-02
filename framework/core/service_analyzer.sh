#!/bin/bash
#
# ServiceAnalyzer - Intelligent Service Detection and Analysis
# Part of PurpleSploit Framework
#
# Analyzes nmap scan results and tracks detected services per target
# Enables "search relevant" to show only modules for detected services
#

# Service database per workspace
SERVICE_DB=""

# Initialize service analyzer
service_analyzer_init() {
    local workspace_name=$(workspace_current)
    local workspace_path="$WORKSPACE_DIR/$workspace_name"
    SERVICE_DB="$workspace_path/services.db"

    # Create services database if it doesn't exist
    if [[ ! -f "$SERVICE_DB" ]]; then
        mkdir -p "$(dirname "$SERVICE_DB")"
        cat > "$SERVICE_DB" <<EOF
# PurpleSploit Service Database
# Format: target|port|protocol|service|version|state
# This file is auto-populated from nmap scans
EOF
    fi
}

# Parse nmap output and extract services
# Usage: service_parse_nmap <nmap_output_file> <target>
service_parse_nmap() {
    local nmap_file="$1"
    local target="$2"

    if [[ ! -f "$nmap_file" ]]; then
        echo "[!] Error: Nmap output file not found: $nmap_file"
        return 1
    fi

    echo "[*] Analyzing nmap results for $target..."

    # Parse nmap output (supports both XML and grep output)
    local services_found=0

    # Try XML parsing first
    if [[ "$nmap_file" == *.xml ]]; then
        # Parse XML with xmllint or grep
        if command -v xmllint &>/dev/null; then
            # Use xmllint for proper XML parsing
            xmllint --xpath "//port[@protocol='tcp' or @protocol='udp']" "$nmap_file" 2>/dev/null | \
            grep -oP 'portid="\K[^"]+|protocol="\K[^"]+|state="\K[^"]+|name="\K[^"]+|product="\K[^"]+|version="\K[^"]+' | \
            while read -r line; do
                # Process XML data
                echo "$line"
            done
        else
            # Fallback to grep-based parsing
            grep -oP '(?<=<port protocol=")[^"]+|(?<=portid=")[^"]+|(?<=<state state=")[^"]+|(?<=<service name=")[^"]+' "$nmap_file" | \
            paste -d'|' - - - - 2>/dev/null
        fi
    fi

    # Parse grep/text output
    if grep -qE '^[0-9]+/(tcp|udp)' "$nmap_file" 2>/dev/null; then
        while IFS= read -r line; do
            # Example line: 445/tcp   open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds
            if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+([a-z]+)[[:space:]]+([a-z0-9_-]+)(.*)$ ]]; then
                local port="${BASH_REMATCH[1]}"
                local protocol="${BASH_REMATCH[2]}"
                local state="${BASH_REMATCH[3]}"
                local service="${BASH_REMATCH[4]}"
                local version="${BASH_REMATCH[5]}"

                # Clean up version info
                version=$(echo "$version" | xargs | sed 's/|/;/g')

                # Only store open ports
                if [[ "$state" == "open" ]]; then
                    # Add to database
                    echo "$target|$port|$protocol|$service|$version|$state" >> "$SERVICE_DB"
                    ((services_found++))
                fi
            fi
        done < "$nmap_file"
    fi

    # Deduplicate entries
    if [[ -f "$SERVICE_DB" ]]; then
        local temp_file=$(mktemp)
        sort -u "$SERVICE_DB" > "$temp_file"
        mv "$temp_file" "$SERVICE_DB"
    fi

    echo "[+] Found $services_found open services on $target"
    return 0
}

# Detect services from nmap grep output (common format)
# Usage: service_detect_from_output <output_text> <target>
service_detect_from_output() {
    local output="$1"
    local target="$2"

    echo "$output" | grep -E '^[0-9]+/(tcp|udp)' | while IFS= read -r line; do
        if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+([a-z]+)[[:space:]]+([a-z0-9_-]+)(.*)$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local protocol="${BASH_REMATCH[2]}"
            local state="${BASH_REMATCH[3]}"
            local service="${BASH_REMATCH[4]}"
            local version="${BASH_REMATCH[5]}"

            version=$(echo "$version" | xargs | sed 's/|/;/g')

            if [[ "$state" == "open" ]]; then
                echo "$target|$port|$protocol|$service|$version|$state" >> "$SERVICE_DB"
            fi
        fi
    done

    # Deduplicate
    if [[ -f "$SERVICE_DB" ]]; then
        local temp_file=$(mktemp)
        sort -u "$SERVICE_DB" > "$temp_file"
        mv "$temp_file" "$SERVICE_DB"
    fi
}

# Get all detected services for a target
# Usage: service_get_for_target <target>
service_get_for_target() {
    local target="$1"

    if [[ ! -f "$SERVICE_DB" ]]; then
        return 1
    fi

    grep "^${target}|" "$SERVICE_DB" | grep -v '^#'
}

# Get all unique services across all targets
# Usage: service_get_all_unique
service_get_all_unique() {
    if [[ ! -f "$SERVICE_DB" ]]; then
        return 1
    fi

    # Extract service names (4th field)
    awk -F'|' '{print $4}' "$SERVICE_DB" | grep -v '^#' | sort -u
}

# Map service names to module categories
# Usage: service_to_module_category <service_name>
service_to_module_category() {
    local service="$1"

    # Service to category mapping
    case "$service" in
        # SMB Services
        microsoft-ds|netbios-ssn|smb|cifs)
            echo "smb"
            ;;

        # Web Services
        http|https|http-proxy|ssl|http-alt|https-alt|http-mgmt|ssl-http)
            echo "web"
            ;;

        # LDAP Services
        ldap|ldaps|ldap-ssl)
            echo "ldap"
            ;;

        # WinRM Services
        winrm|wsman|ms-wbt-server)
            echo "winrm"
            ;;

        # RDP Services
        rdp|ms-wbt-server|ms-term-serv)
            echo "rdp"
            ;;

        # SSH Services
        ssh)
            echo "ssh"
            ;;

        # MSSQL Services
        ms-sql|ms-sql-s|ms-sql-m|mssql)
            echo "mssql"
            ;;

        # MySQL Services
        mysql|mysql-proxy)
            echo "mysql"
            ;;

        # PostgreSQL Services
        postgresql|postgres)
            echo "postgresql"
            ;;

        # FTP Services
        ftp|ftp-data|ftps)
            echo "ftp"
            ;;

        # DNS Services
        domain|dns)
            echo "dns"
            ;;

        # Kerberos Services
        kerberos|kerberos-sec|kdc)
            echo "kerberos"
            ;;

        *)
            echo "other"
            ;;
    esac
}

# Get relevant module categories based on detected services
# Usage: service_get_relevant_categories
service_get_relevant_categories() {
    local categories=()

    if [[ ! -f "$SERVICE_DB" ]]; then
        return 1
    fi

    # Get all unique services
    local services=$(service_get_all_unique)

    # Map to categories
    while IFS= read -r service; do
        [[ -z "$service" ]] && continue
        local category=$(service_to_module_category "$service")
        [[ "$category" != "other" ]] && categories+=("$category")
    done <<< "$services"

    # Return unique categories
    printf '%s\n' "${categories[@]}" | sort -u
}

# Search modules relevant to detected services
# Usage: service_search_relevant
service_search_relevant() {
    local relevant_categories=$(service_get_relevant_categories)

    if [[ -z "$relevant_categories" ]]; then
        echo "[!] No services detected yet."
        echo "[*] Run an nmap scan first to detect services"
        echo "[*] Example: use recon/nmap/quick_scan"
        return 1
    fi

    echo ""
    echo "Detected Services:"
    echo "================================================================================"
    service_list_detected
    echo ""

    echo "Relevant Module Categories:"
    echo "================================================================================"
    echo "$relevant_categories" | while read -r cat; do
        echo "  - $cat"
    done
    echo ""

    # Build list of relevant modules
    local relevant_modules=""

    for module_name in "${MODULE_LIST[@]}"; do
        local module_desc=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
        local module_tool=$(module_get_field "$module_name" "MODULE_TOOL")

        # Check if module matches any relevant category
        echo "$relevant_categories" | while read -r category; do
            [[ -z "$category" ]] && continue

            # Check if module name or description contains the category
            if [[ "$module_name" == *"$category"* ]] || \
               [[ "$module_desc" =~ $category ]] || \
               [[ "$module_tool" =~ $category ]]; then
                echo "$module_name|$module_desc"
            fi
        done
    done | sort -u

    return 0
}

# FZF-based relevant module search
# Usage: service_search_relevant_fzf
service_search_relevant_fzf() {
    local relevant_categories=$(service_get_relevant_categories)

    if [[ -z "$relevant_categories" ]]; then
        echo "[!] No services detected yet."
        echo "[*] Run an nmap scan first: use recon/nmap/quick_scan"
        return 1
    fi

    # Build list of relevant modules
    local relevant_list=""
    local count=0

    for module_name in "${MODULE_LIST[@]}"; do
        local module_desc=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
        local module_category=$(module_get_field "$module_name" "MODULE_CATEGORY")
        local module_tool=$(module_get_field "$module_name" "MODULE_TOOL")

        # Check if module matches any relevant category
        local is_relevant=false
        while IFS= read -r category; do
            [[ -z "$category" ]] && continue

            if [[ "$module_name" == *"$category"* ]] || \
               [[ "$module_desc" =~ $category ]] || \
               [[ "$module_tool" =~ $category ]] || \
               [[ "$module_name" =~ $category ]]; then
                is_relevant=true
                break
            fi
        done <<< "$relevant_categories"

        if [[ "$is_relevant" == true ]]; then
            relevant_list+="$module_name | $module_category | $module_desc"$'\n'
            ((count++))
        fi
    done

    if [[ $count -eq 0 ]]; then
        echo "[!] No relevant modules found for detected services"
        return 1
    fi

    echo "[*] Found $count relevant modules based on detected services"

    # Use FZF if available
    if check_fzf; then
        local selected=$(echo "$relevant_list" | fzf \
            --prompt="Select Relevant Module> " \
            --header="Modules relevant to detected services (detected: $(echo "$relevant_categories" | tr '\n' ',' | sed 's/,$//'))" \
            --preview='echo "Module: {1}" && echo "" && echo "Category: {3}" && echo "" && echo "Description: {5..}"' \
            --preview-window=up:40% \
            --height=90% \
            --reverse \
            --border \
            --delimiter=' | ' \
            --with-nth=1,3)

        if [[ -n "$selected" ]]; then
            local module_name=$(echo "$selected" | awk -F ' | ' '{print $1}')
            module_use "$module_name"
            return 0
        fi
    else
        # Fallback to basic list
        echo ""
        echo "Relevant Modules:"
        echo "================================================================================"
        echo "$relevant_list" | awk -F ' | ' '{printf "  %-50s %s\n", $1, $3}'
        echo "================================================================================"
        echo ""
    fi

    return 0
}

# List all detected services
# Usage: service_list_detected
service_list_detected() {
    if [[ ! -f "$SERVICE_DB" ]]; then
        echo "No services detected yet"
        return 1
    fi

    echo ""
    echo "Detected Services:"
    echo "================================================================================"
    printf "%-20s %-8s %-10s %-20s %s\n" "Target" "Port" "Protocol" "Service" "Version"
    echo "--------------------------------------------------------------------------------"

    local count=0
    while IFS='|' read -r target port protocol service version state; do
        # Skip comments and empty lines
        [[ "$target" =~ ^#.* ]] && continue
        [[ -z "$target" ]] && continue

        # Truncate long version strings
        if [[ ${#version} -gt 40 ]]; then
            version="${version:0:37}..."
        fi

        printf "%-20s %-8s %-10s %-20s %s\n" "$target" "$port" "$protocol" "$service" "$version"
        ((count++))
    done < "$SERVICE_DB"

    echo "================================================================================"
    echo "Total: $count services"
    echo ""
}

# List services for current target (RHOST)
# Usage: service_list_current_target
service_list_current_target() {
    local target=$(var_get "RHOST" 2>/dev/null)

    if [[ -z "$target" ]]; then
        echo "[!] No target set (RHOST not defined)"
        return 1
    fi

    local services=$(service_get_for_target "$target")

    if [[ -z "$services" ]]; then
        echo "[!] No services detected for $target"
        echo "[*] Run an nmap scan first"
        return 1
    fi

    echo ""
    echo "Services on $target:"
    echo "================================================================================"
    printf "%-8s %-10s %-20s %s\n" "Port" "Protocol" "Service" "Version"
    echo "--------------------------------------------------------------------------------"

    echo "$services" | while IFS='|' read -r t port protocol service version state; do
        [[ -z "$port" ]] && continue

        if [[ ${#version} -gt 50 ]]; then
            version="${version:0:47}..."
        fi

        printf "%-8s %-10s %-20s %s\n" "$port" "$protocol" "$service" "$version"
    done

    echo "================================================================================"
    echo ""
}

# Clear service database
# Usage: service_clear
service_clear() {
    if [[ -f "$SERVICE_DB" ]]; then
        read -p "Clear all detected services? [y/N]: " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            rm -f "$SERVICE_DB"
            service_analyzer_init
            echo "[+] Service database cleared"
        fi
    else
        echo "[!] No service database found"
    fi
}

# Import services from nmap XML
# Usage: service_import_nmap <nmap_xml_file>
service_import_nmap() {
    local nmap_file="$1"

    if [[ ! -f "$nmap_file" ]]; then
        echo "[!] File not found: $nmap_file"
        return 1
    fi

    # Try to detect target from filename or XML
    local target=$(basename "$nmap_file" | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | head -1)

    if [[ -z "$target" ]]; then
        read -p "Enter target IP/hostname for this scan: " target
    fi

    service_parse_nmap "$nmap_file" "$target"
}

# Export functions
export -f service_analyzer_init
export -f service_parse_nmap
export -f service_detect_from_output
export -f service_get_for_target
export -f service_get_all_unique
export -f service_to_module_category
export -f service_get_relevant_categories
export -f service_search_relevant
export -f service_search_relevant_fzf
export -f service_list_detected
export -f service_list_current_target
export -f service_clear
export -f service_import_nmap
