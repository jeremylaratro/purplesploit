#!/bin/bash
#
# Nmap Results Management
# Functions for managing nmap scan results and auto-detecting web servers
#
# This module provides:
# - Listing nmap scan results
# - Parsing nmap XML output
# - Auto-importing detected web servers to web targets database
# - Viewing scan results with multiple display options
#
# Required global variables:
# - NMAP_RESULTS_DIR
# - WEB_TARGETS_DB
# - RED, GREEN, YELLOW, BLUE, CYAN, NC (colors)
#

# List nmap scan results
list_nmap_scans() {
    if [[ ! -d "$NMAP_RESULTS_DIR" ]]; then
        return 1
    fi
    find "$NMAP_RESULTS_DIR" -name "*.xml" -type f 2>/dev/null | sort -r
}

# Get scan name from file path
get_scan_name() {
    basename "$1" .xml
}

# Parse and display nmap results
parse_nmap_results() {
    local xml_file="$1"
    local options="$2"

    if [[ ! -f "$xml_file" ]]; then
        echo -e "${RED}Error: Scan file not found: $xml_file${NC}"
        return 1
    fi

    if [[ ! -f "${SCRIPT_DIR}/tools/parse_nmap.py" ]]; then
        echo -e "${RED}Error: parse_nmap.py not found in ${SCRIPT_DIR}/tools${NC}"
        return 1
    fi

    python3 "${SCRIPT_DIR}/tools/parse_nmap.py" "$xml_file" $options
}

# Auto-import web targets from nmap scan
import_web_targets_from_nmap() {
    local xml_file="$1"

    if [[ ! -f "$xml_file" ]]; then
        echo -e "${RED}Error: Scan file not found: $xml_file${NC}"
        return 1
    fi

    if [[ ! -f "${SCRIPT_DIR}/tools/parse_nmap.py" ]]; then
        echo -e "${RED}Error: parse_nmap.py not found in ${SCRIPT_DIR}/tools${NC}"
        return 1
    fi

    echo -e "${CYAN}Detecting web servers and importing to web targets...${NC}"
    echo ""

    # Use the parser to export web targets
    python3 "${SCRIPT_DIR}/tools/parse_nmap.py" "$xml_file" --export-web "$WEB_TARGETS_DB"

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Web targets imported successfully!${NC}"
        return 0
    else
        echo -e "${RED}Failed to import web targets${NC}"
        return 1
    fi
}

# Auto-import detected services from nmap scan
import_services_from_nmap() {
    local xml_file="$1"

    if [[ ! -f "$xml_file" ]]; then
        echo -e "${RED}Error: Scan file not found: $xml_file${NC}"
        return 1
    fi

    if [[ ! -f "${SCRIPT_DIR}/tools/parse_nmap.py" ]]; then
        echo -e "${RED}Error: parse_nmap.py not found in ${SCRIPT_DIR}/tools${NC}"
        return 1
    fi

    echo -e "${CYAN}Detecting services (SMB, LDAP, SSH, RDP, WinRM, MSSQL)...${NC}"
    echo ""

    # Use the parser to export detected services
    python3 "${SCRIPT_DIR}/tools/parse_nmap.py" "$xml_file" --export-services "$SERVICES_DB"

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Services imported successfully!${NC}"
        # Also import web targets
        echo ""
        echo -e "${CYAN}Detecting web servers...${NC}"
        python3 "${SCRIPT_DIR}/tools/parse_nmap.py" "$xml_file" --export-web "$WEB_TARGETS_DB"
        return 0
    else
        echo -e "${RED}Failed to import services${NC}"
        return 1
    fi
}

# View nmap scan results menu
view_nmap_results() {
    local scans=$(list_nmap_scans)

    if [[ -z "$scans" ]]; then
        echo -e "${YELLOW}No nmap scans found in $NMAP_RESULTS_DIR${NC}"
        sleep 2
        return 1
    fi

    # Create a nice display list
    local display_list=""
    while IFS= read -r scan_file; do
        local scan_name=$(get_scan_name "$scan_file")
        local scan_date=$(stat -c %y "$scan_file" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
        display_list+="$scan_name [$scan_date]"$'\n'
    done <<< "$scans"

    local choice=$(echo "$display_list" | fzf --prompt="Select scan to view: " --height=50% --reverse)

    if [[ -z "$choice" ]]; then
        return 1
    fi

    # Extract scan name from choice
    local scan_name=$(echo "$choice" | cut -d' ' -f1)
    local scan_file="$NMAP_RESULTS_DIR/${scan_name}.xml"

    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     NMAP SCAN RESULTS: $scan_name${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    # Ask for view options
    local view_option=$(echo "Summary Only
Detailed View
Web Servers Only
Summary + Web Import" | fzf --prompt="View option: " --height=40% --reverse)

    case "$view_option" in
        "Summary Only")
            parse_nmap_results "$scan_file"
            ;;
        "Detailed View")
            parse_nmap_results "$scan_file" "--detailed"
            ;;
        "Web Servers Only")
            parse_nmap_results "$scan_file" "--web-only"
            ;;
        "Summary + Web Import")
            parse_nmap_results "$scan_file"
            echo ""
            echo -e "${YELLOW}Import detected web servers to web targets database?${NC}"
            read -p "Continue? (y/n): " confirm
            if [[ "$confirm" == "y" ]]; then
                import_web_targets_from_nmap "$scan_file"
            fi
            ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
}

# Clear all nmap results
clear_all_nmap_results() {
    clear
    echo -e "${YELLOW}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║     CLEAR ALL NMAP RESULTS                ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}WARNING: This will delete ALL nmap scan results!${NC}"
    echo ""

    local scan_count=$(list_nmap_scans | wc -l)
    echo -e "Nmap scans to be deleted: ${RED}$scan_count${NC}"
    echo ""

    read -p "Type 'CLEAR' to confirm deletion: " confirm

    if [[ "$confirm" == "CLEAR" ]]; then
        # Remove all XML files from nmap results directory
        rm -f "$NMAP_RESULTS_DIR"/*.xml 2>/dev/null

        echo -e "\n${GREEN}✓ All nmap results cleared!${NC}"
        sleep 2
    else
        echo -e "\n${YELLOW}Cancelled.${NC}"
        sleep 2
    fi
}
