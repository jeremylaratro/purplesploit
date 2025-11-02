#!/bin/bash
#
# Database Management Module
# Provides reset and clear functionality for all databases
#
# This module requires the following functions from library modules:
# - clear_all_credentials() from lib/credentials.sh
# - clear_all_targets() from lib/targets.sh
# - clear_all_web_targets() from lib/web_targets.sh
# - clear_all_ad_targets() from lib/ad_targets.sh
# - clear_all_nmap_results() from lib/nmap_results.sh
#
# Required global variables:
# - RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, NC (colors)
#

# Clear all databases at once
clear_all_databases() {
    clear
    echo -e "${RED}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     CLEAR ALL DATABASES                   ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}⚠️  CRITICAL WARNING ⚠️${NC}"
    echo ""
    echo -e "${YELLOW}This will delete ALL data from ALL databases:${NC}"
    echo -e "  • ${CYAN}Credentials${NC} (custom sets only, defaults preserved)"
    echo -e "  • ${CYAN}Network Targets${NC}"
    echo -e "  • ${CYAN}Web Targets${NC}"
    echo -e "  • ${CYAN}Active Directory Targets${NC}"
    echo -e "  • ${CYAN}Nmap Scan Results${NC}"
    echo ""
    echo -e "${RED}This action CANNOT be undone!${NC}"
    echo ""

    # Show counts
    local cred_count=$(list_cred_names 2>/dev/null | grep -v "^Null Auth$" | grep -v "^Guest Account$" | wc -l)
    local target_count=$(list_target_names 2>/dev/null | wc -l)
    local web_count=$(list_web_target_names 2>/dev/null | wc -l)
    local ad_count=$(list_ad_target_names 2>/dev/null | wc -l)
    local nmap_count=$(list_nmap_scans 2>/dev/null | wc -l)

    echo -e "${YELLOW}Items to be deleted:${NC}"
    echo -e "  Credentials:    ${RED}$cred_count${NC} custom sets"
    echo -e "  Network Targets: ${RED}$target_count${NC}"
    echo -e "  Web Targets:     ${RED}$web_count${NC}"
    echo -e "  AD Targets:      ${RED}$ad_count${NC}"
    echo -e "  Nmap Scans:      ${RED}$nmap_count${NC}"
    echo ""

    read -p "Type 'CLEAR ALL' to confirm deletion: " confirm

    if [[ "$confirm" == "CLEAR ALL" ]]; then
        echo ""
        echo -e "${CYAN}Clearing databases...${NC}"
        echo ""

        # Clear each database
        echo -n "  • Credentials... "
        clear_all_credentials > /dev/null 2>&1
        echo -e "${GREEN}✓${NC}"

        echo -n "  • Network Targets... "
        clear_all_targets > /dev/null 2>&1
        echo -e "${GREEN}✓${NC}"

        echo -n "  • Web Targets... "
        clear_all_web_targets > /dev/null 2>&1
        echo -e "${GREEN}✓${NC}"

        echo -n "  • AD Targets... "
        clear_all_ad_targets > /dev/null 2>&1
        echo -e "${GREEN}✓${NC}"

        echo -n "  • Nmap Results... "
        clear_all_nmap_results > /dev/null 2>&1
        echo -e "${GREEN}✓${NC}"

        echo ""
        echo -e "${GREEN}✓ All databases cleared successfully!${NC}"
        sleep 3
    else
        echo -e "\n${YELLOW}Cancelled.${NC}"
        sleep 2
    fi
}

# Database management menu
manage_databases() {
    while true; do
        clear
        echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║     DATABASE MANAGEMENT                   ║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
        echo ""

        # Show current counts
        local cred_count=$(list_cred_names 2>/dev/null | grep -v "^Null Auth$" | grep -v "^Guest Account$" | wc -l)
        local target_count=$(list_target_names 2>/dev/null | wc -l)
        local web_count=$(list_web_target_names 2>/dev/null | wc -l)
        local ad_count=$(list_ad_target_names 2>/dev/null | wc -l)
        local nmap_count=$(list_nmap_scans 2>/dev/null | wc -l)

        echo -e "${CYAN}Current Database Status:${NC}"
        echo -e "  Credentials:     ${YELLOW}$cred_count${NC} custom sets"
        echo -e "  Network Targets: ${YELLOW}$target_count${NC}"
        echo -e "  Web Targets:     ${YELLOW}$web_count${NC}"
        echo -e "  AD Targets:      ${YELLOW}$ad_count${NC}"
        echo -e "  Nmap Scans:      ${YELLOW}$nmap_count${NC}"
        echo ""

        local choice=$(echo "Clear Credentials
Clear Network Targets
Clear Web Targets
Clear AD Targets
Clear Nmap Results
---
Clear ALL Databases
---
Back to Main Menu" | fzf --prompt="Select Action: " --height=50% --reverse)

        case "$choice" in
            "Clear Credentials")
                clear_all_credentials
                ;;
            "Clear Network Targets")
                clear_all_targets
                ;;
            "Clear Web Targets")
                clear_all_web_targets
                ;;
            "Clear AD Targets")
                clear_all_ad_targets
                ;;
            "Clear Nmap Results")
                clear_all_nmap_results
                ;;
            "Clear ALL Databases")
                clear_all_databases
                ;;
            "Back to Main Menu"|"")
                return
                ;;
        esac
    done
}
