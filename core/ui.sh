#!/bin/bash

# UI Module
# This module contains all UI/menu functions for the PurpleSploit framework
# Functions handle dynamic menu generation with fzf and command execution wrappers
# References global variables from config.sh for credentials, targets, and display settings

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
Database Management (Reset/Clear)
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
Parse Spider Results
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
---
Nmap Port Scan (Auto Web Detection)
Nmap Service Detection
Nmap Vulnerability Scan
View Nmap Results
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
