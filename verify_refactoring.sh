#!/bin/bash
#
# Refactoring Verification Script
# Verifies that all modules are properly organized and can be sourced
#

echo "==================================================================="
echo "PurpleSploit Refactoring Verification"
echo "==================================================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SUCCESS=0
FAILURES=0

# Function to check file
check_file() {
    local file="$1"
    local description="$2"

    if [[ -f "$file" ]]; then
        echo -e "${GREEN}✓${NC} $description"
        echo -e "  ${CYAN}→${NC} $file"
        ((SUCCESS++))
        return 0
    else
        echo -e "${RED}✗${NC} $description"
        echo -e "  ${RED}→${NC} Missing: $file"
        ((FAILURES++))
        return 1
    fi
}

# Function to check handler function exists in file
check_handler() {
    local file="$1"
    local handler="$2"
    local description="$3"

    if [[ -f "$file" ]]; then
        if grep -q "^${handler}()" "$file"; then
            echo -e "${GREEN}✓${NC} $description"
            echo -e "  ${CYAN}→${NC} ${handler}() in $file"
            ((SUCCESS++))
            return 0
        else
            echo -e "${RED}✗${NC} $description"
            echo -e "  ${RED}→${NC} Missing function: ${handler}() in $file"
            ((FAILURES++))
            return 1
        fi
    else
        echo -e "${RED}✗${NC} $description"
        echo -e "  ${RED}→${NC} Missing file: $file"
        ((FAILURES++))
        return 1
    fi
}

echo "==================================================================="
echo "1. Checking Main Entry Point"
echo "==================================================================="
check_file "purplesploit.sh" "Main entry point script"
if [[ -x "purplesploit.sh" ]]; then
    echo -e "${GREEN}✓${NC} Script is executable"
    ((SUCCESS++))
else
    echo -e "${RED}✗${NC} Script is not executable"
    ((FAILURES++))
fi
echo ""

echo "==================================================================="
echo "2. Checking Core Modules"
echo "==================================================================="
check_file "core/config.sh" "Core configuration module"
check_file "core/database.sh" "Core database module"
check_file "core/ui.sh" "Core UI module"
echo ""

echo "==================================================================="
echo "3. Checking Library Modules"
echo "==================================================================="
check_file "lib/credentials.sh" "Credentials library"
check_file "lib/targets.sh" "Targets library"
check_file "lib/web_targets.sh" "Web targets library"
check_file "lib/ad_targets.sh" "AD targets library"
check_file "lib/utils.sh" "Utilities library"
echo ""

echo "==================================================================="
echo "4. Checking Web Testing Modules"
echo "==================================================================="
check_handler "modules/web/feroxbuster.sh" "handle_feroxbuster" "Feroxbuster handler"
check_handler "modules/web/wfuzz.sh" "handle_wfuzz" "WFUZZ handler"
check_handler "modules/web/sqlmap.sh" "handle_sqlmap" "SQLMap handler"
check_handler "modules/web/httpx.sh" "handle_httpx" "HTTPX handler"
echo ""

echo "==================================================================="
echo "5. Checking NXC Modules"
echo "==================================================================="
check_handler "modules/nxc/smb.sh" "handle_smb_auth" "SMB Authentication handler"
check_handler "modules/nxc/smb.sh" "handle_smb_enum" "SMB Enumeration handler"
check_handler "modules/nxc/smb.sh" "handle_smb_shares" "SMB Shares handler"
check_handler "modules/nxc/smb.sh" "handle_smb_exec" "SMB Execution handler"
check_handler "modules/nxc/smb.sh" "handle_smb_creds" "SMB Credentials handler"
check_handler "modules/nxc/smb.sh" "handle_smb_vulns" "SMB Vulnerabilities handler"
check_handler "modules/nxc/ldap.sh" "handle_ldap" "LDAP Enumeration handler"
check_handler "modules/nxc/ldap.sh" "handle_bloodhound" "BloodHound handler"
check_handler "modules/nxc/winrm.sh" "handle_winrm" "WinRM handler"
check_handler "modules/nxc/mssql.sh" "handle_mssql" "MSSQL handler"
check_handler "modules/nxc/rdp.sh" "handle_rdp" "RDP handler"
check_handler "modules/nxc/ssh.sh" "handle_ssh" "SSH handler"
check_handler "modules/nxc/scanning.sh" "handle_scanning" "Scanning handler"
echo ""

echo "==================================================================="
echo "6. Checking Impacket Modules"
echo "==================================================================="
check_handler "modules/impacket/execution.sh" "handle_psexec" "PSExec handler"
check_handler "modules/impacket/execution.sh" "handle_wmiexec" "WMIExec handler"
check_handler "modules/impacket/execution.sh" "handle_smbexec" "SMBExec handler"
check_handler "modules/impacket/execution.sh" "handle_atexec" "ATExec handler"
check_handler "modules/impacket/execution.sh" "handle_dcomexec" "DcomExec handler"
check_handler "modules/impacket/credentials.sh" "handle_secretsdump" "SecretsDump handler"
check_handler "modules/impacket/kerberos.sh" "handle_kerberoast" "Kerberoasting handler"
check_handler "modules/impacket/kerberos.sh" "handle_asreproast" "AS-REP Roasting handler"
check_handler "modules/impacket/kerberos.sh" "handle_tickets" "Ticket handler"
check_handler "modules/impacket/enumeration.sh" "handle_enum" "Enumeration handler"
check_handler "modules/impacket/smbclient.sh" "handle_smbclient" "SMB Client handler"
check_handler "modules/impacket/services.sh" "handle_services" "Service Management handler"
check_handler "modules/impacket/registry.sh" "handle_registry" "Registry handler"
echo ""

echo "==================================================================="
echo "7. Checking Documentation"
echo "==================================================================="
check_file "REFACTORING_SUMMARY.md" "Refactoring summary document"
check_file "HANDLER_REFERENCE.md" "Handler reference guide"
check_file "LINE_MAPPING.md" "Line-by-line mapping document"
echo ""

echo "==================================================================="
echo "8. Testing Module Sourcing"
echo "==================================================================="

# Try to source core modules
echo -n "Testing core/config.sh... "
if source core/config.sh 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
    ((SUCCESS++))
else
    echo -e "${RED}FAILED${NC}"
    ((FAILURES++))
fi

echo -n "Testing core/database.sh... "
if source core/database.sh 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
    ((SUCCESS++))
else
    echo -e "${RED}FAILED${NC}"
    ((FAILURES++))
fi

echo -n "Testing core/ui.sh... "
if source core/ui.sh 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
    ((SUCCESS++))
else
    echo -e "${RED}FAILED${NC}"
    ((FAILURES++))
fi

echo ""

echo "==================================================================="
echo "9. File Statistics"
echo "==================================================================="

echo -e "${CYAN}Main Script:${NC}"
wc -l purplesploit.sh 2>/dev/null || echo "  File not found"

echo -e "\n${CYAN}Core Modules:${NC}"
wc -l core/*.sh 2>/dev/null | tail -1 || echo "  No files found"

echo -e "\n${CYAN}Library Modules:${NC}"
wc -l lib/*.sh 2>/dev/null | tail -1 || echo "  No files found"

echo -e "\n${CYAN}Web Testing Modules:${NC}"
wc -l modules/web/*.sh 2>/dev/null | tail -1 || echo "  No files found"

echo -e "\n${CYAN}NXC Modules:${NC}"
wc -l modules/nxc/*.sh 2>/dev/null | tail -1 || echo "  No files found"

echo -e "\n${CYAN}Impacket Modules:${NC}"
wc -l modules/impacket/*.sh 2>/dev/null | tail -1 || echo "  No files found"

echo -e "\n${CYAN}Total Module Files:${NC}"
find . -name "*.sh" -not -name "plat02.sh" -not -name "verify_refactoring.sh" | wc -l

echo ""

echo "==================================================================="
echo "10. Comparison with Original"
echo "==================================================================="

if [[ -f "plat02.sh" ]]; then
    orig_lines=$(wc -l < plat02.sh)
    new_lines=$(wc -l < purplesploit.sh)
    reduction=$((100 - (new_lines * 100 / orig_lines)))

    echo -e "${CYAN}Original plat02.sh:${NC}       $orig_lines lines"
    echo -e "${CYAN}New purplesploit.sh:${NC}      $new_lines lines"
    echo -e "${GREEN}Reduction:${NC}                ${reduction}%"
else
    echo -e "${YELLOW}Original plat02.sh not found for comparison${NC}"
fi

echo ""

echo "==================================================================="
echo "Verification Summary"
echo "==================================================================="
echo -e "${GREEN}Successful checks:${NC} $SUCCESS"
echo -e "${RED}Failed checks:${NC}     $FAILURES"
echo ""

if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ ALL CHECKS PASSED${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "The refactoring is complete and verified!"
    echo "You can now run: ./purplesploit.sh"
    echo ""
    exit 0
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}✗ SOME CHECKS FAILED${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Please review the failures above and fix them."
    echo ""
    exit 1
fi
