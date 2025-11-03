#!/bin/bash
#
# NXC Interactive Cheatsheet Setup
# Installs navi and configures NXC cheatsheet
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════╗
║   NXC Interactive Cheatsheet Installer    ║
║        Powered by Navi                    ║
╚═══════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}[!] This script should NOT be run as root${NC}"
   exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for dependencies
echo -e "${BLUE}[*] Checking dependencies...${NC}"

if ! command_exists navi; then
    echo -e "${YELLOW}[!] Navi not found. Installing...${NC}"
    
    # Detect OS and install accordingly
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt; then
            # Debian/Ubuntu
            echo -e "${GREEN}[+] Detected Debian/Ubuntu${NC}"
            echo -e "${YELLOW}[*] Installing via bash script...${NC}"
            bash <(curl -sL https://raw.githubusercontent.com/denisidoro/navi/master/scripts/install)
        elif command_exists yum || command_exists dnf; then
            # RHEL/CentOS/Fedora
            echo -e "${GREEN}[+] Detected RHEL/CentOS/Fedora${NC}"
            bash <(curl -sL https://raw.githubusercontent.com/denisidoro/navi/master/scripts/install)
        else
            echo -e "${RED}[!] Unsupported Linux distribution${NC}"
            echo -e "${YELLOW}[*] Please install navi manually from: https://github.com/denisidoro/navi${NC}"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo -e "${GREEN}[+] Detected macOS${NC}"
        if command_exists brew; then
            brew install navi
        else
            echo -e "${RED}[!] Homebrew not found${NC}"
            echo -e "${YELLOW}[*] Install Homebrew first: https://brew.sh${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[!] Unsupported operating system${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] Navi is already installed${NC}"
fi

# Check for NetExec
if ! command_exists nxc && ! command_exists netexec; then
    echo -e "${YELLOW}[!] NetExec (nxc) not found${NC}"
    echo -e "${YELLOW}[*] Install with: pipx install netexec${NC}"
    echo -e "${YELLOW}[*] Or: pip install netexec${NC}"
    read -p "Do you want to install NetExec now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command_exists pipx; then
            pipx install netexec
        elif command_exists pip3; then
            pip3 install netexec --break-system-packages
        else
            echo -e "${RED}[!] Neither pipx nor pip3 found${NC}"
            exit 1
        fi
    fi
fi

# Setup navi cheat directory
NAVI_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/navi"
CHEAT_DIR="$NAVI_CONFIG_DIR/cheats"

echo -e "${BLUE}[*] Setting up navi configuration...${NC}"
mkdir -p "$CHEAT_DIR"

# Copy cheatsheet
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHEAT_FILE="$SCRIPT_DIR/nxc.cheat"

if [[ -f "$CHEAT_FILE" ]]; then
    cp "$CHEAT_FILE" "$CHEAT_DIR/"
    echo -e "${GREEN}[+] Cheatsheet installed to: $CHEAT_DIR/nxc.cheat${NC}"
else
    echo -e "${RED}[!] Cheatsheet file not found: $CHEAT_FILE${NC}"
    exit 1
fi

# Create navi config if it doesn't exist
CONFIG_FILE="$NAVI_CONFIG_DIR/config.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" << 'EOF'
cheats:
  paths:
    - ~/.config/navi/cheats

finder:
  command: fzf
  overrides: --height 40% --reverse --inline-info

shell:
  command: bash
EOF
    echo -e "${GREEN}[+] Created navi config: $CONFIG_FILE${NC}"
else
    echo -e "${GREEN}[+] Navi config already exists${NC}"
fi

# Setup shell integration
echo -e "\n${BLUE}[*] Setting up shell integration...${NC}"

SHELL_NAME=$(basename "$SHELL")
case "$SHELL_NAME" in
    bash)
        RC_FILE="$HOME/.bashrc"
        NAVI_BINDING='eval "$(navi widget bash)"'
        ;;
    zsh)
        RC_FILE="$HOME/.zshrc"
        NAVI_BINDING='eval "$(navi widget zsh)"'
        ;;
    fish)
        RC_FILE="$HOME/.config/fish/config.fish"
        NAVI_BINDING='navi widget fish | source'
        ;;
    *)
        echo -e "${YELLOW}[!] Unknown shell: $SHELL_NAME${NC}"
        RC_FILE=""
        ;;
esac

if [[ -n "$RC_FILE" && -f "$RC_FILE" ]]; then
    if ! grep -q "navi widget" "$RC_FILE"; then
        echo -e "${YELLOW}[*] Adding navi widget to $RC_FILE${NC}"
        echo "" >> "$RC_FILE"
        echo "# Navi cheatsheet widget (Ctrl+G)" >> "$RC_FILE"
        echo "$NAVI_BINDING" >> "$RC_FILE"
        echo -e "${GREEN}[+] Shell integration added${NC}"
        echo -e "${YELLOW}[!] Run 'source $RC_FILE' or restart your shell${NC}"
    else
        echo -e "${GREEN}[+] Shell integration already configured${NC}"
    fi
fi

# Create quick reference
cat > "$SCRIPT_DIR/QUICKSTART.txt" << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║          NXC Interactive Cheatsheet - Quick Start         ║
╚═══════════════════════════════════════════════════════════╝

BASIC USAGE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Launch interactive mode:
   $ navi

2. Search for commands:
   - Type keywords (e.g., "smb", "enumerate", "dump")
   - Navigate with arrow keys
   - Press Enter to select

3. Fill in variables:
   - Tab through placeholders
   - Edit values as needed
   - Press Enter to execute

4. Browse by tags:
   $ navi --tag-rules nxc,smb
   $ navi --tag-rules ldap
   $ navi --tag-rules winrm

5. Execute directly (non-interactive):
   $ navi --query "smb authentication"


KEYBOARD SHORTCUTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Ctrl+G          Open navi from anywhere in terminal
Ctrl+R          Alternative shortcut (if configured)
Ctrl+C          Cancel/Exit
Tab             Navigate between input fields
Enter           Execute command
Esc             Go back


COMMON WORKFLOWS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

◆ Quick Authentication Test:
  $ navi
  → Search: "test authentication"
  → Select protocol (smb/ldap/winrm)
  → Fill in credentials
  → Execute

◆ Enumerate Domain:
  $ navi
  → Search: "enumerate"
  → Select: users, groups, shares, etc.
  → Auto-fills last used credentials

◆ Dump Credentials:
  $ navi
  → Search: "dump"
  → Select: SAM, LSA, or NTDS
  → Execute

◆ Check Vulnerabilities:
  $ navi
  → Search: "ms17-010" or "zerologon"
  → Fill in target
  → Execute


EXAMPLES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Find all SMB enumeration commands
$ navi --tag-rules nxc,smb,enumeration

# Search for credential dumping
$ navi --query "dump credentials"

# Browse all LDAP commands
$ navi --tag-rules nxc,ldap

# Find vulnerability checks
$ navi --query "vulnerability"


TIPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Variables are remembered between commands
✓ Use partial matches (e.g., "enum" finds "enumerate")
✓ Tags help narrow down results
✓ Press Tab to preview command before executing
✓ Commands show examples by default


ADVANCED:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Print command without executing
$ navi --print

# Use best match directly
$ navi --query "smb shares" --best-match

# Pipe to another command
$ navi --query "enumerate users" --print | tee users.txt


CONFIGURATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Config location: ~/.config/navi/config.yaml
Cheats location: ~/.config/navi/cheats/nxc.cheat

Edit cheatsheet:
$ nano ~/.config/navi/cheats/nxc.cheat


TROUBLESHOOTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• "command not found: navi"
  → Run: source ~/.bashrc (or restart terminal)

• Cheatsheet not showing
  → Run: navi repo browse
  → Check: ~/.config/navi/cheats/nxc.cheat exists

• Ctrl+G not working
  → Add to shell: eval "$(navi widget bash)"
  → Restart terminal


RESOURCES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Navi docs:    https://github.com/denisidoro/navi
NetExec wiki: https://www.netexec.wiki/
Add commands: Edit ~/.config/navi/cheats/nxc.cheat


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Press Ctrl+G now to start using the interactive cheatsheet!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

cat "$SCRIPT_DIR/QUICKSTART.txt"

echo -e "\n${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Installation Complete!                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo -e "${YELLOW}[*] Restart your terminal or run: source $RC_FILE${NC}"
echo -e "${BLUE}[*] Then press Ctrl+G to launch navi${NC}"
echo -e "${BLUE}[*] Or run: navi${NC}\n"
