#!/bin/bash
#
# TUI Menu Flow Test Script
# Tests that menu selections work correctly with color stripping
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Testing TUI Menu Flow and Pattern Matching"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Source required files
source "$SCRIPT_DIR/core/config.sh"

# Test strip_colors function
strip_colors() {
    echo "$1" | sed -r 's/\x1b\[[0-9;]*m//g; s/\x1b\(B//g; s/[▸●○★◆◦✓✗⚠ℹ🌐🔒🛠️💼🤖⚙️🚪🎯🔐⚡⬅️🔄]//g; s/^[[:space:]]*//; s/[[:space:]]*$//'
}

echo "Test 1: Strip Colors Function"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_string=$(echo -e "${CYAN}▸${NC} Network Scanning")
cleaned=$(strip_colors "$test_string")
echo "Input:   '$test_string'"
echo "Cleaned: '$cleaned'"

if [[ "$cleaned" == "Network Scanning" ]]; then
    echo "✓ PASS: Correctly stripped to 'Network Scanning'"
else
    echo "✗ FAIL: Expected 'Network Scanning' but got '$cleaned'"
fi
echo ""

echo "Test 2: Pattern Matching"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Simulate menu items
declare -a menu_items=(
    "$(echo -e "${CYAN}▸${NC} Feroxbuster (Directory/File Discovery)")"
    "$(echo -e "${CYAN}▸${NC} Network Scanning")"
    "$(echo -e "${BRIGHT_GREEN}●${NC} ${BRIGHT_CYAN}SMB Authentication${NC}")"
    "$(echo -e "${CYAN}▸${NC} Sessions Management")"
    "$(echo -e "${CYAN}▸${NC} Manage Web Targets")"
)

declare -a expected_matches=(
    "Feroxbuster"
    "Network Scanning"
    "SMB Authentication"
    "Sessions"
    "Web Targets"
)

pass_count=0
fail_count=0

for i in "${!menu_items[@]}"; do
    item="${menu_items[$i]}"
    expected="${expected_matches[$i]}"
    cleaned=$(strip_colors "$item")

    echo "Testing: $cleaned"

    matched=false
    case "$cleaned" in
        *"Feroxbuster"*|*"Directory/File Discovery"*)
            if [[ "$expected" == "Feroxbuster" ]]; then
                echo "  ✓ PASS: Matched Feroxbuster"
                ((pass_count++))
                matched=true
            fi
            ;;
        *"Network Scanning"*)
            if [[ "$expected" == "Network Scanning" ]]; then
                echo "  ✓ PASS: Matched Network Scanning"
                ((pass_count++))
                matched=true
            fi
            ;;
        *"SMB Authentication"*)
            if [[ "$expected" == "SMB Authentication" ]]; then
                echo "  ✓ PASS: Matched SMB Authentication"
                ((pass_count++))
                matched=true
            fi
            ;;
        *"Sessions Management"*|*"Sessions"*)
            if [[ "$expected" == "Sessions" ]]; then
                echo "  ✓ PASS: Matched Sessions"
                ((pass_count++))
                matched=true
            fi
            ;;
        *"Manage Web Targets"*|*"Web Targets"*)
            if [[ "$expected" == "Web Targets" ]]; then
                echo "  ✓ PASS: Matched Web Targets"
                ((pass_count++))
                matched=true
            fi
            ;;
    esac

    if [[ "$matched" == "false" ]]; then
        echo "  ✗ FAIL: No match for '$cleaned'"
        ((fail_count++))
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Results: $pass_count passed, $fail_count failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $fail_count -eq 0 ]]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi
