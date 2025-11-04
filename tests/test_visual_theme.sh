#!/bin/bash
#
# Visual Theme Test Script
# Tests all visual components to ensure they render correctly
#

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

# Source visual theme
source "$SCRIPT_DIR/core/visual_theme.sh"
source "$SCRIPT_DIR/core/config.sh"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Testing PurpleSploit Visual Theme Components"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Test 1: Enhanced Banner
echo "Test 1: Enhanced Banner"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
show_enhanced_banner "test-workspace" "1.0-dev"
echo ""
read -p "Does the banner display correctly with colors? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Banner test failed or needs terminal configuration"
echo ""

# Test 2: Enhanced Context Bar
echo "Test 2: Enhanced Context Bar"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
draw_enhanced_context "test-workspace" "192.168.1.100" "admin:password" "single"
echo ""
draw_enhanced_context "test-workspace" "<none>" "<none>" "all"
echo ""
read -p "Do both context bars display with appropriate colors? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Context bar test failed"
echo ""

# Test 3: Menu Categories
echo "Test 3: Menu Category Headers"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
draw_menu_category "🌐" "WEB TESTING" "$BRIGHT_YELLOW"
draw_menu_category "🔒" "NETWORK TESTING" "$BRIGHT_MAGENTA"
draw_menu_category "🛠️" "TOOLS" "$BRIGHT_BLUE"
draw_menu_category "⚙️" "SETTINGS" "$BRIGHT_WHITE"
echo ""
read -p "Do category headers show with colors and emojis? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Category header test failed - check emoji support"
echo ""

# Test 4: Menu Items
echo "Test 4: Menu Items with Status Indicators"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
draw_menu_item "" "Normal Item" "normal"
draw_menu_item "" "Active Service Detected" "active"
draw_menu_item "" "Recommended Action" "recommended"
draw_menu_item "" "Inactive/Unavailable" "inactive"
echo ""
read -p "Do menu items show different colors based on status? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Menu item test failed"
echo ""

# Test 5: Status Messages
echo "Test 5: Status Messages"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
show_success "Operation completed successfully!"
show_error "An error occurred during processing"
show_warning "This action requires confirmation"
show_info "Informational message about system status"
show_loading "Loading resources"
echo ""
read -p "Do status messages show with appropriate icons and colors? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Status message test failed"
echo ""

# Test 6: Progress Bar
echo "Test 6: Progress Bar Animation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for i in {1..10}; do
    show_progress $i 10 "Processing items"
    sleep 0.1
done
echo ""
read -p "Did the progress bar animate smoothly? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Progress bar test failed"
echo ""

# Test 7: Box Drawing
echo "Test 7: Box Drawing Characters"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
draw_box 60 "Test Box" "single"
draw_box_line 60 "This is content inside a single-line box" "single"
draw_box_line 60 "Multiple lines can be displayed" "single"
draw_box_bottom 60 "single"
echo ""
draw_box 60 "Double Box" "double"
draw_box_line 60 "This uses double-line characters" "double"
draw_box_bottom 60 "double"
echo ""
read -p "Do boxes display with correct borders? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Box drawing test failed - check UTF-8 support"
echo ""

# Test 8: Table Drawing
echo "Test 8: Table Drawing"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
draw_table_header "Name" "IP Address" "Status"
draw_table_row "Server01" "192.168.1.10" "Active"
draw_table_row "Server02" "192.168.1.11" "Inactive"
draw_table_row "Server03" "192.168.1.12" "Active"
draw_table_footer 3
echo ""
read -p "Does the table display correctly? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Table drawing test failed"
echo ""

# Test 9: Shortcuts Help
echo "Test 9: Keyboard Shortcuts Help"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
draw_shortcuts_help
echo ""
read -p "Do shortcuts display clearly? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Shortcuts help test failed"
echo ""

# Test 10: Color Palette
echo "Test 10: Full Color Palette"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Standard Colors:"
echo -e "${RED}■${NC} RED  ${GREEN}■${NC} GREEN  ${YELLOW}■${NC} YELLOW  ${BLUE}■${NC} BLUE  ${MAGENTA}■${NC} MAGENTA  ${CYAN}■${NC} CYAN"
echo ""
echo -e "Bright Colors:"
echo -e "${BRIGHT_RED}■${NC} BRIGHT_RED  ${BRIGHT_GREEN}■${NC} BRIGHT_GREEN  ${BRIGHT_YELLOW}■${NC} BRIGHT_YELLOW"
echo -e "${BRIGHT_BLUE}■${NC} BRIGHT_BLUE  ${BRIGHT_MAGENTA}■${NC} BRIGHT_MAGENTA  ${BRIGHT_CYAN}■${NC} BRIGHT_CYAN  ${BRIGHT_WHITE}■${NC} BRIGHT_WHITE"
echo ""
echo -e "Text Styles:"
echo -e "${BOLD}Bold Text${NC}  ${DIM}Dimmed Text${NC}  ${UNDERLINE}Underlined Text${NC}  ${REVERSE}Reversed${NC}"
echo ""
read -p "Do all colors and styles display correctly? (y/n) " answer
[[ "$answer" != "y" ]] && echo "⚠️  Color palette test failed - check 256-color support"
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Visual Theme Test Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "If any tests failed, check the TUI Setup Guide:"
echo "  docs/TUI_SETUP.md"
echo ""
echo "Common issues:"
echo "  - Terminal doesn't support UTF-8: Set LANG=en_US.UTF-8"
echo "  - No emoji support: Install emoji fonts (fonts-noto-color-emoji)"
echo "  - Wrong colors: Set TERM=xterm-256color"
echo "  - Box characters broken: Use a unicode-compatible font"
echo ""
