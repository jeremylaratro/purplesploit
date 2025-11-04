#!/bin/bash
#
# Visual Theme Module
# Provides enhanced visual elements for TUI
#
# Features:
# - Box drawing characters
# - Color schemes
# - Styled headers
# - Status indicators
# - Progress bars
# - Decorative elements
#

# ============================================================================
# Box Drawing Characters
# ============================================================================

# Single-line box characters
BOX_TL="┌"  # Top-left
BOX_TR="┐"  # Top-right
BOX_BL="└"  # Bottom-left
BOX_BR="┘"  # Bottom-right
BOX_H="─"   # Horizontal
BOX_V="│"   # Vertical
BOX_VR="├"  # Vertical-right (left T)
BOX_VL="┤"  # Vertical-left (right T)
BOX_HU="┴"  # Horizontal-up (bottom T)
BOX_HD="┬"  # Horizontal-down (top T)
BOX_X="┼"   # Cross

# Double-line box characters
DBOX_TL="╔"
DBOX_TR="╗"
DBOX_BL="╚"
DBOX_BR="╝"
DBOX_H="═"
DBOX_V="║"
DBOX_VR="╠"
DBOX_VL="╣"
DBOX_HU="╩"
DBOX_HD="╦"
DBOX_X="╬"

# Heavy box characters
HBOX_TL="┏"
HBOX_TR="┓"
HBOX_BL="┗"
HBOX_BR="┛"
HBOX_H="━"
HBOX_V="┃"

# Block characters
BLOCK_FULL="█"
BLOCK_DARK="▓"
BLOCK_MEDIUM="▒"
BLOCK_LIGHT="░"
BLOCK_HALF_LEFT="▌"
BLOCK_HALF_RIGHT="▐"

# Arrow characters
ARROW_RIGHT="▶"
ARROW_LEFT="◀"
ARROW_UP="▲"
ARROW_DOWN="▼"
ARROW_R="→"
ARROW_L="←"
ARROW_U="↑"
ARROW_D="↓"

# Bullet characters
BULLET="•"
BULLET_HOLLOW="◦"
BULLET_SQUARE="▪"
BULLET_DIAMOND="◆"
BULLET_STAR="✦"
BULLET_CHECK="✓"
BULLET_X="✗"
BULLET_WARN="⚠"
BULLET_INFO="ℹ"

# ============================================================================
# Enhanced Color Palette
# ============================================================================

# Standard colors (already defined in config.sh)
# RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, NC

# Additional colors
BOLD="\033[1m"
DIM="\033[2m"
ITALIC="\033[3m"
UNDERLINE="\033[4m"
BLINK="\033[5m"
REVERSE="\033[7m"
HIDDEN="\033[8m"

# Bright colors
BRIGHT_RED="\033[91m"
BRIGHT_GREEN="\033[92m"
BRIGHT_YELLOW="\033[93m"
BRIGHT_BLUE="\033[94m"
BRIGHT_MAGENTA="\033[95m"
BRIGHT_CYAN="\033[96m"
BRIGHT_WHITE="\033[97m"

# Background colors
BG_BLACK="\033[40m"
BG_RED="\033[41m"
BG_GREEN="\033[42m"
BG_YELLOW="\033[43m"
BG_BLUE="\033[44m"
BG_MAGENTA="\033[45m"
BG_CYAN="\033[46m"
BG_WHITE="\033[47m"

# Themed colors for context
COLOR_SUCCESS="${BRIGHT_GREEN}"
COLOR_ERROR="${BRIGHT_RED}"
COLOR_WARNING="${BRIGHT_YELLOW}"
COLOR_INFO="${BRIGHT_CYAN}"
COLOR_PRIMARY="${BRIGHT_MAGENTA}"
COLOR_SECONDARY="${CYAN}"
COLOR_ACCENT="${YELLOW}"
COLOR_MUTED="${DIM}"

# ============================================================================
# Box Drawing Functions
# ============================================================================

# Draw a simple box
draw_box() {
    local width=$1
    local title="$2"
    local style="${3:-single}"  # single, double, heavy

    local tl tr bl br h v

    case "$style" in
        double)
            tl="$DBOX_TL" tr="$DBOX_TR" bl="$DBOX_BL" br="$DBOX_BR"
            h="$DBOX_H" v="$DBOX_V"
            ;;
        heavy)
            tl="$HBOX_TL" tr="$HBOX_TR" bl="$HBOX_BL" br="$HBOX_BR"
            h="$HBOX_H" v="$HBOX_V"
            ;;
        *)
            tl="$BOX_TL" tr="$BOX_TR" bl="$BOX_BL" br="$BOX_BR"
            h="$BOX_H" v="$BOX_V"
            ;;
    esac

    # Top border with title
    if [[ -n "$title" ]]; then
        local title_len=${#title}
        local padding=$(( (width - title_len - 2) / 2 ))
        local line=$(printf "%${padding}s" | tr ' ' "$h")
        echo -e "${tl}${line} ${title} ${line}${tr}"
    else
        local line=$(printf "%${width}s" | tr ' ' "$h")
        echo -e "${tl}${line}${tr}"
    fi
}

# Draw bottom border
draw_box_bottom() {
    local width=$1
    local style="${2:-single}"

    local bl br h

    case "$style" in
        double)
            bl="$DBOX_BL" br="$DBOX_BR" h="$DBOX_H"
            ;;
        heavy)
            bl="$HBOX_BL" br="$HBOX_BR" h="$HBOX_H"
            ;;
        *)
            bl="$BOX_BL" br="$BOX_BR" h="$BOX_H"
            ;;
    esac

    local line=$(printf "%${width}s" | tr ' ' "$h")
    echo -e "${bl}${line}${br}"
}

# Draw box line (content line with borders)
draw_box_line() {
    local width=$1
    local content="$2"
    local style="${3:-single}"

    local v
    case "$style" in
        double) v="$DBOX_V" ;;
        heavy) v="$HBOX_V" ;;
        *) v="$BOX_V" ;;
    esac

    # Strip ANSI codes for length calculation
    local content_plain=$(echo -e "$content" | sed 's/\x1b\[[0-9;]*m//g')
    local content_len=${#content_plain}
    local padding=$(( width - content_len ))
    local padding_str=$(printf "%${padding}s" "")

    echo -e "${v} ${content}${padding_str}${v}"
}

# Draw a separator line
draw_separator() {
    local width=$1
    local style="${2:-single}"
    local title="$3"

    local vr vl h

    case "$style" in
        double)
            vr="$DBOX_VR" vl="$DBOX_VL" h="$DBOX_H"
            ;;
        heavy)
            vr="$BOX_VR" vl="$BOX_VL" h="$HBOX_H"
            ;;
        *)
            vr="$BOX_VR" vl="$BOX_VL" h="$BOX_H"
            ;;
    esac

    if [[ -n "$title" ]]; then
        local title_len=${#title}
        local padding=$(( (width - title_len - 2) / 2 ))
        local line=$(printf "%${padding}s" | tr ' ' "$h")
        echo -e "${vr}${line} ${title} ${line}${vl}"
    else
        local line=$(printf "%${width}s" | tr ' ' "$h")
        echo -e "${vr}${line}${vl}"
    fi
}

# ============================================================================
# Styled Headers
# ============================================================================

# Main banner header
draw_banner() {
    local title="$1"
    local subtitle="$2"
    local width=70

    echo -e ""
    echo -e "${BRIGHT_MAGENTA}${DBOX_TL}$(printf "%${width}s" | tr ' ' "$DBOX_H")${DBOX_TR}${NC}"
    echo -e "${BRIGHT_MAGENTA}${DBOX_V}${NC}$(printf "%$(( (width - ${#title}) / 2 ))s")${BOLD}${BRIGHT_CYAN}${title}${NC}$(printf "%$(( (width - ${#title}) / 2 ))s")${BRIGHT_MAGENTA}${DBOX_V}${NC}"

    if [[ -n "$subtitle" ]]; then
        echo -e "${BRIGHT_MAGENTA}${DBOX_V}${NC}$(printf "%$(( (width - ${#subtitle}) / 2 ))s")${CYAN}${subtitle}${NC}$(printf "%$(( (width - ${#subtitle}) / 2 ))s")${BRIGHT_MAGENTA}${DBOX_V}${NC}"
    fi

    echo -e "${BRIGHT_MAGENTA}${DBOX_BL}$(printf "%${width}s" | tr ' ' "$DBOX_H")${DBOX_BR}${NC}"
    echo -e ""
}

# Section header
draw_section_header() {
    local title="$1"
    local color="${2:-$BRIGHT_CYAN}"
    local width=70

    echo -e ""
    echo -e "${color}${HBOX_TL}$(printf "%${width}s" | tr ' ' "$HBOX_H")${HBOX_TR}${NC}"
    echo -e "${color}${HBOX_V}${NC} ${BOLD}${color}${title}${NC}$(printf "%$(( width - ${#title} - 1 ))s")${color}${HBOX_V}${NC}"
    echo -e "${color}${HBOX_BL}$(printf "%${width}s" | tr ' ' "$HBOX_H")${HBOX_BR}${NC}"
    echo -e ""
}

# Subsection divider
draw_divider() {
    local title="$1"
    local width=70

    if [[ -n "$title" ]]; then
        local title_len=${#title}
        local padding=$(( (width - title_len - 2) / 2 ))
        echo -e "${CYAN}$(printf "%${padding}s" | tr ' ' "$BOX_H") ${BOLD}${title}${NC}${CYAN} $(printf "%${padding}s" | tr ' ' "$BOX_H")${NC}"
    else
        echo -e "${CYAN}$(printf "%${width}s" | tr ' ' "$BOX_H")${NC}"
    fi
}

# ============================================================================
# Status Indicators
# ============================================================================

# Success message
show_success() {
    local message="$1"
    echo -e "${COLOR_SUCCESS}${BULLET_CHECK}${NC} ${BOLD}${message}${NC}"
}

# Error message
show_error() {
    local message="$1"
    echo -e "${COLOR_ERROR}${BULLET_X}${NC} ${BOLD}${message}${NC}"
}

# Warning message
show_warning() {
    local message="$1"
    echo -e "${COLOR_WARNING}${BULLET_WARN}${NC} ${BOLD}${message}${NC}"
}

# Info message
show_info() {
    local message="$1"
    echo -e "${COLOR_INFO}${BULLET_INFO}${NC} ${message}"
}

# Loading message
show_loading() {
    local message="$1"
    echo -e "${COLOR_PRIMARY}${ARROW_RIGHT}${NC} ${ITALIC}${message}...${NC}"
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local message="$3"
    local width=30

    local percent=$(( current * 100 / total ))
    local filled=$(( width * current / total ))
    local empty=$(( width - filled ))

    local bar="${GREEN}${BLOCK_FULL}${NC}"
    local fill=$(printf "${bar}%.0s" $(seq 1 $filled))
    local space=$(printf " %.0s" $(seq 1 $empty))

    echo -ne "\r${CYAN}[${fill}${space}${CYAN}]${NC} ${percent}% ${message}"

    if [[ $current -eq $total ]]; then
        echo ""  # New line when complete
    fi
}

# ============================================================================
# Menu Formatting
# ============================================================================

# Format menu item with icon
format_menu_item() {
    local icon="$1"
    local text="$2"
    local service_detected="${3:-false}"

    if [[ "$service_detected" == "true" ]]; then
        echo "${BRIGHT_GREEN}${BULLET}${NC} ${BRIGHT_CYAN}${text}${NC}"
    else
        echo "${DIM}${BULLET_HOLLOW}${NC} ${text}"
    fi
}

# Format menu category
format_category() {
    local title="$1"
    local width=40

    echo "${BRIGHT_MAGENTA}${BOX_VR}${BOX_H}${BOX_H} ${BOLD}${title}${NC} ${BRIGHT_MAGENTA}$(printf "%$(( width - ${#title} - 5 ))s" | tr ' ' "$BOX_H")${NC}"
}

# ============================================================================
# Table Drawing
# ============================================================================

# Draw table header
draw_table_header() {
    local -a headers=("$@")
    local col_width=20

    # Top border
    echo -en "${BOX_TL}"
    for header in "${headers[@]}"; do
        echo -en "$(printf "%${col_width}s" | tr ' ' "$BOX_H")${BOX_HD}"
    done
    echo -e "\b${BOX_TR}"

    # Headers
    echo -en "${BOX_V}"
    for header in "${headers[@]}"; do
        local padding=$(( (col_width - ${#header}) / 2 ))
        printf " %${padding}s${BOLD}${BRIGHT_CYAN}%s${NC}%${padding}s ${BOX_V}" "" "$header" ""
    done
    echo ""

    # Separator
    echo -en "${BOX_VR}"
    for header in "${headers[@]}"; do
        echo -en "$(printf "%${col_width}s" | tr ' ' "$BOX_H")${BOX_X}"
    done
    echo -e "\b${BOX_VL}"
}

# Draw table row
draw_table_row() {
    local -a values=("$@")
    local col_width=20

    echo -en "${BOX_V}"
    for value in "${values[@]}"; do
        printf " %-${col_width}s${BOX_V}" "$value"
    done
    echo ""
}

# Draw table footer
draw_table_footer() {
    local num_cols=$1
    local col_width=20

    echo -en "${BOX_BL}"
    for (( i=0; i<num_cols; i++ )); do
        echo -en "$(printf "%${col_width}s" | tr ' ' "$BOX_H")${BOX_HU}"
    done
    echo -e "\b${BOX_BR}"
}

# ============================================================================
# Context Display
# ============================================================================

# Show workspace context
draw_context_bar() {
    local workspace="$1"
    local target="$2"
    local creds="$3"
    local mode="$4"

    echo -e "${CYAN}${BOX_TL}$(printf "%68s" | tr ' ' "$BOX_H")${BOX_TR}${NC}"
    echo -e "${CYAN}${BOX_V}${NC} ${BOLD}Workspace:${NC} ${BRIGHT_CYAN}${workspace}${NC} ${CYAN}${BOX_V}${NC} ${BOLD}Target:${NC} ${BRIGHT_GREEN}${target}${NC} ${CYAN}${BOX_V}${NC} ${BOLD}Creds:${NC} ${YELLOW}${creds}${NC} ${CYAN}${BOX_V}${NC} ${BOLD}Mode:${NC} ${MAGENTA}${mode}${NC} ${CYAN}${BOX_V}${NC}"
    echo -e "${CYAN}${BOX_BL}$(printf "%68s" | tr ' ' "$BOX_H")${BOX_BR}${NC}"
}

# Show keyboard shortcuts
draw_shortcuts_bar() {
    local -a shortcuts=("$@")

    echo -e ""
    echo -e "${DIM}${BULLET} Shortcuts: ${NC}"
    for shortcut in "${shortcuts[@]}"; do
        local key=$(echo "$shortcut" | cut -d: -f1)
        local desc=$(echo "$shortcut" | cut -d: -f2)
        echo -e "  ${BRIGHT_CYAN}[${BOLD}${key}${NC}${BRIGHT_CYAN}]${NC} ${desc}"
    done
    echo -e ""
}

# ============================================================================
# Enhanced Banner with Color Gradient
# ============================================================================

show_enhanced_banner() {
    local workspace="${1:-default}"
    local version="${2:-1.0}"

    echo -e ""
    # Top border with gradient effect
    echo -e "${BRIGHT_MAGENTA}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}                                                                           ${BRIGHT_MAGENTA}║${NC}"
    # PURPLE line
    echo -e "${BRIGHT_MAGENTA}║${NC}   ${BRIGHT_MAGENTA}██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗███████╗██████╗${NC}       ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}   ${BRIGHT_MAGENTA}██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗${NC}      ${BRIGHT_MAGENTA}║${NC}"
    # Transition to cyan
    echo -e "${BRIGHT_MAGENTA}║${NC}   ${MAGENTA}██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗  ███████╗██████╔╝${NC}      ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}   ${CYAN}██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝  ╚════██║██╔═══╝${NC}       ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}   ${BRIGHT_CYAN}██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗███████║██║${NC}           ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}   ${BRIGHT_CYAN}╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝${NC}           ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}                                                                           ${BRIGHT_MAGENTA}║${NC}"
    # SPLOIT in different gradient
    echo -e "${BRIGHT_MAGENTA}║${NC}         ${BRIGHT_CYAN}███████╗██████╗  █████╗ ███╗   ███╗███████╗${NC}${BRIGHT_GREEN}██╗    ██╗${NC} ${BRIGHT_YELLOW}██████╗${NC}    ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}         ${BRIGHT_CYAN}██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝${NC}${BRIGHT_GREEN}██║    ██║${NC}${BRIGHT_YELLOW}██╔═══██╗${NC}   ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}         ${CYAN}█████╗  ██████╔╝███████║██╔████╔██║█████╗${NC}  ${GREEN}██║ █╗ ██║${NC}${YELLOW}██║   ██║${NC}   ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}         ${CYAN}██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝${NC}  ${GREEN}██║███╗██║${NC}${YELLOW}██║   ██║${NC}   ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}         ${BRIGHT_BLUE}██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗${NC}${BRIGHT_GREEN}╚███╔███╔╝${NC}${BRIGHT_YELLOW}╚██████╔╝${NC}   ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}         ${BRIGHT_BLUE}╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝${NC}${BRIGHT_GREEN} ╚══╝╚══╝${NC} ${BRIGHT_YELLOW}╚═════╝${NC}    ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}                                                                           ${BRIGHT_MAGENTA}║${NC}"
    # Subtitle with color
    echo -e "${BRIGHT_MAGENTA}║${NC}           ${DIM}${CYAN}Metasploit-Style Offensive Security Framework${NC}              ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}                ${DIM}Version ${version} | Workspace: ${BRIGHT_CYAN}${workspace}${NC}                     ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}║${NC}                                                                           ${BRIGHT_MAGENTA}║${NC}"
    echo -e "${BRIGHT_MAGENTA}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
}

# Enhanced context bar with better colors
draw_enhanced_context() {
    local workspace="$1"
    local target="$2"
    local creds="$3"
    local mode="$4"

    # Use colors to indicate status
    local target_color="${BRIGHT_RED}"
    [[ -n "$target" && "$target" != "<none>" ]] && target_color="${BRIGHT_GREEN}"

    local creds_color="${BRIGHT_RED}"
    [[ -n "$creds" && "$creds" != "<none>" ]] && creds_color="${BRIGHT_YELLOW}"

    echo -e "${BRIGHT_CYAN}┌────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BRIGHT_CYAN}│${NC} ${BOLD}${BRIGHT_MAGENTA}⚡ Workspace:${NC} ${BRIGHT_CYAN}${workspace}${NC} ${BRIGHT_CYAN}│${NC} ${BOLD}${BRIGHT_MAGENTA}🎯 Target:${NC} ${target_color}${target}${NC} ${BRIGHT_CYAN}│${NC} ${BOLD}${BRIGHT_MAGENTA}🔐 Creds:${NC} ${creds_color}${creds}${NC} ${BRIGHT_CYAN}│${NC} ${BOLD}${BRIGHT_MAGENTA}⚙️  Mode:${NC} ${MAGENTA}${mode}${NC} ${BRIGHT_CYAN}│${NC}"
    echo -e "${BRIGHT_CYAN}└────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo -e ""
}

# Enhanced menu category headers with color and style
draw_menu_category() {
    local icon="$1"
    local title="$2"
    local color="${3:-$BRIGHT_CYAN}"
    local width=76

    local title_full="$icon $title"
    local title_len=${#title_full}
    local line_len=$(( (width - title_len - 2) ))

    echo -e "${color}┌─ ${BOLD}${title_full}${NC}${color} $(printf "%${line_len}s" | tr ' ' '─')${NC}"
}

# Color-coded menu items based on status
draw_menu_item() {
    local icon="$1"
    local text="$2"
    local status="${3:-normal}"  # normal, active, inactive, recommended

    case "$status" in
        active)
            echo -e "${BRIGHT_GREEN}●${NC} ${BRIGHT_CYAN}${text}${NC}"
            ;;
        recommended)
            echo -e "${BRIGHT_YELLOW}★${NC} ${BRIGHT_WHITE}${text}${NC}"
            ;;
        inactive)
            echo -e "${DIM}○ ${text}${NC}"
            ;;
        *)
            echo -e "${CYAN}▸${NC} ${text}"
            ;;
    esac
}

# Loading animation for initialization
show_init_progress() {
    local message="$1"
    local step="$2"
    local total="$3"

    local percent=$(( step * 100 / total ))
    local bar_width=30
    local filled=$(( bar_width * step / total ))

    echo -ne "\r${BRIGHT_CYAN}[${NC}"
    for ((i=0; i<bar_width; i++)); do
        if [ $i -lt $filled ]; then
            echo -ne "${BRIGHT_MAGENTA}━${NC}"
        else
            echo -ne "${DIM}━${NC}"
        fi
    done
    echo -ne "${BRIGHT_CYAN}]${NC} ${BRIGHT_GREEN}${percent}%${NC} ${message}..."

    if [ $step -eq $total ]; then
        echo ""
    fi
}

# Styled shortcuts help
draw_shortcuts_help() {
    echo -e ""
    echo -e "${DIM}┌─ Keyboard Shortcuts ─────────────────────────────────────────────────────┐${NC}"
    echo -e "${DIM}│${NC} ${BRIGHT_CYAN}CTRL+T${NC}:targets  ${BRIGHT_CYAN}CTRL+C${NC}:creds   ${BRIGHT_CYAN}CTRL+W${NC}:web    ${BRIGHT_CYAN}CTRL+D${NC}:AD     ${BRIGHT_CYAN}CTRL+A${NC}:auth ${DIM}│${NC}"
    echo -e "${DIM}│${NC} ${BRIGHT_CYAN}CTRL+S${NC}:select   ${BRIGHT_CYAN}CTRL+J${NC}:jobs    ${BRIGHT_CYAN}CTRL+M${NC}:mode   ${BRIGHT_CYAN}Type${NC} to filter    ${DIM}│${NC}"
    echo -e "${DIM}└──────────────────────────────────────────────────────────────────────────┘${NC}"
}

# Service indicator with color
show_service_indicator() {
    local detected="${1:-false}"

    if [[ "$detected" == "true" ]]; then
        echo -e "${BRIGHT_GREEN}●${NC}"
    else
        echo -e "${DIM}○${NC}"
    fi
}

# ============================================================================
# Export Functions
# ============================================================================

export -f draw_box
export -f draw_box_bottom
export -f draw_box_line
export -f draw_separator
export -f draw_banner
export -f draw_section_header
export -f draw_divider
export -f show_success
export -f show_error
export -f show_warning
export -f show_info
export -f show_loading
export -f show_progress
export -f format_menu_item
export -f format_category
export -f draw_table_header
export -f draw_table_row
export -f draw_table_footer
export -f draw_context_bar
export -f draw_shortcuts_bar
export -f show_enhanced_banner
export -f draw_enhanced_context
export -f draw_menu_category
export -f draw_menu_item
export -f show_init_progress
export -f draw_shortcuts_help
export -f show_service_indicator
