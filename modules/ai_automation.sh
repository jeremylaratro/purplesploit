#!/bin/bash
#
# AI Automation Module
# Provides AI-assisted pentesting workflows using MCP server
#
# This module handles:
# - Launching AI assistants (OpenAI/Claude)
# - Configuring MCP server connections
# - Managing API keys
# - Interactive AI pentesting sessions
#
# Dependencies:
# - Python 3 with openai/anthropic packages
# - tools/ai_kali_client.py
# - MCP server running (optional, can use local)
#
# Global Variables (from config.sh):
# - Colors: RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, NC
# - SCRIPT_DIR: Root directory of PurpleSploit
#

# ============================================================================
# AI Automation Configuration
# ============================================================================
AI_CONFIG_FILE="$HOME/.purplesploit/ai_config"

load_ai_config() {
    if [[ -f "$AI_CONFIG_FILE" ]]; then
        source "$AI_CONFIG_FILE"
    fi
}

save_ai_config() {
    mkdir -p "$(dirname "$AI_CONFIG_FILE")"
    cat > "$AI_CONFIG_FILE" <<EOF
# AI Automation Configuration
AI_PROVIDER="${AI_PROVIDER:-}"
AI_MODEL="${AI_MODEL:-}"
MCP_SERVER_URL="${MCP_SERVER_URL:-}"
AI_TIMEOUT="${AI_TIMEOUT:-3600}"
EOF
    chmod 600 "$AI_CONFIG_FILE"
}

# ============================================================================
# AI Provider Configuration
# ============================================================================
configure_ai_provider() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     AI PROVIDER CONFIGURATION             ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    load_ai_config

    echo -e "${CYAN}Select AI Provider:${NC}"
    local provider=$(echo "OpenAI (GPT-4)
Claude (Anthropic)" | fzf --prompt="Provider: " --height=40% --reverse)

    case "$provider" in
        "OpenAI"*)
            AI_PROVIDER="openai"
            echo ""
            echo -e "${CYAN}Enter OpenAI Model [default: gpt-4o]:${NC}"
            read -p "Model: " model
            AI_MODEL="${model:-gpt-4o}"

            echo ""
            echo -e "${YELLOW}Set your API key:${NC}"
            echo -e "  ${GREEN}export OPENAI_API_KEY='your-key-here'${NC}"
            echo ""
            read -p "Press Enter to continue..."
            ;;
        "Claude"*)
            AI_PROVIDER="claude"
            echo ""
            echo -e "${CYAN}Enter Claude Model [default: claude-sonnet-4-20250514]:${NC}"
            read -p "Model: " model
            AI_MODEL="${model:-claude-sonnet-4-20250514}"

            echo ""
            echo -e "${YELLOW}Set your API key:${NC}"
            echo -e "  ${GREEN}export ANTHROPIC_API_KEY='your-key-here'${NC}"
            echo ""
            read -p "Press Enter to continue..."
            ;;
        *)
            echo -e "${RED}Cancelled${NC}"
            sleep 1
            return
            ;;
    esac

    save_ai_config
    echo -e "${GREEN}✓ AI provider configured!${NC}"
    sleep 2
}

# ============================================================================
# MCP Server Configuration
# ============================================================================
configure_mcp_server() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     MCP SERVER CONFIGURATION              ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    load_ai_config

    echo -e "${CYAN}Current MCP Server:${NC} ${MCP_SERVER_URL:-<not set>}"
    echo ""
    echo -e "${YELLOW}Enter MCP Server URL:${NC}"
    echo -e "${CYAN}Examples:${NC}"
    echo "  http://localhost:8000"
    echo "  http://192.168.1.100:8000"
    echo ""
    read -p "URL: " server_url

    if [[ -z "$server_url" ]]; then
        echo -e "${RED}Cancelled${NC}"
        sleep 1
        return
    fi

    MCP_SERVER_URL="$server_url"

    echo ""
    echo -e "${CYAN}Enter timeout in seconds [default: 3600]:${NC}"
    read -p "Timeout: " timeout
    AI_TIMEOUT="${timeout:-3600}"

    save_ai_config
    echo ""
    echo -e "${GREEN}✓ MCP server configured!${NC}"
    sleep 2
}

# ============================================================================
# Launch AI Assistant
# ============================================================================
launch_ai_assistant() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     LAUNCH AI ASSISTANT                   ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    load_ai_config

    # Check configuration
    if [[ -z "$AI_PROVIDER" ]]; then
        echo -e "${RED}❌ AI provider not configured!${NC}"
        echo -e "${YELLOW}Please configure AI provider first.${NC}"
        sleep 3
        return 1
    fi

    if [[ -z "$MCP_SERVER_URL" ]]; then
        echo -e "${RED}❌ MCP server not configured!${NC}"
        echo -e "${YELLOW}Please configure MCP server first.${NC}"
        sleep 3
        return 1
    fi

    # Check API key
    if [[ "$AI_PROVIDER" == "openai" ]] && [[ -z "$OPENAI_API_KEY" ]]; then
        echo -e "${RED}❌ OPENAI_API_KEY not set!${NC}"
        echo ""
        echo -e "${YELLOW}Set it with:${NC}"
        echo -e "  ${GREEN}export OPENAI_API_KEY='your-key-here'${NC}"
        echo ""
        read -p "Press Enter to continue..."
        return 1
    fi

    if [[ "$AI_PROVIDER" == "claude" ]] && [[ -z "$ANTHROPIC_API_KEY" ]]; then
        echo -e "${RED}❌ ANTHROPIC_API_KEY not set!${NC}"
        echo ""
        echo -e "${YELLOW}Set it with:${NC}"
        echo -e "  ${GREEN}export ANTHROPIC_API_KEY='your-key-here'${NC}"
        echo ""
        read -p "Press Enter to continue..."
        return 1
    fi

    # Display configuration
    echo -e "${CYAN}Configuration:${NC}"
    echo -e "  Provider: ${GREEN}$AI_PROVIDER${NC}"
    echo -e "  Model: ${GREEN}${AI_MODEL:-default}${NC}"
    echo -e "  Server: ${GREEN}$MCP_SERVER_URL${NC}"
    echo -e "  Timeout: ${GREEN}${AI_TIMEOUT}s${NC}"
    echo ""

    # Check Python script exists
    local ai_client="$SCRIPT_DIR/tools/ai_kali_client.py"
    if [[ ! -f "$ai_client" ]]; then
        echo -e "${RED}❌ AI client not found at: $ai_client${NC}"
        sleep 3
        return 1
    fi

    echo -e "${GREEN}🚀 Launching AI assistant...${NC}"
    echo ""
    sleep 1

    # Build command
    local cmd="python3 '$ai_client' --server '$MCP_SERVER_URL' --provider '$AI_PROVIDER' --timeout $AI_TIMEOUT"
    if [[ -n "$AI_MODEL" ]]; then
        cmd="$cmd --model '$AI_MODEL'"
    fi

    # Execute
    eval "$cmd"

    echo ""
    echo -e "${CYAN}AI session ended.${NC}"
    read -p "Press Enter to continue..."
}

# ============================================================================
# Check Dependencies
# ============================================================================
check_ai_dependencies() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     AI AUTOMATION DEPENDENCIES            ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""

    local all_ok=true

    # Check Python
    if command -v python3 &> /dev/null; then
        echo -e "${GREEN}✓${NC} Python 3: $(python3 --version)"
    else
        echo -e "${RED}✗${NC} Python 3: Not found"
        all_ok=false
    fi

    # Check pip
    if command -v pip3 &> /dev/null; then
        echo -e "${GREEN}✓${NC} pip3: $(pip3 --version | cut -d' ' -f2)"
    else
        echo -e "${RED}✗${NC} pip3: Not found"
        all_ok=false
    fi

    # Check openai package
    if python3 -c "import openai" 2>/dev/null; then
        local openai_ver=$(python3 -c "import openai; print(openai.__version__)" 2>/dev/null)
        echo -e "${GREEN}✓${NC} openai package: $openai_ver"
    else
        echo -e "${YELLOW}○${NC} openai package: Not installed (required for OpenAI)"
    fi

    # Check anthropic package
    if python3 -c "import anthropic" 2>/dev/null; then
        local anthropic_ver=$(python3 -c "import anthropic; print(anthropic.__version__)" 2>/dev/null)
        echo -e "${GREEN}✓${NC} anthropic package: $anthropic_ver"
    else
        echo -e "${YELLOW}○${NC} anthropic package: Not installed (required for Claude)"
    fi

    # Check requests package
    if python3 -c "import requests" 2>/dev/null; then
        local requests_ver=$(python3 -c "import requests; print(requests.__version__)" 2>/dev/null)
        echo -e "${GREEN}✓${NC} requests package: $requests_ver"
    else
        echo -e "${RED}✗${NC} requests package: Not installed (required)"
        all_ok=false
    fi

    echo ""

    if [[ "$all_ok" == "false" ]]; then
        echo -e "${YELLOW}Install missing dependencies:${NC}"
        echo -e "  ${GREEN}pip3 install --user openai anthropic requests${NC}"
        echo ""
    else
        echo -e "${GREEN}✓ All dependencies satisfied!${NC}"
        echo ""
    fi

    read -p "Press Enter to continue..."
}

# ============================================================================
# AI Automation Main Menu
# ============================================================================
handle_ai_automation() {
    while true; do
        load_ai_config

        local header="AI Provider: ${AI_PROVIDER:-<not set>} | Server: ${MCP_SERVER_URL:-<not set>}"

        local choice=$(echo "┌ AI ASSISTANT ──────────────────────────
Launch AI Assistant
Configure AI Provider
Configure MCP Server
┌ UTILITIES ─────────────────────────────
Check Dependencies
View Current Configuration
Test MCP Connection
┌ NAVIGATION ────────────────────────────
Back to Main Menu" | fzf \
            --prompt="AI Automation: " \
            --height=80% \
            --reverse \
            --header="$header")

        case "$choice" in
            "Launch AI Assistant")
                launch_ai_assistant
                ;;
            "Configure AI Provider")
                configure_ai_provider
                ;;
            "Configure MCP Server")
                configure_mcp_server
                ;;
            "Check Dependencies")
                check_ai_dependencies
                ;;
            "View Current Configuration")
                clear
                echo -e "${CYAN}Current Configuration:${NC}"
                echo ""
                load_ai_config
                echo -e "  AI Provider: ${AI_PROVIDER:-<not set>}"
                echo -e "  AI Model: ${AI_MODEL:-<not set>}"
                echo -e "  MCP Server: ${MCP_SERVER_URL:-<not set>}"
                echo -e "  Timeout: ${AI_TIMEOUT:-3600}s"
                echo -e "  Config File: $AI_CONFIG_FILE"
                echo ""
                read -p "Press Enter to continue..."
                ;;
            "Test MCP Connection")
                clear
                echo -e "${CYAN}Testing MCP connection...${NC}"
                if [[ -z "$MCP_SERVER_URL" ]]; then
                    echo -e "${RED}❌ MCP server not configured${NC}"
                else
                    echo -e "Server: $MCP_SERVER_URL"
                    if curl -s -f "$MCP_SERVER_URL/health" &>/dev/null; then
                        echo -e "${GREEN}✓ Connection successful!${NC}"
                    else
                        echo -e "${RED}✗ Connection failed${NC}"
                    fi
                fi
                echo ""
                read -p "Press Enter to continue..."
                ;;
            "Back to Main Menu"|"")
                return
                ;;
        esac
    done
}

# Export functions for use in main script
export -f handle_ai_automation
export -f launch_ai_assistant
export -f configure_ai_provider
export -f configure_mcp_server
export -f check_ai_dependencies
export -f load_ai_config
export -f save_ai_config
