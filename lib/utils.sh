#!/bin/bash
#
# Utility Functions
# Helper functions and utilities for the framework
#

# Find NXC download directory
find_nxc_downloads() {
    # NetExec saves spider_plus downloads to ~/.nxc/modules/nxc_spider_plus
    local dirs=(
        "$HOME/.nxc/modules/nxc_spider_plus"
        "$HOME/.nxc/modules"
        "$HOME/.nxc/logs"
        "/tmp/nxc_hosted/nxc_spider_plus"
        "/tmp/nxc"
    )

    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]] && [[ $(find "$dir" -type f 2>/dev/null | wc -l) -gt 0 ]]; then
            echo "$dir"
            return 0
        fi
    done

    echo "$HOME/.nxc/modules/nxc_spider_plus"
    return 1
}

# Show downloaded files intelligently
show_downloads() {
    echo -e "\n${GREEN}Searching for downloaded files...${NC}\n"

    local found=0
    local dirs=(
        "$HOME/.nxc/modules/nxc_spider_plus"
        "$HOME/.nxc/modules"
        "$HOME/.nxc/logs"
        "/tmp/nxc_hosted/nxc_spider_plus"
        "/tmp/nxc"
    )

    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local file_count=$(find "$dir" -type f 2>/dev/null | wc -l)
            if [[ $file_count -gt 0 ]]; then
                echo -e "${GREEN}═══ Found $file_count files in: $dir ═══${NC}"
                ls -lhR "$dir" 2>/dev/null | tail -50
                echo ""
                found=1
            fi
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo -e "${YELLOW}No files found in common NXC locations.${NC}"
        echo -e "${CYAN}NXC spider_plus saves to:${NC}"
        echo -e "  • $HOME/.nxc/modules/nxc_spider_plus/"
        echo -e "  • $HOME/.nxc/logs/"
        echo -e ""
        echo -e "${CYAN}Search manually with:${NC}"
        echo -e "  find ~/.nxc -name '*spider*' -type f 2>/dev/null"
    fi

    read -p "Press Enter to continue..."
}
