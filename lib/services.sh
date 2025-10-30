#!/bin/bash
#
# Services Detection
# Functions for checking detected services from nmap scans
#
# This module provides:
# - Checking if services are detected for a target
# - Getting port information for services (including non-standard ports)
# - Helper functions for each service type
#
# Required global variables:
# - SERVICES_DB
# - TARGET
# - RED, GREEN, YELLOW, CYAN, NC (colors)
#

# Check if a specific service is detected for the current target
# Usage: has_service <target_ip> <service_type>
# Returns: 0 if service is found, 1 otherwise
has_service() {
    local target_ip="$1"
    local service_type="$2"

    if [[ ! -f "$SERVICES_DB" ]]; then
        return 1
    fi

    # Format: IP|HOSTNAME|SERVICE_TYPE|PORT|IS_STANDARD_PORT
    grep -q "^${target_ip}|.*|${service_type}|" "$SERVICES_DB" 2>/dev/null
    return $?
}

# Get the port for a specific service on a target
# Usage: get_service_port <target_ip> <service_type>
# Returns: port number or empty string if not found
get_service_port() {
    local target_ip="$1"
    local service_type="$2"

    if [[ ! -f "$SERVICES_DB" ]]; then
        echo ""
        return 1
    fi

    # Format: IP|HOSTNAME|SERVICE_TYPE|PORT|IS_STANDARD_PORT
    local port=$(grep "^${target_ip}|.*|${service_type}|" "$SERVICES_DB" 2>/dev/null | head -n1 | cut -d'|' -f4)
    echo "$port"
}

# Check if a service is using a non-standard port
# Usage: is_nonstandard_port <target_ip> <service_type>
# Returns: 0 if non-standard, 1 if standard or not found
is_nonstandard_port() {
    local target_ip="$1"
    local service_type="$2"

    if [[ ! -f "$SERVICES_DB" ]]; then
        return 1
    fi

    # Format: IP|HOSTNAME|SERVICE_TYPE|PORT|IS_STANDARD_PORT
    local is_standard=$(grep "^${target_ip}|.*|${service_type}|" "$SERVICES_DB" 2>/dev/null | head -n1 | cut -d'|' -f5)

    if [[ "$is_standard" == "no" ]]; then
        return 0
    else
        return 1
    fi
}

# Get all detected services for a target
# Usage: get_target_services <target_ip>
# Returns: space-separated list of service types
get_target_services() {
    local target_ip="$1"

    if [[ ! -f "$SERVICES_DB" ]]; then
        echo ""
        return 1
    fi

    # Format: IP|HOSTNAME|SERVICE_TYPE|PORT|IS_STANDARD_PORT
    grep "^${target_ip}|" "$SERVICES_DB" 2>/dev/null | cut -d'|' -f3 | sort -u | tr '\n' ' '
}

# Print service detection status for current target
print_service_status() {
    local target_ip="$1"

    if [[ -z "$target_ip" ]]; then
        return 1
    fi

    local services=$(get_target_services "$target_ip")

    if [[ -z "$services" ]]; then
        echo -e "${YELLOW}No services detected for this target${NC}"
        return 1
    fi

    echo -e "${CYAN}Detected Services:${NC}"
    for service in $services; do
        local port=$(get_service_port "$target_ip" "$service")
        if is_nonstandard_port "$target_ip" "$service"; then
            echo -e "  ${GREEN}✓${NC} ${service^^} (port ${port})"
        else
            echo -e "  ${GREEN}✓${NC} ${service^^}"
        fi
    done
}

# Highlight menu option if service is detected
# Usage: highlight_if_active <target_ip> <service_type> <menu_text>
# Returns: menu text with highlight if service is active
highlight_if_active() {
    local target_ip="$1"
    local service_type="$2"
    local menu_text="$3"

    if has_service "$target_ip" "$service_type"; then
        echo "● $menu_text"
    else
        echo "$menu_text"
    fi
}

# Get port argument for nxc command if non-standard port
# Usage: get_port_arg <target_ip> <service_type>
# Returns: "-p PORT" if non-standard, empty string otherwise
get_port_arg() {
    local target_ip="$1"
    local service_type="$2"

    if is_nonstandard_port "$target_ip" "$service_type"; then
        local port=$(get_service_port "$target_ip" "$service_type")
        echo "-p $port"
    else
        echo ""
    fi
}

# Initialize services database if it doesn't exist
init_services_db() {
    if [[ ! -f "$SERVICES_DB" ]]; then
        touch "$SERVICES_DB"
    fi
}
