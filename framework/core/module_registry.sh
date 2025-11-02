#!/bin/bash
#
# ModuleRegistry - Module Discovery and Management System
# Part of PurpleSploit Framework
#
# This module handles:
# - Automatic discovery of .psm module files
# - Module metadata loading and validation
# - Module search and filtering
# - Module information display
#
# Module File Format (.psm):
#   MODULE_NAME="category/tool/action"
#   MODULE_CATEGORY="category"
#   MODULE_DESCRIPTION="Description"
#   MODULE_AUTHOR="Author"
#   MODULE_TOOL="tool_binary"
#   REQUIRED_VARS="VAR1,VAR2"
#   OPTIONAL_VARS="VAR1:default1,VAR2:default2"
#   COMMAND_TEMPLATE="tool \${VAR1} \${VAR2}"
#   OUTPUT_PARSER="parser_function"
#

# Module storage
# Initialize associative arrays without declare to ensure global scope
# These will be set up properly in module_registry_init
CURRENT_MODULE=""
CURRENT_MODULE_PATH=""

# Initialize module registry
module_registry_init() {
    local modules_dir="$1"

    if [[ ! -d "$modules_dir" ]]; then
        echo "[!] Error: Modules directory not found: $modules_dir"
        return 1
    fi

    echo "[*] Discovering modules in $modules_dir..."

    # Find all .psm files using mapfile (avoids subshell issues)
    local module_count=0
    local -a module_files

    # Use mapfile to read find output into array
    mapfile -t module_files < <(find "$modules_dir" -type f -name "*.psm")

    # Load each module
    for module_file in "${module_files[@]}"; do
        if module_load_metadata "$module_file"; then
            ((module_count++)) || true
        fi
    done

    echo "[+] Loaded $module_count modules"
    return 0
}

# Load module metadata from .psm file
# Usage: module_load_metadata "/path/to/module.psm"
module_load_metadata() {
    local module_file="$1"

    if [[ ! -f "$module_file" ]]; then
        echo "[!] Error: Module file not found: $module_file"
        return 1
    fi

    # Create a subshell to load module variables without polluting current scope
    local metadata=$(
        # Reset variables
        MODULE_NAME=""
        MODULE_CATEGORY=""
        MODULE_DESCRIPTION=""
        MODULE_AUTHOR=""
        MODULE_TOOL=""
        REQUIRED_VARS=""
        OPTIONAL_VARS=""
        COMMAND_TEMPLATE=""
        OUTPUT_PARSER=""

        # Source the module file
        source "$module_file" 2>/dev/null

        # Output metadata as key=value pairs
        echo "MODULE_NAME=$MODULE_NAME"
        echo "MODULE_CATEGORY=$MODULE_CATEGORY"
        echo "MODULE_DESCRIPTION=$MODULE_DESCRIPTION"
        echo "MODULE_AUTHOR=$MODULE_AUTHOR"
        echo "MODULE_TOOL=$MODULE_TOOL"
        echo "REQUIRED_VARS=$REQUIRED_VARS"
        echo "OPTIONAL_VARS=$OPTIONAL_VARS"
        echo "COMMAND_TEMPLATE=$COMMAND_TEMPLATE"
        echo "OUTPUT_PARSER=$OUTPUT_PARSER"
        echo "MODULE_FILE=$module_file"
    )

    # Parse metadata
    local module_name=""
    while IFS='=' read -r key value; do
        if [[ "$key" == "MODULE_NAME" ]]; then
            module_name="$value"
        fi

        # Store in metadata hash
        MODULE_METADATA["${module_name}:${key}"]="$value"
    done <<< "$metadata"

    # Validate module has required fields
    if [[ -z "$module_name" ]]; then
        echo "[!] Warning: Module missing MODULE_NAME: $module_file"
        return 1
    fi

    # Register module
    MODULE_REGISTRY[$module_name]="$module_file"
    MODULE_LIST+=("$module_name")

    return 0
}

# Get module metadata field
# Usage: module_get_field "module_name" "field_name"
module_get_field() {
    local module_name="$1"
    local field_name="$2"

    echo "${MODULE_METADATA[${module_name}:${field_name}]}"
}

# Set current module
# Usage: module_use "web/feroxbuster/basic_scan"
module_use() {
    local module_name="$1"

    # Check if module exists
    if [[ ! -v "MODULE_REGISTRY[$module_name]" ]]; then
        echo "[!] Error: Module not found: $module_name"
        echo "[*] Use 'search' to find available modules"
        return 1
    fi

    # Clear previous module-scoped variables
    var_clear_module_scope

    # Set current module
    CURRENT_MODULE="$module_name"
    CURRENT_MODULE_PATH="${MODULE_REGISTRY[$module_name]}"

    # Load optional variable defaults
    local optional_vars=$(module_get_field "$module_name" "OPTIONAL_VARS")
    if [[ -n "$optional_vars" ]]; then
        IFS=',' read -ra OPT_ARRAY <<< "$optional_vars"
        for opt_var in "${OPT_ARRAY[@]}"; do
            local var_name="${opt_var%%:*}"
            local var_default="${opt_var#*:}"

            # Only set if not already set globally
            if ! var_is_set "$var_name"; then
                var_set "$var_name" "$var_default" "module"
            fi
        done
    fi

    echo "[+] Using module: $module_name"
    return 0
}

# Get current module name
# Usage: module_get_current
module_get_current() {
    echo "$CURRENT_MODULE"
}

# Clear current module
# Usage: module_clear
module_clear() {
    CURRENT_MODULE=""
    CURRENT_MODULE_PATH=""
    var_clear_module_scope
}

# List all modules
# Usage: module_list_all
module_list_all() {
    echo ""
    echo "Available Modules:"
    echo "================================================================================"
    printf "%-50s %s\n" "Module Path" "Description"
    echo "--------------------------------------------------------------------------------"

    for module_name in "${MODULE_LIST[@]}"; do
        local description=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
        printf "%-50s %s\n" "$module_name" "$description"
    done

    echo "================================================================================"
    echo ""
    echo "Total: ${#MODULE_LIST[@]} modules"
    echo ""
}

# Search modules by keyword
# Usage: module_search "keyword"
module_search() {
    local keyword="$1"

    if [[ -z "$keyword" ]]; then
        echo "[!] Usage: search <keyword>"
        return 1
    fi

    echo ""
    echo "Search Results for: $keyword"
    echo "================================================================================"
    printf "%-50s %s\n" "Module Path" "Description"
    echo "--------------------------------------------------------------------------------"

    local found=0
    for module_name in "${MODULE_LIST[@]}"; do
        local description=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
        local category=$(module_get_field "$module_name" "MODULE_CATEGORY")
        local tool=$(module_get_field "$module_name" "MODULE_TOOL")

        # Search in name, description, category, and tool
        if [[ "$module_name" == *"$keyword"* ]] || \
           [[ "$description" == *"$keyword"* ]] || \
           [[ "$category" == *"$keyword"* ]] || \
           [[ "$tool" == *"$keyword"* ]]; then
            printf "%-50s %s\n" "$module_name" "$description"
            ((found++))
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo "No modules found matching: $keyword"
    fi

    echo "================================================================================"
    echo ""
    echo "Found: $found modules"
    echo ""
}

# Show module information
# Usage: module_info [module_name]
module_info() {
    local module_name="${1:-$CURRENT_MODULE}"

    if [[ -z "$module_name" ]]; then
        echo "[!] Error: No module selected. Use 'use <module>' first"
        return 1
    fi

    if [[ ! -v "MODULE_REGISTRY[$module_name]" ]]; then
        echo "[!] Error: Module not found: $module_name"
        return 1
    fi

    # Get metadata
    local description=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
    local category=$(module_get_field "$module_name" "MODULE_CATEGORY")
    local author=$(module_get_field "$module_name" "MODULE_AUTHOR")
    local tool=$(module_get_field "$module_name" "MODULE_TOOL")
    local required_vars=$(module_get_field "$module_name" "REQUIRED_VARS")
    local optional_vars=$(module_get_field "$module_name" "OPTIONAL_VARS")
    local command_template=$(module_get_field "$module_name" "COMMAND_TEMPLATE")
    local output_parser=$(module_get_field "$module_name" "OUTPUT_PARSER")
    local module_file=$(module_get_field "$module_name" "MODULE_FILE")

    echo ""
    echo "Module Information"
    echo "================================================================================"
    echo "       Name: $module_name"
    echo "   Category: $category"
    echo "Description: $description"
    echo "     Author: $author"
    echo "       Tool: $tool"
    echo "       Path: $module_file"
    echo ""
    echo "Required Variables:"
    if [[ -n "$required_vars" ]]; then
        IFS=',' read -ra REQ_ARRAY <<< "$required_vars"
        for var_name in "${REQ_ARRAY[@]}"; do
            var_name=$(echo "$var_name" | xargs)
            local var_value=$(var_get "$var_name" 2>/dev/null || echo "<not set>")
            local var_desc="${VAR_DESCRIPTIONS[$var_name]:-}"
            printf "  %-15s : %-30s %s\n" "$var_name" "$var_value" "$var_desc"
        done
    else
        echo "  None"
    fi

    echo ""
    echo "Optional Variables:"
    if [[ -n "$optional_vars" ]]; then
        IFS=',' read -ra OPT_ARRAY <<< "$optional_vars"
        for opt_var in "${OPT_ARRAY[@]}"; do
            local var_name="${opt_var%%:*}"
            local var_default="${opt_var#*:}"
            local var_value=$(var_get "$var_name" 2>/dev/null || echo "$var_default")
            local var_desc="${VAR_DESCRIPTIONS[$var_name]:-}"
            printf "  %-15s : %-30s %s\n" "$var_name" "$var_value" "$var_desc"
        done
    else
        echo "  None"
    fi

    echo ""
    echo "Command Template:"
    echo "  $command_template"
    echo ""

    if [[ -n "$output_parser" ]]; then
        echo "Output Parser: $output_parser"
        echo ""
    fi

    echo "================================================================================"
    echo ""
}

# List modules by category
# Usage: module_list_by_category "web"
module_list_by_category() {
    local category="$1"

    if [[ -z "$category" ]]; then
        # List all categories
        echo ""
        echo "Available Categories:"
        echo "================================================================================"

        local -A categories
        for module_name in "${MODULE_LIST[@]}"; do
            local cat=$(module_get_field "$module_name" "MODULE_CATEGORY")
            categories[$cat]=1
        done

        for cat in "${!categories[@]}"; do
            echo "  - $cat"
        done

        echo "================================================================================"
        echo ""
        return 0
    fi

    # List modules in category
    echo ""
    echo "Modules in category: $category"
    echo "================================================================================"
    printf "%-50s %s\n" "Module Path" "Description"
    echo "--------------------------------------------------------------------------------"

    local found=0
    for module_name in "${MODULE_LIST[@]}"; do
        local cat=$(module_get_field "$module_name" "MODULE_CATEGORY")
        if [[ "$cat" == "$category" ]]; then
            local description=$(module_get_field "$module_name" "MODULE_DESCRIPTION")
            printf "%-50s %s\n" "$module_name" "$description"
            ((found++))
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo "No modules found in category: $category"
    fi

    echo "================================================================================"
    echo ""
}

# Export functions
export -f module_registry_init
export -f module_load_metadata
export -f module_get_field
export -f module_use
export -f module_get_current
export -f module_clear
export -f module_list_all
export -f module_search
export -f module_info
export -f module_list_by_category
