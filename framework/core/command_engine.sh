#!/bin/bash
#
# CommandEngine - Command Building and Execution System
# Part of PurpleSploit Framework
#
# This module handles:
# - Building commands from module templates
# - Variable substitution in command templates
# - Command preview and editing
# - Command execution with output capture
# - Command history tracking
# - Job management for background execution
#
# Features:
# - Interactive command editing before execution
# - Command history with search
# - Background job execution
# - Output redirection and logging
# - Exit code tracking
#

# Command history storage
COMMAND_HISTORY=()
COMMAND_HISTORY_FILE="$HOME/.purplesploit/command_history"

# Job management
declare -A ACTIVE_JOBS
JOB_COUNTER=0

# Colors
CMD_COLOR='\033[0;36m'
SUCCESS_COLOR='\033[0;32m'
ERROR_COLOR='\033[0;31m'
WARNING_COLOR='\033[1;33m'
NC='\033[0m'

# Initialize command engine
command_engine_init() {
    # Create history file if it doesn't exist
    mkdir -p "$(dirname "$COMMAND_HISTORY_FILE")"
    touch "$COMMAND_HISTORY_FILE"

    # Load command history
    if [[ -f "$COMMAND_HISTORY_FILE" ]]; then
        mapfile -t COMMAND_HISTORY < "$COMMAND_HISTORY_FILE"
    fi
}

# Build command from current module
# Usage: command_build
command_build() {
    local module_name=$(module_get_current)

    if [[ -z "$module_name" ]]; then
        echo -e "${ERROR_COLOR}[!] Error: No module selected. Use 'use <module>' first${NC}"
        return 1
    fi

    # Get command template
    local template=$(module_get_field "$module_name" "COMMAND_TEMPLATE")

    if [[ -z "$template" ]]; then
        echo -e "${ERROR_COLOR}[!] Error: Module has no command template${NC}"
        return 1
    fi

    # Validate required variables
    local required_vars=$(module_get_field "$module_name" "REQUIRED_VARS")
    if [[ -n "$required_vars" ]]; then
        if ! var_validate_required "$required_vars"; then
            echo -e "${WARNING_COLOR}[*] Use 'show options' to see required variables${NC}"
            return 1
        fi
    fi

    # Substitute variables in template
    local command=$(var_substitute "$template")

    echo "$command"
    return 0
}

# Preview command before execution
# Usage: command_preview
command_preview() {
    local command=$(command_build)

    if [[ $? -ne 0 ]]; then
        return 1
    fi

    echo ""
    echo -e "${CMD_COLOR}Command Preview:${NC}"
    echo "================================================================================"
    echo "$command"
    echo "================================================================================"
    echo ""

    return 0
}

# Execute command with interactive preview
# Usage: command_run [options]
#   -y, --yes       Skip confirmation
#   -j, --job       Run in background
#   -o, --output    Output file path
command_run() {
    local skip_confirm=false
    local run_background=false
    local output_file=""

    # Parse options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -y|--yes)
                skip_confirm=true
                shift
                ;;
            -j|--job)
                run_background=true
                shift
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    # Build command
    local command=$(command_build)

    if [[ $? -ne 0 ]]; then
        return 1
    fi

    # Preview command
    echo ""
    echo -e "${CMD_COLOR}Command to execute:${NC}"
    echo "================================================================================"
    echo "$command"
    echo "================================================================================"
    echo ""

    # Confirm or allow editing
    if [[ "$skip_confirm" != true ]]; then
        echo "Options:"
        echo "  [r] Run command"
        echo "  [e] Edit command"
        echo "  [c] Cancel"
        echo ""
        read -p "Choice [r/e/c]: " choice

        case "$choice" in
            e|E)
                # Allow user to edit command
                read -e -i "$command" -p "Edit command: " edited_command
                command="$edited_command"
                ;;
            c|C)
                echo "Cancelled."
                return 0
                ;;
            r|R|"")
                # Continue with execution
                ;;
            *)
                echo "Invalid choice. Cancelled."
                return 0
                ;;
        esac
    fi

    # Save to history
    command_history_add "$command"

    # Execute command
    if [[ "$run_background" == true ]]; then
        command_execute_background "$command" "$output_file"
    else
        command_execute_foreground "$command" "$output_file"
    fi

    return $?
}

# Execute command in foreground
# Usage: command_execute_foreground "command" [output_file]
command_execute_foreground() {
    local command="$1"
    local output_file="$2"

    echo ""
    echo -e "${SUCCESS_COLOR}[*] Executing command...${NC}"
    echo ""

    local start_time=$(date +%s)

    # Execute command
    if [[ -n "$output_file" ]]; then
        # Redirect output to file and show on screen
        eval "$command" 2>&1 | tee "$output_file"
        local exit_code=${PIPESTATUS[0]}
    else
        # Just execute
        eval "$command"
        local exit_code=$?
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${SUCCESS_COLOR}[+] Command completed successfully (${duration}s)${NC}"
    else
        echo -e "${ERROR_COLOR}[!] Command failed with exit code: $exit_code (${duration}s)${NC}"
    fi

    if [[ -n "$output_file" ]]; then
        echo -e "${SUCCESS_COLOR}[+] Output saved to: $output_file${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."

    return $exit_code
}

# Execute command in background
# Usage: command_execute_background "command" [output_file]
command_execute_background() {
    local command="$1"
    local output_file="$2"

    # Generate job ID
    ((JOB_COUNTER++))
    local job_id=$JOB_COUNTER

    # Set output file if not provided
    if [[ -z "$output_file" ]]; then
        output_file="$HOME/.purplesploit/jobs/job_${job_id}.log"
        mkdir -p "$(dirname "$output_file")"
    fi

    # Execute in background
    echo -e "${SUCCESS_COLOR}[*] Starting job $job_id in background...${NC}"
    echo -e "${SUCCESS_COLOR}[+] Output: $output_file${NC}"

    (
        eval "$command" > "$output_file" 2>&1
        local exit_code=$?
        echo "EXIT_CODE:$exit_code" >> "$output_file"
    ) &

    local pid=$!

    # Store job info
    ACTIVE_JOBS[$job_id]="$pid|$command|$output_file"

    echo -e "${SUCCESS_COLOR}[+] Job $job_id started (PID: $pid)${NC}"
    echo ""

    return 0
}

# List active jobs
# Usage: command_jobs_list
command_jobs_list() {
    if [[ ${#ACTIVE_JOBS[@]} -eq 0 ]]; then
        echo "No active jobs"
        return 0
    fi

    echo ""
    echo "Active Jobs:"
    echo "================================================================================"
    printf "%-10s %-10s %-10s %s\n" "Job ID" "PID" "Status" "Command"
    echo "--------------------------------------------------------------------------------"

    for job_id in "${!ACTIVE_JOBS[@]}"; do
        local job_info="${ACTIVE_JOBS[$job_id]}"
        local pid="${job_info%%|*}"
        local rest="${job_info#*|}"
        local command="${rest%%|*}"
        local output_file="${rest#*|}"

        # Check if process is still running
        local status="Running"
        if ! kill -0 "$pid" 2>/dev/null; then
            status="Completed"
        fi

        # Truncate long commands
        if [[ ${#command} -gt 50 ]]; then
            command="${command:0:47}..."
        fi

        printf "%-10s %-10s %-10s %s\n" "$job_id" "$pid" "$status" "$command"
    done

    echo "================================================================================"
    echo ""
}

# Kill a job
# Usage: command_job_kill <job_id>
command_job_kill() {
    local job_id="$1"

    if [[ ! -v "ACTIVE_JOBS[$job_id]" ]]; then
        echo -e "${ERROR_COLOR}[!] Error: Job $job_id not found${NC}"
        return 1
    fi

    local job_info="${ACTIVE_JOBS[$job_id]}"
    local pid="${job_info%%|*}"

    if kill "$pid" 2>/dev/null; then
        echo -e "${SUCCESS_COLOR}[+] Job $job_id (PID: $pid) killed${NC}"
        unset "ACTIVE_JOBS[$job_id]"
        return 0
    else
        echo -e "${ERROR_COLOR}[!] Failed to kill job $job_id (PID: $pid)${NC}"
        return 1
    fi
}

# Add command to history
# Usage: command_history_add "command"
command_history_add() {
    local command="$1"

    # Add to in-memory history
    COMMAND_HISTORY+=("$command")

    # Append to history file
    echo "$command" >> "$COMMAND_HISTORY_FILE"
}

# Show command history
# Usage: command_history_show [count]
command_history_show() {
    local count="${1:-20}"

    echo ""
    echo "Command History (last $count):"
    echo "================================================================================"

    local total=${#COMMAND_HISTORY[@]}
    local start=$((total - count))
    [[ $start -lt 0 ]] && start=0

    for ((i=start; i<total; i++)); do
        printf "%4d  %s\n" "$((i+1))" "${COMMAND_HISTORY[$i]}"
    done

    echo "================================================================================"
    echo ""
}

# Search command history
# Usage: command_history_search "keyword"
command_history_search() {
    local keyword="$1"

    if [[ -z "$keyword" ]]; then
        echo "[!] Usage: history_search <keyword>"
        return 1
    fi

    echo ""
    echo "Command History Search: $keyword"
    echo "================================================================================"

    local found=0
    for ((i=0; i<${#COMMAND_HISTORY[@]}; i++)); do
        if [[ "${COMMAND_HISTORY[$i]}" == *"$keyword"* ]]; then
            printf "%4d  %s\n" "$((i+1))" "${COMMAND_HISTORY[$i]}"
            ((found++))
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo "No commands found matching: $keyword"
    fi

    echo "================================================================================"
    echo "Found: $found commands"
    echo ""
}

# Export functions
export -f command_engine_init
export -f command_build
export -f command_preview
export -f command_run
export -f command_execute_foreground
export -f command_execute_background
export -f command_jobs_list
export -f command_job_kill
export -f command_history_add
export -f command_history_show
export -f command_history_search
