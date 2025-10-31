#!/bin/bash
#
# PurpleSploit Framework - Main Entry Point
# Metasploit-Style Pentesting Framework with FZF Integration
#
# Usage: ./purplesploit-framework.sh
#

set -eo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source framework engine
source "$SCRIPT_DIR/framework/core/engine.sh"

# Main command loop
main_loop() {
    local current_module=""

    while true; do
        # Build prompt
        current_module=$(module_get_current)
        local prompt="purplesploit"

        if [[ -n "$current_module" ]]; then
            prompt="${prompt}(${current_module})"
        fi

        prompt="${prompt}> "

        # Read command
        read -e -p "$prompt" command_line

        # Skip empty commands
        [[ -z "$command_line" ]] && continue

        # Parse command
        read -ra cmd_parts <<< "$command_line"
        local cmd="${cmd_parts[0]}"
        local args=("${cmd_parts[@]:1}")

        # Process command
        case "$cmd" in
            # Module commands
            use)
                if [[ ${#args[@]} -eq 0 ]]; then
                    echo "[!] Usage: use <module>"
                else
                    module_use "${args[0]}"
                fi
                ;;

            back)
                if [[ -n "$current_module" ]]; then
                    module_clear
                    echo "[+] Cleared module selection"
                else
                    echo "[!] No module selected"
                fi
                ;;

            search)
                if [[ ${#args[@]} -eq 0 ]]; then
                    # Interactive FZF search with no initial query
                    fzf_module_search ""
                elif [[ "${args[0]}" == "relevant" ]]; then
                    # Search for modules relevant to detected services
                    service_search_relevant_fzf
                else
                    # FZF search with initial query
                    fzf_module_search "${args[*]}"
                fi
                ;;

            info)
                if [[ ${#args[@]} -eq 0 ]]; then
                    module_info
                else
                    module_info "${args[0]}"
                fi
                ;;

            browse)
                # Interactive category browser
                fzf_category_browse
                ;;

            # Variable commands
            set)
                if [[ ${#args[@]} -lt 2 ]]; then
                    echo "[!] Usage: set <VAR> <value>"
                else
                    var_set "${args[0]}" "${args[*]:1}"
                fi
                ;;

            setg)
                if [[ ${#args[@]} -lt 2 ]]; then
                    echo "[!] Usage: setg <VAR> <value>"
                else
                    var_set "${args[0]}" "${args[*]:1}"
                fi
                ;;

            unset)
                if [[ ${#args[@]} -eq 0 ]]; then
                    echo "[!] Usage: unset <VAR>"
                else
                    var_unset "${args[0]}"
                fi
                ;;

            # Show commands
            show)
                if [[ ${#args[@]} -eq 0 ]]; then
                    echo "[!] Usage: show <modules|options|vars|categories>"
                else
                    case "${args[0]}" in
                        modules)
                            module_list_all
                            ;;
                        options)
                            module_info
                            ;;
                        vars)
                            var_show_all
                            ;;
                        categories)
                            module_list_by_category
                            ;;
                        *)
                            echo "[!] Unknown show target: ${args[0]}"
                            echo "[*] Available: modules, options, vars, categories"
                            ;;
                    esac
                fi
                ;;

            # Execution commands
            run)
                local run_args=()
                for arg in "${args[@]}"; do
                    run_args+=("$arg")
                done
                command_run "${run_args[@]}"
                ;;

            check)
                command_preview
                ;;

            # Workspace commands
            workspace)
                if [[ ${#args[@]} -eq 0 ]]; then
                    # Interactive FZF workspace selection
                    fzf_workspace_select
                elif [[ "${args[0]}" == "-a" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: workspace -a <name>"
                    else
                        workspace_create "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-d" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: workspace -d <name>"
                    else
                        workspace_delete "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-i" ]]; then
                    workspace_info "${args[1]:-}"
                elif [[ "${args[0]}" == "-l" ]]; then
                    workspace_list
                else
                    workspace_switch "${args[0]}"
                fi
                ;;

            # Target commands
            targets)
                if [[ ${#args[@]} -eq 0 ]]; then
                    # Interactive FZF target selection
                    fzf_target_select
                elif [[ "${args[0]}" == "-a" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: targets -a <target>"
                    else
                        workspace_add_target "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-r" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: targets -r <target>"
                    else
                        workspace_remove_target "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-i" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: targets -i <file>"
                    else
                        workspace_import_targets "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-e" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: targets -e <file>"
                    else
                        workspace_export_targets "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-l" ]]; then
                    workspace_list_targets
                else
                    echo "[!] Unknown targets option: ${args[0]}"
                    echo "[*] Available: -a (add), -r (remove), -i (import), -e (export), -l (list)"
                fi
                ;;

            # Credential commands
            credentials|creds)
                if [[ ${#args[@]} -eq 0 ]]; then
                    # Interactive FZF credential selection
                    fzf_credential_select
                elif [[ "${args[0]}" == "-a" ]]; then
                    credential_add_interactive
                elif [[ "${args[0]}" == "-l" ]]; then
                    credential_list_all
                elif [[ "${args[0]}" == "-d" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: credentials -d <id>"
                    else
                        credential_delete "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-e" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: credentials -e <id>"
                    else
                        credential_edit "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-m" ]]; then
                    credential_manage
                elif [[ "${args[0]}" == "-i" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: credentials -i <file>"
                    else
                        credential_import "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-x" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: credentials -x <file>"
                    else
                        credential_export "${args[1]}"
                    fi
                else
                    # Load credential by ID
                    credential_load "${args[0]}"
                fi
                ;;

            # Mythic C2 commands
            mythic)
                if [[ ${#args[@]} -eq 0 ]]; then
                    mythic_menu
                elif [[ "${args[0]}" == "configure" ]]; then
                    mythic_configure
                elif [[ "${args[0]}" == "test" ]]; then
                    mythic_test_connection
                elif [[ "${args[0]}" == "payloads" ]]; then
                    mythic_list_payloads
                else
                    mythic_menu
                fi
                ;;

            # Job commands
            jobs)
                if [[ ${#args[@]} -eq 0 ]]; then
                    command_jobs_list
                elif [[ "${args[0]}" == "-k" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: jobs -k <job_id>"
                    else
                        command_job_kill "${args[1]}"
                    fi
                else
                    echo "[!] Unknown jobs option: ${args[0]}"
                fi
                ;;

            # History commands
            history)
                if [[ ${#args[@]} -eq 0 ]]; then
                    # Interactive FZF history selection
                    fzf_history_select
                elif [[ "${args[0]}" == "-s" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: history -s <keyword>"
                    else
                        command_history_search "${args[1]}"
                    fi
                elif [[ "${args[0]}" == "-l" ]]; then
                    command_history_show "${args[1]:-20}"
                else
                    command_history_show "${args[0]}"
                fi
                ;;

            # Interactive variable editor
            vars)
                fzf_variable_select
                ;;

            # Service analysis commands
            services)
                if [[ ${#args[@]} -eq 0 ]]; then
                    service_list_detected
                elif [[ "${args[0]}" == "-t" ]] || [[ "${args[0]}" == "--target" ]]; then
                    service_list_current_target
                elif [[ "${args[0]}" == "-c" ]] || [[ "${args[0]}" == "--clear" ]]; then
                    service_clear
                elif [[ "${args[0]}" == "-i" ]] || [[ "${args[0]}" == "--import" ]]; then
                    if [[ ${#args[@]} -lt 2 ]]; then
                        echo "[!] Usage: services -i <nmap_file>"
                    else
                        service_import_nmap "${args[1]}"
                    fi
                else
                    echo "[!] Unknown services option: ${args[0]}"
                    echo "[*] Available: -t (current target), -c (clear), -i <file> (import)"
                fi
                ;;

            # Utility commands
            status)
                framework_status
                ;;

            help|"?")
                framework_help
                ;;

            quickstart)
                framework_quickstart
                ;;

            clear)
                clear
                show_banner
                ;;

            exit|quit)
                echo ""
                echo -e "${CYAN}[*] Exiting framework...${NC}"
                break
                ;;

            # Unknown command
            *)
                echo "[!] Unknown command: $cmd"
                echo "[*] Type 'help' for available commands"
                ;;
        esac
    done
}

# Main entry point
main() {
    # Show banner
    show_banner

    # Initialize framework
    framework_init

    # Show quick start
    framework_quickstart

    # Enter main loop
    main_loop
}

# Run main
main "$@"
