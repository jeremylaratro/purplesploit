# Changelog

All notable changes to PurpleSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.2.0] - 2025-11-22

### Added
- **Persistent Module Defaults System**: Save and reuse custom module configurations
  - Set default options per module that persist across sessions
  - Override defaults when needed without losing saved configurations
  - Improved workflow efficiency for repeated operations
- **Persistent Ligolo Sessions**: Automated pivot deployment with session persistence
  - Ligolo sessions automatically reconnect and persist across framework restarts
  - Automated pivot deployment capabilities
  - `-selfcert` flag enabled by default for easier setup
- **Database Sync Utilities**: Enhanced synchronization between CLI and web portal
  - New `get_all_services` method for comprehensive service querying
  - Automatic service syncing to webserver database
  - Sync existing database entries to webserver on startup
- **Nmap Background Mode**: Run nmap scans in background without blocking CLI
  - Continue using framework while scans execute
  - Real-time scan progress tracking
  - Enhanced nmap module descriptions for better discoverability

### Changed
- **Project Structure Cleanup**: Streamlined repository organization
  - Removed all 21 .psm files from old TUI version
  - Consolidated documentation into `docs/` directory
  - Created `scripts/` directory for utility scripts (reset-databases.py, start-web-portal.py, sync_databases.py)
  - Clean root directory with only essential files (README.md, QUICKSTART.md, LICENSE, purplesploit-python)
  - Moved CHANGELOG.md, COMMANDS.md, DISCLAIMER.md, OVERVIEW.md, SYNC_DATABASES.md, WEB_PORTAL_GUIDE.md to docs/
  - Updated all documentation links and script references to reflect new structure
- **Chronological Versioning**: All PRs and commits now properly versioned chronologically
- **Nmap Module Descriptions**: Updated to be more distinctive and clear

### Fixed
- **Webserver Request Logging**: Suppressed verbose logging in CLI for cleaner output
- **Webserver Real-time Updates**: Fixed synchronization issues between CLI and web portal
- **Dashboard Session Data**: Corrected database path to display proper session data from core database
- **Database Location**: Changed from `/tmp` to persistent project directory location
  - Ensures data survives system reboots
  - Self-contained deployment with all data in project directory
- **Database Path Consistency**: Unified database path between CLI and dashboard
  - CLI and web portal now use same database location
  - Real-time sync works reliably across both interfaces

### Removed
- Old TUI module files (.psm) - 20 module files and 1 template removed
- Empty documentation directories (docs/examples/)

## [6.1.0] - 2025-11-21

### Added
- **Web Portal & API Server**: Comprehensive web interface for PurpleSploit
  - Real-time target analysis and visualization dashboard
  - Interactive API documentation at `/api/docs`
  - RESTful API for all framework operations
  - Web portal at `http://localhost:5000` with dark-themed UI
- **Webserver Command**: Integrated web server management from CLI
  - `webserver start` - Launch server in background process
  - `webserver stop` - Gracefully stop running server
  - `webserver status` - Check server status and PID
  - Background execution allows continued CLI usage while server runs
  - Custom port support with `--port` flag
- **Real-time Database Synchronization**: Web portal and CLI share same database
  - Targets, credentials, and services automatically sync
  - Changes in CLI instantly visible in web portal
  - Changes via API instantly visible in CLI
- **Repository Reorganization**: Enhanced modularity and parameter system
  - Improved module structure for better maintainability
  - Enhanced parameter passing between components
  - Better separation of concerns across modules

### Fixed
- **Multiprocessing Error**: Fixed RuntimeError when starting web server
  - Disabled auto-reload by default to prevent multiprocessing issues
  - Server now runs cleanly in background without spawn errors
  - Proper process management with daemon threads

### Changed
- Web server now runs as background process (non-blocking)
- Updated help documentation with webserver commands
- Improved server startup feedback with status indicators

## [6.0.1] - 2025-11-21

### Fixed
- **Database Corruption Auto-Recovery**: Automatic detection and recovery for corrupted databases
  - Detects SQLite database corruption on startup
  - Automatically backs up corrupted databases
  - Creates fresh database files when corruption detected
  - Prevents data loss with timestamped backups

### Changed
- Enhanced database initialization with corruption checking
- Improved error messages for database issues

## [6.0.0] - 2025-11-19

### Added
- **Enhanced Auto-Completion**: Context-aware dropdown menu with dynamic suggestions
  - Auto-completes module paths, target IPs, and common operations
  - Real-time updates based on current framework state
  - Styled dropdown menu with green highlighting
  - Fuzzy matching with middle-word support
- **Dynamic Command Completer**: Suggestions include all loaded modules and targets
- **Improved Console Experience**: Better prompt styling and dropdown menu navigation

### Changed
- **Major Architecture Change**: Converted to pure Python implementation
  - Removed all bash script components (core/, framework/, modules/*.sh, tests/)
  - Removed TUI mode and all related bash infrastructure
  - Updated banner to "Python Edition" instead of "Console Mode"
  - Simplified directory structure by removing bash-specific folders

### Removed
- **Bash Components**: All bash scripts and shell-based framework removed
  - Removed core/, framework/, lib/, tools/ directories
  - Removed all .sh module implementations
  - Removed test.sh and bash test scripts
  - Removed bin/*.sh launcher scripts
- **TUI Mode**: Complete removal of TUI interface
  - Removed docs/tui-mode/ documentation
  - Removed TUI-specific code and references
  - Framework is now console-only (Python-based)
- **Legacy Files**: Cleaned up feroxbuster state files and test artifacts

### Migration Notes
**Breaking Changes**: This is a major version bump due to architectural changes.
- **Bash scripts removed**: All .sh files have been removed. Use Python modules instead.
- **TUI mode removed**: Only console mode (Python) is available. TUI has been moved to a separate repository.
- **Module format**: Modules must be Python-based (see Contributing guide for examples).

If you need the bash/TUI version, use v5.2.0 or earlier:
```bash
git checkout v5.2.0
```

## [5.2.0] - 2025-11-19

### Added
- **Shell Command**: New `shell` command for localhost terminal access
  - Drop directly into system shell from PurpleSploit
  - CTRL+D navigation to return to framework
  - Execute single commands or launch interactive shell
  - Respects user's $SHELL environment variable

## [5.1.0] - 2025-11-19

### Added
- **Ligolo-ng Integration**: New `ligolo` command for seamless ligolo-ng proxy tunneling
  - Full ligolo-ng dashboard access from within PurpleSploit
  - CTRL+D navigation to return to PurpleSploit
  - Complete ligolo functionality including route management
  - Auto-detection of ligolo-ng installation

### Removed
- TUI mode components and dependencies (console-only version)
- Interactive TUI command and related bash scripts

### Changed
- Simplified setup.py entry points (removed TUI references)
- Updated banner to reflect console-only interface

## [5.0.0] - 2025-11-17

### Changed
- **Complete SMB Module Restructure**: Reorganized SMB modules into logical categories (authentication, enumeration, credential extraction, file operations)
- Improved module organization for better discoverability
- Enhanced documentation structure with version tracking

### Removed
- Archived outdated documentation (legacy/ and archive/ folders)
- Removed historical documentation that was no longer relevant to current version

### Added
- Version tracking system for documentation
- Centralized CHANGELOG.md for tracking all version changes
- VERSION_CONTROL.md guide for documentation versioning

## [4.6.0] - 2025-11-09

### Added
- **Dynamic Banner System**: Multiple ASCII art variants for visual appeal
  - 8 total banner designs with randomized selection
  - Sleek ASCII art branding in README
  - Integrated into launch scripts for variety
- **Enhanced Documentation**: Improved README with better descriptions
  - Added "Why PurpleSploit?" section explaining framework benefits
  - Revised tool descriptions for clarity
  - Fixed formatting throughout documentation

### Changed
- Banner now randomizes on each launch for fresh look
- Improved README formatting and content organization

## [4.5.1] - 2025-11-08

### Fixed
- **Ops Command**: Fixed issues with operation search and execution
  - Enable direct run by operation ID from search results
  - Improved search result display and numbering
  - Better error handling for operation selection

## [4.5.0] - 2025-11-11

### Added
- Major module organization improvements
- Enhanced usability features
- Improved search and selection capabilities
- **Core Documentation**: Command reference guide and architecture overview

### Changed
- Module structure improvements
- Better module categorization

## [3.8.0] - 2025-11-08

### Added
- **Governance and Licensing**: Simplified launch with non-commercial license
  - Switched to non-commercial license for clarity
  - Removed governance overhead for streamlined development
  - Added comprehensive public launch documentation

### Changed
- Updated version numbering to 3.8
- Refactored documentation structure for better organization
- Improved security hardening documentation

## [3.5.0] - 2025-11-08

### Added
- **Wordlist Manager**: Comprehensive wordlist management system
  - Category-based organization (web_dir, dns_vhost, username, password, etc.)
  - Interactive wordlist selection with `wordlists select <category>`
  - Add, remove, and set wordlists per category
  - Auto-population of wordlist options in modules
- **Module Creator**: Automated module generation tool
  - Scaffolding for new modules with templates
  - Streamlined module development workflow
- **Interactive Select Feature**: Enhanced user interaction across all commands
  - `targets select`, `creds select`, `services select`, `wordlists select`
  - Fuzzy search integration with fzf
  - Numbered selection for quick access
  - Auto-set feature for automatic option population
- **Enhanced Ops Search**: Operations searchable globally across modules
  - Organized results by module category
  - Direct execution from search results
  - Multi-word query support
- Dual interface support (Console Mode + TUI Mode)
- Fuzzy search with `search` and `ops` commands
- Smart service detection
- Workspace and job management

### Features
- **Console Mode**: Metasploit-style CLI with advanced search
- **TUI Mode**: Full-screen menu interface
- 50+ operations across web, network, recon, and exploitation tools
- Integration with NetExec, Impacket, SQLMap, Feroxbuster, and more

### Changed
- Version bumped from 3.3 to 3.5
- Enhanced banner display system
- Improved interactive mode and selection mechanisms

### Fixed
- Interactive mode stdin/input conflicts with fzf
- Module metadata access issues
- Banner display bugs

## [3.3.0] - 2025-11-08

### Added
- **Customized Branding**: Enhanced visual identity
  - Polished UI elements across interfaces
  - Improved help screens and banners
  - Organized dual-mode documentation (console/TUI)
- **Module Select with Submenu Traversal**: Tree view navigation
  - Hierarchical module browsing
  - Submenu navigation for module categories
  - Visual tree structure for better discoverability
- **Accessibility Improvements**: Comprehensive accessibility features
  - Better keyboard navigation
  - Screen reader compatibility considerations
  - Improved command documentation

### Fixed
- Banner display issues in various modes
- Command help formatting

## [3.2.0] - 2025-11-07

### Added
- **Comprehensive Accessibility Features**: Enhanced accessibility across framework
  - Detailed accessibility documentation
  - Improved keyboard navigation patterns
  - Better screen reader compatibility notes

### Fixed
- **Critical Bug Fixes**: Module metadata access and interactive selector
  - Fixed ModuleMetadata access errors
  - Resolved interactive selector issues
  - Fixed show modules command functionality

## [3.1.0] - 2025-11-07

### Added
- **Smart Search and Workflow**: Enhanced efficiency features
  - Smart search capabilities across modules
  - Workflow demo and examples for quick learning
  - Interactive selection with power commands for 3-command workflow

### Fixed
- **Interactive Selector**: Terminal access improvements
  - Fixed fzf stdin/input conflicts using /dev/tty
  - Enabled fzf and numbered selection with prompt_toolkit
  - Resolved interactive mode, ops search, and banner display issues

## [3.0.0] - 2025-11-08

### Added
- **Initial Python Framework Implementation**: Complete rewrite from bash
  - Core module system with dynamic loading
  - Database integration for targets and credentials (SQLite)
  - Metasploit-style command-line interface with prompt_toolkit
  - Session management and context persistence
- **Interactive Mode**: Full interactive command interface
  - Real-time command completion
  - History support with search
  - Context-aware prompting
- **Granular Operations**: 86 total operations across modules
  - All NetExec (NXC) modules with granular operation support
  - SMB, LDAP, WinRM, MSSQL, RDP, SSH operations
  - Web testing tools (Feroxbuster, SQLMap, WFuzz)
- **Power Commands**: 3-command workflow capability
  - Quick target/credential setup
  - Rapid module loading and execution
  - Streamlined penetration testing workflow

### Changed
- Migrated from bash scripts to pure Python
- Improved module architecture for extensibility

## [2.9.0] - 2025-11-07

### Added
- **Complete Module Port**: All 18 modules operational in Python
  - Successfully ported all bash modules to Python framework
  - Full NetExec integration across all modules
  - Impacket tools integrated (secretsdump, GetUserSPNs, etc.)
  - Web testing tools (Feroxbuster, SQLMap, WFuzz)
  - All modules tested and operational

## [2.5.0] - 2025-11-06

### Added
- **Module Expansion**: 9 additional modules (11 total operational)
  - Expanded module library significantly
  - Added network protocol modules (LDAP, WinRM, MSSQL, RDP)
  - Added web application testing modules
  - Improved module loading system

## [Earlier Versions]

Previous versions focused on bash-based automation and initial framework development.

---

## Version History Summary

- **v6.2.0** (2025-11-22): Persistent module defaults, ligolo sessions, nmap background mode, project cleanup
- **v6.1.0** (2025-11-21): Web portal & API server, webserver command, background execution
- **v6.0.1** (2025-11-21): Database corruption auto-recovery
- **v6.0.0** (2025-11-19): Pure Python edition, enhanced auto-completion, removed bash/TUI
- **v5.2.0** (2025-11-19): Shell command integration
- **v5.1.0** (2025-11-19): Ligolo-ng integration, console-only version
- **v5.0.0** (2025-11-17): Complete SMB restructure, documentation cleanup
- **v4.6.0** (2025-11-09): Dynamic banner system, enhanced documentation
- **v4.5.1** (2025-11-08): Ops command fixes
- **v4.5.0** (2025-11-11): Module organization improvements, core documentation
- **v3.8.0** (2025-11-08): Governance and licensing, documentation refactor
- **v3.5.0** (2025-11-08): Wordlist manager, module creator, interactive select
- **v3.3.0** (2025-11-08): Customized branding, module tree view
- **v3.2.0** (2025-11-07): Accessibility improvements, critical bug fixes
- **v3.1.0** (2025-11-07): Smart search and workflow, interactive selector fixes
- **v3.0.0** (2025-11-08): Python framework implementation, 86 operations
- **v2.9.0** (2025-11-07): Complete module port, 18 modules operational
- **v2.5.0** (2025-11-06): Module expansion, 11 modules operational
- **Earlier**: Bash-based automation and prototyping

---

For detailed information about each version, see the git commit history and release notes.
