# Changelog

All notable changes to PurpleSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.9.0] - 2026-01-29

### Added
- **Comprehensive Business Logic Test Suite**: Added 155 new tests to improve test coverage and validate core functionality
  - User workflow tests (42 tests): go command navigation, quick command execution, targets range operations
  - Session state consistency tests (48 tests): session state integrity, index consistency, export/import functionality
  - Error recovery tests (33 tests): error handling patterns, transaction rollback, input validation
  - Operation execution tests (32 tests): module operation execution flow and lifecycle
- All 3,835 unit tests passing with enhanced coverage of core session management and UI command systems

### Changed
- Enhanced database.py error handling and session management (56 line changes)
- Improved UI command test fixtures and mocking strategies across test suite (640+ line changes)
- Enhanced XLSX reporting test coverage with comprehensive test suite (516 new lines)

### Fixed
- Resolved test fixture issues in UI command tests for better mock isolation
- Improved mock isolation in shell command tests to prevent cross-test contamination

## [6.8.2] - 2026-01-23

### Fixed
- **Phase 2 Test Fixes**: Resolved 19 failing tests in UI commands test suite (74% total issue resolution)
  - Fixed FindingsCommand tests (12 tests) by converting dict access to object attributes in mock findings
  - Fixed WorkflowCommand tests (6 tests) by pre-assigning internal manager references before method calls
  - Fixed PluginCommand tests (7 tests) by correcting method names and mock structure for plugin operations
  - Added `create_mock_finding()` helper function for consistent test fixture creation
  - Updated integration tests (module_chaining, persistence, workflow) for compatibility with current architecture
  - Test suite improvements: 3,464 → 3,571 passing tests (+107), failures reduced from 205 to 54 issues

### Changed
- **Documentation Cleanup**: Removed outdated planning documents from python/ directory
  - Deleted IMPLEMENTATION_PLAN.md, SPRINT_PLAN.md, and TEST_IMPROVEMENT_PLAN.md
  - Consolidated documentation in docs/ directory with dated filenames per project standards
- **Documentation Organization**: Added comprehensive test fix documentation in docs/ directory
  - Created TEST_FIX_PLAN-23JAN2026.md and TEST_FIX_PLAN_PHASE2-23JAN2026.md
  - Added UNIT_TESTING_PLAN-23JAN2026.md and DOCUMENTATION_AUDIT-23JAN2026.md

## [6.8.1] - 2025-11-28

### Fixed
- **Module Discovery**: Fixed critical bugs preventing modules from being registered during startup
  - **Framework Registration**: Module discovery now properly filters out imported classes vs. classes defined in the module file
    - Added `obj.__module__` check in `_register_module()` to ensure only locally-defined classes are registered
    - Resolves module registration conflicts when modules inherit from other modules
  - **Nmap Module Imports**: Fixed missing typing imports causing all nmap modules to fail
    - Added `from typing import List, Dict, Any` to nmap.py (line 10)
    - All nmap variant modules (fast, aggressive, stealth, comprehensive, no_ping, udp) now load correctly
  - **Nmap Parser Import**: Fixed incorrect relative import path
    - Changed `from ..core.module import BaseModule` to `from purplesploit.core.module import BaseModule`
    - nmap_parser module now loads without errors
  - **Result**: All 37 modules (including 8 nmap modules) now properly discovered and available for use

## [6.7.0] - 2025-11-27

### Added
- **Mobile-Friendly Web Dashboard**: Enhanced web dashboard with comprehensive responsive design
  - Added mobile breakpoints for tablets (768px) and phones (480px)
  - Navigation bar now wraps properly on smaller screens with adjusted spacing
  - Responsive grid layouts for stats cards with optimized min-widths
  - Table horizontal scrolling with touch support for better mobile browsing
  - Optimized font sizes, padding, and spacing for mobile devices
  - Service grid adapts from 150px to 90px minimum width on mobile
  - Auto-refresh indicator repositioned and resized for mobile screens
  - Container padding reduced on mobile for better space utilization
  - Improved readability with scaled-down typography on small screens

## [6.6.2] - 2025-11-27

### Fixed
- **Web Dashboard Target/Credential Display**: Fixed current target and credential not updating in web terminal context display
  - Updated session tracking to include `current_target` and `current_credential` fields
  - Modified `updateContext()` in c2-terminal.js to display current target from session
  - Target/credential context now properly updates when selected in web terminal
- **Web Dashboard Database Sync**: Fixed main dashboard showing zero targets/credentials despite data existing
  - Changed dashboard.py to use models database (db_manager) instead of core database
  - Dashboard now displays accurate counts from the shared models database
  - All dashboard routes (targets, credentials, services) now sync with API data
- **Searchsploit Exploit Discovery**: Fixed exploit discovery not working in nmap_parser module
  - Updated nmap_parser to use db_manager.add_exploit() for storing exploits
  - Added service syncing to models database for web dashboard visibility
  - Exploits now properly stored and displayed in web dashboard

### Added
- **Credential Selection UI**: Added "Use" button for existing credentials in web terminal credential manager
  - Credential manager now allows selecting existing credentials like the target manager
  - Added `useCredential()` function to execute credential selection
  - Credentials can now be selected from the list or added new

## [6.6.1] - 2025-11-27

### Fixed
- **Password Display**: Removed password censoring in credentials list - passwords and hashes now display uncensored
  - Updated `print_credentials_table()` in display.py to show plaintext passwords
  - Removed asterisk masking logic for sensitive data
- **Services Display**: Fixed nmap services table to show one service/port per row
  - Changed services table to display individual service/port combinations on separate rows
  - Host column now shows blank cells for additional rows from same host
  - Column header changed from "Ports" to "Port" for clarity
- **Target Auto-Import**: Fixed nmap discovered IPs not being added to targets list
  - Updated `process_discovered_hosts()` in nmap.py to use `framework.add_target()`
  - Discovered IPs now correctly appear in both session and database targets
  - Fixed issue where IPs were only saved to database but not to active session

## [6.6.0] - 2025-11-26

### Added
- **DOMAIN/DCIP/DNS Credential Fields**: Added domain controller IP (dcip) and DNS server (dns) fields to credential manager
  - Updated CredentialManager to support dcip and dns fields
  - Updated database models (Credential, CredentialCreate, CredentialResponse) with new fields
  - Auto-set dcip and dns values when selecting credentials in modules
- **AUTH_TYPE Option for SMB/MSSQL**: Added authentication type selection for SMB and MSSQL modules
  - Supports: domain (default), local, kerberos, and windows authentication
  - Available as AUTH_TYPE option in nxc_smb and nxc_mssql modules
  - Automatically appends appropriate flags (--local-auth, --kerberos, --windows-auth)
- **SWITCHES Option**: Added global SWITCHES option to all ExternalToolModule instances
  - Allows custom command-line switches to be appended to any module command
  - Available in OPTIONS menu for all modules using ExternalToolModule base class

### Fixed
- **Module Creator Bug**: Fixed "name 'key' is not defined" error in multi-operation module generation
  - Updated template generation to use proper variable names (opt_key, opt_val)
  - Corrected f-string escaping in generated operation methods
- **Ligolo Pivot Module**: Fixed missing operations implementation
  - Converted from old-style self.operations dict to get_operations() method
  - Module now properly displays 7 deployment operations in operation selector
  - Added missing List and Dict type imports

### Enhanced
- Credential manager modify() method now supports dcip and dns field modifications
- Credential selection auto-populates DCIP and DNS in modules that support them
- Improved modularity of authentication handling across network modules

## [6.5.0] - 2025-11-26

### Added
- **Intelligent Subnet Scanning Workflow**: Nmap now automatically discovers and adds hosts
  - Scans subnets (e.g., 192.168.1.0/24) and auto-discovers live hosts
  - Automatically adds discovered IPs with open ports to targets table with 'verified' status
  - Automatically imports all services to services table individually per host
  - Subnets remain as notation until verified via nmap scan
- **Nmap XML Import Functionality**: Import existing nmap scan results
  - New `parse <file.xml>` command to import nmap XML results
  - Web API endpoint `/api/nmap/upload` for uploading nmap XML files
  - Automatic parsing and import of discovered hosts and services
  - Full support for both CLI and API upload methods
- **Background Scanning by Default**: All nmap scans now run in background mode by default
  - Changed BACKGROUND default from "false" to "true"
  - Allows continued work while scans run
  - Parse results when complete with `parse` command

### Changed
- Nmap module now parses XML output automatically after scans complete
- Discovered hosts from subnet scans are automatically added to targets table
- Services are automatically imported for all discovered hosts
- XML output is now required and enabled by default for all scans

### Enhanced
- Added `parse_xml_output()` method to nmap module for robust XML parsing
- Added `process_discovered_hosts()` method to handle auto-import of targets/services
- Updated run() method to automatically process XML results after scan completion

## [6.4.0] - 2025-11-25

### Added
- **Enhanced Target Management**: Added range-based deletion and modification for targets
  - `targets clear` - clear all targets
  - `targets 1-5 clear` - clear targets by index range
  - `targets 1 clear` - clear single target by index
  - `targets 1 modify name=NewName ip=10.0.0.1` - modify target attributes
- **Enhanced Credential Management**: Added range-based deletion and modification for credentials
  - `creds clear` - clear all credentials
  - `creds 1-5 clear` - clear credentials by index range
  - `creds 1 clear` - clear single credential by index
  - `creds 1 modify username=admin password=newpass` - modify credential attributes
- **Web Dashboard CRUD**: Added delete functionality to web dashboard for targets and credentials
  - Created targets.html and credentials.html templates with delete buttons
  - Added POST routes for target and credential deletion
  - Added PUT endpoints in API for target and credential updates
- **Improved Subnet Handling**: Subnets now stored as-is (e.g., 192.168.1.0/24) until hosts are verified
  - Added status field to targets table ('unverified', 'verified', 'subnet')
  - Subnets no longer auto-expanded into individual IPs
  - Only verified/responsive hosts appear in main targets list
  - Added `mark_target_verified()` method for post-scan verification

### Changed
- Targets and credentials now include index numbers for easier management
- Session managers (TargetManager, CredentialManager) now support index-based operations
- Database schema updated with status field for targets
- API endpoint behavior changed: subnets are stored as-is rather than expanded

### Fixed
- Module execution endpoints properly configured in API server
- Subnet handling no longer creates hundreds of unverified target entries
- Target and credential management now more uniform across CLI and web interfaces

## [6.3.0] - Previous Release

### Added
- Persistent module defaults
- Ligolo session management
- Nmap background mode
- Project cleanup and optimization

### Changed
- Various performance improvements

## [6.2.0] - Previous Release

### Added
- Persistent module defaults
- Ligolo sessions
- Nmap background mode
- Project cleanup

### Changed
- Performance and stability improvements

## [6.1.0] - Previous Release

### Added
- Web portal & API server
- Webserver command
- Real-time database sync

## [6.0.0] - Previous Release

### Added
- Pure Python edition
- Enhanced auto-completion

### Removed
- Bash dependencies
- TUI interface (replaced with enhanced console)
