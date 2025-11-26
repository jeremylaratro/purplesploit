# Changelog

All notable changes to PurpleSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
