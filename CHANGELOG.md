# Changelog

All notable changes to PurpleSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [4.5.0] - 2024

### Added
- Major module organization improvements
- Enhanced usability features
- Improved search and selection capabilities

### Changed
- Module structure improvements
- Better module categorization

## [3.5.0] - 2024

### Added
- Dual interface support (Console Mode + TUI Mode)
- Fuzzy search with `search` and `ops` commands
- Interactive selection with `{}` syntax
- Smart service detection
- Workspace and job management

### Features
- **Console Mode**: Metasploit-style CLI with advanced search
- **TUI Mode**: Full-screen menu interface
- 50+ operations across web, network, recon, and exploitation tools
- Integration with NetExec, Impacket, SQLMap, Feroxbuster, and more

## [3.0.0] - 2024

### Added
- Initial Python framework implementation
- Core module system
- Database integration for targets and credentials
- Basic command-line interface

## [Earlier Versions]

Previous versions focused on bash-based automation and initial framework development.

---

## Version History Summary

- **v5.0.0**: Complete SMB restructure, documentation cleanup
- **v4.5.0**: Module organization improvements
- **v3.5.0**: Dual interface (Console + TUI), fuzzy search
- **v3.0.0**: Python framework implementation
- **Earlier**: Bash-based automation and prototyping

---

For detailed information about each version, see the git commit history and release notes.
