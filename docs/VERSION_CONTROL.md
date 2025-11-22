# Documentation Version Control

This document describes the version control and documentation management system for PurpleSploit.

## Current Version

**PurpleSploit v6.1.0**

The current version is defined in `python/purplesploit/__init__.py` as `__version__ = "6.1.0"`.

## Version Control Policy

### Single Version Documentation

PurpleSploit maintains **only current version documentation**. This approach:

- **Reduces confusion**: Users always see documentation for the current version
- **Simplifies maintenance**: No need to update multiple doc versions
- **Keeps repository clean**: No historical documentation clutter
- **Improves discoverability**: Clear, focused documentation structure

### Version History

Historical version information is tracked in:

1. **CHANGELOG.md** (root directory)
   - High-level changes between versions
   - Feature additions, removals, and modifications
   - Breaking changes and migration notes
   - Comprehensive version history with semantic versioning

2. **Git History**
   - Detailed commit-by-commit changes
   - Use `git log --grep="Release"` to find version releases
   - Use `git tag` for version tags

3. **Git Tags**
   - Major releases are tagged (e.g., `v6.1.0`, `v6.0.0`, `v5.2.0`)
   - Use `git checkout <tag>` to view code at specific versions

## Recent Versions

- **v6.1.0** (2025-11-21): Web portal & API server, webserver command, real-time database sync
- **v6.0.1** (2025-11-21): Database corruption auto-recovery
- **v6.0.0** (2025-11-19): Pure Python edition, enhanced auto-completion, removed bash/TUI
- **v5.2.0** (2025-11-19): Shell command integration
- **v5.1.0** (2025-11-19): Ligolo-ng integration, console-only version
- **v5.0.0** (2025-11-17): Complete SMB module restructure, documentation cleanup
- **v4.6.0** (2025-11-09): Dynamic banner system, enhanced documentation
- **v4.5.1** (2025-11-08): Ops command bug fixes
- **v4.5.0** (2025-11-11): Module organization improvements
- **v3.8.0** (2025-11-08): Governance and licensing, documentation refactor
- **v3.5.0** (2025-11-08): Wordlist manager, module creator, interactive select
- **v3.3.0** (2025-11-08): Customized branding, module tree view
- **v3.2.0** (2025-11-07): Accessibility improvements, critical bug fixes
- **v3.1.0** (2025-11-07): Smart search and workflow improvements
- **v3.0.0** (2025-11-08): Python framework implementation, 86 operations
- **v2.9.0** (2025-11-07): Complete module port, 18 modules operational
- **v2.5.0** (2025-11-06): Module expansion, 11 modules operational

## Documentation Structure

```
purplesploit/
├── README.md                    # Main project documentation
├── QUICKSTART.md               # Quick start guide
├── DISCLAIMER.md               # Legal disclaimer
├── CHANGELOG.md                # Version history
├── docs/
│   ├── README.md               # Documentation index
│   ├── VERSION_CONTROL.md      # This file
│   ├── CONTRIBUTING.md         # Contribution guidelines
│   ├── ARCHITECTURE.md         # System architecture
│   └── console-mode/
│       └── README.md           # Console interface guide
├── python/
│   └── purplesploit/
│       ├── modules/            # Python module implementations
│       ├── core/               # Core framework
│       └── ui/                 # User interface
├── modules/
│   ├── nxc/
│   │   └── README.md           # NetExec module docs
│   └── impacket/
│       └── README.md           # Impacket module docs
```

## Version Update Process

When releasing a new version, follow these steps:

### 1. Update Version Number

Update the version in these files:

- `python/purplesploit/__init__.py` → `__version__ = "X.Y.Z"`
- `python/setup.py` → `version="X.Y.Z"`
- `python/purplesploit/main.py` → `version='PurpleSploit X.Y.Z'`
- `python/purplesploit/ui/display.py` → `Version X.Y.Z - Python Edition`
- `README.md` → `# PurpleSploit Framework vX.Y.Z`

### 2. Update CHANGELOG.md

Add a new section at the top of CHANGELOG.md:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features and additions

### Changed
- Modifications to existing features

### Deprecated
- Features marked for future removal

### Removed
- Features removed in this version

### Fixed
- Bug fixes

### Security
- Security-related changes
```

### 3. Review Documentation

Ensure all documentation reflects current functionality:

- [ ] README.md has current features and examples
- [ ] QUICKSTART.md has up-to-date installation steps
- [ ] Interface guides (console-mode/, tui-mode/) reflect current UI
- [ ] Module documentation matches current implementation
- [ ] No references to deprecated features

### 4. Create Git Tag

```bash
git tag -a v5.0.0 -m "Release v5.0.0: Complete SMB Module Restructure"
git push origin v5.0.0
```

## Handling Old Documentation

### Archive Policy

**We do NOT maintain archived documentation.** Old documentation is removed when:

- Features are significantly changed or removed
- Documentation becomes misleading or confusing
- Multiple conflicting versions exist

### Historical Reference

If users need to reference old versions:

1. **Check Git Tags**: `git checkout v4.5.0` to view that version
2. **View Commit History**: `git log` shows all changes
3. **Read CHANGELOG.md**: High-level overview of version changes

### Migration Guides

For major breaking changes, include migration notes in CHANGELOG.md:

```markdown
## [X.0.0] - YYYY-MM-DD

### Breaking Changes
- **Module Structure**: Modules reorganized from flat to hierarchical
  - **Migration**: Update module paths in custom scripts
  - **Example**: `smb_enum` → `network/nxc/smb/enumeration`
```

## Version Numbering

PurpleSploit follows [Semantic Versioning](https://semver.org/):

### Format: MAJOR.MINOR.PATCH

- **MAJOR** (X.0.0): Breaking changes, major restructures
- **MINOR** (x.Y.0): New features, non-breaking changes
- **PATCH** (x.y.Z): Bug fixes, minor improvements

### Examples

- `5.0.0`: Complete SMB module restructure (breaking)
- `4.5.0`: Module organization improvements (non-breaking)
- `4.5.1`: Bug fix for module loading (patch)

## Documentation Principles

1. **Current Over Historical**: Only document current version
2. **Clear Over Complete**: Focus on what users need now
3. **Examples Over Explanations**: Show, don't just tell
4. **Tested Over Theoretical**: All examples should work
5. **Maintained Over Static**: Regular updates to match code

## Contributing to Documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Documentation style guidelines
- Adding new documentation
- Updating existing docs
- Testing documentation changes

---

**Last Updated**: 2025-11-21 (v6.1.0)

For questions about documentation versioning, see the [Contributing Guide](CONTRIBUTING.md).
