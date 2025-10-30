# PurpleSploit Framework Documentation

Welcome to the PurpleSploit Framework documentation! This directory contains comprehensive guides for all framework features.

---

## 📚 Core Documentation

### [Framework Guide](FRAMEWORK_README.md)
**Complete framework documentation**
- Architecture overview
- Module system
- Variable management
- Workspace organization
- Adding custom modules
- Examples and tutorials

### [Features Guide](FEATURES.md)
**Enhanced features documentation**
- FZF integration and usage
- Multi-credential management
- Multi-target tracking
- Mythic C2 integration
- Usage examples
- Troubleshooting

### [Service Analysis Guide](SERVICE_ANALYSIS.md)
**Smart module selection**
- How service analysis works
- `search relevant` command
- Service-to-module mapping
- Auto-detection from nmap scans
- Manual import
- Advanced workflows

---

## 🚀 Quick Links

### Getting Started
- **Installation:** See main [README.md](../README.md#installation)
- **Quick Start:** See main [README.md](../README.md#quick-start)
- **Module Template:** [../MODULE_TEMPLATE.psm](../MODULE_TEMPLATE.psm)

### Key Concepts

#### Universal Variables
Set once, use everywhere:
```bash
set RHOST 192.168.1.100
set USERNAME admin
# Variables work across all modules!
```

#### Smart Module Search
```bash
# Run nmap scan
use recon/nmap/quick_scan
run

# Shows ONLY relevant modules
search relevant
```

#### FZF Menus
Interactive point-and-click:
```bash
search          # Search modules
targets         # Select target
credentials     # Load credentials
workspace       # Switch workspace
```

---

## 📖 Documentation by Topic

### Architecture & Design
- **[Framework Architecture](FRAMEWORK_README.md#architecture)** - System design
- **[Module System](FRAMEWORK_README.md#module-system)** - How modules work
- **[Directory Structure](FRAMEWORK_README.md#directory-structure)** - File organization

### Features
- **[FZF Integration](FEATURES.md#-fzf-integration)** - Interactive menus
- **[Credential Management](FEATURES.md#-credential-management)** - Multi-cred system
- **[Target Management](FEATURES.md#-multi-target-management)** - Organize targets
- **[Mythic C2](FEATURES.md#-mythic-c2-integration)** - Agent deployment
- **[Service Analysis](SERVICE_ANALYSIS.md)** - Smart module filtering

### Usage
- **[Command Reference](FRAMEWORK_README.md#commands)** - All commands
- **[Usage Examples](FEATURES.md#-usage-examples)** - Real-world scenarios
- **[Creating Modules](FRAMEWORK_README.md#adding-new-modules)** - Custom tools
- **[Troubleshooting](FEATURES.md#-troubleshooting)** - Common issues

---

## 🔧 Development

### Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code style guidelines
- Pull request process
- Testing requirements
- Documentation standards

### Creating Modules
1. Copy [../MODULE_TEMPLATE.psm](../MODULE_TEMPLATE.psm)
2. Edit module metadata and command template
3. Drop in `modules/` directory
4. Restart framework - auto-discovered!

**Full guide:** [Framework Guide - Adding Modules](FRAMEWORK_README.md#adding-new-modules)

---

## 🗂️ Legacy Documentation

Documentation for the "lite" version (TUI-based) is preserved in [legacy/](legacy/):

- **[ARCHITECTURE.md](legacy/ARCHITECTURE.md)** - Lite version architecture
- **[USAGE_GUIDE.md](legacy/USAGE_GUIDE.md)** - Lite version usage
- **[HANDLER_REFERENCE.md](legacy/HANDLER_REFERENCE.md)** - Handler functions
- **[LINE_MAPPING.md](legacy/LINE_MAPPING.md)** - Code migration map
- **[REFACTORING_SUMMARY.md](legacy/REFACTORING_SUMMARY.md)** - Refactoring details

Launch lite version: `./purplesploit.sh`

---

## 📊 Documentation Map

```
docs/
├── README.md                    # This file (documentation index)
├── FRAMEWORK_README.md          # Complete framework guide
├── FEATURES.md                  # FZF, credentials, Mythic C2
├── SERVICE_ANALYSIS.md          # Smart module selection
├── CONTRIBUTING.md              # Contribution guidelines
│
└── legacy/                      # Lite version documentation
    ├── ARCHITECTURE.md
    ├── USAGE_GUIDE.md
    ├── HANDLER_REFERENCE.md
    ├── LINE_MAPPING.md
    ├── REFACTORING_SUMMARY.md
    ├── README_REFACTORING.md
    ├── TASK_COMPLETION_SUMMARY.md
    └── QUICKSTART.txt
```

---

## 🆘 Need Help?

### In Framework
```bash
purplesploit> help           # Full command list
purplesploit> quickstart     # Quick start guide
purplesploit> info           # Current module details
```

### Documentation
- **Main README:** [../README.md](../README.md)
- **Framework Guide:** [FRAMEWORK_README.md](FRAMEWORK_README.md)
- **Feature Guide:** [FEATURES.md](FEATURES.md)
- **Service Analysis:** [SERVICE_ANALYSIS.md](SERVICE_ANALYSIS.md)

### Support
- **GitHub Issues:** https://github.com/jeremylaratro/purplesploit/issues
- **Module Template:** [../MODULE_TEMPLATE.psm](../MODULE_TEMPLATE.psm)

---

## 🎯 Common Tasks

### Add a New Module
1. Read: [Framework Guide - Adding Modules](FRAMEWORK_README.md#adding-new-modules)
2. Copy: [../MODULE_TEMPLATE.psm](../MODULE_TEMPLATE.psm)
3. Create: `modules/category/tool/action.psm`

### Use FZF Features
Read: [Features Guide - FZF Integration](FEATURES.md#-fzf-integration)

### Setup Mythic C2
Read: [Features Guide - Mythic Integration](FEATURES.md#-mythic-c2-integration)

### Understand Service Analysis
Read: [Service Analysis Guide](SERVICE_ANALYSIS.md)

### Manage Credentials
Read: [Features Guide - Credential Management](FEATURES.md#-credential-management)

---

<div align="center">

**🟣 Happy Hacking! 🟣**

[Main README](../README.md) • [GitHub](https://github.com/jeremylaratro/purplesploit)

</div>
