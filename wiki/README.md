# PurpleSploit Wiki

**Complete documentation for PurpleSploit v6.7.1**

---

## 📚 Documentation

### [Commands Reference](Commands-Reference.md)
**Complete command reference with tables**
- All module, target, credential commands
- Keyboard shortcuts and workflows
- Quick reference for daily use

### [Framework Guide](Framework-Guide.md)
**Understanding PurpleSploit architecture**
- Core concepts (modules, operations, context)
- Search vs ops explained
- Typical workflows and use cases
- Architecture overview

### [Web Portal](Web-Portal.md)
**Visual interface and web dashboard**
- Starting and using the web portal
- Background scanning
- Mobile interface
- API endpoints

---

## 🚀 Quick Start

### Installation
```bash
git clone https://github.com/jeremylaratro/purplesploit.git
cd purplesploit

# Install dependencies
apt install fzf ripgrep python3 netexec impacket-scripts nmap

# Launch
python3 -m purplesploit.main
```

### Basic Workflow
```bash
# Search and load module
purplesploit> search smb enum
purplesploit> use 1

# Set target and credentials
purplesploit(nxc_smb)> target 192.168.1.100
purplesploit(nxc_smb)> cred admin:password

# Run with interactive menu
purplesploit(nxc_smb)> run
```

---

## 📖 Additional Documentation

### Developer Resources
- [CONTRIBUTING.md](../docs/CONTRIBUTING.md) - Module development guide
- [CHANGELOG.md](../docs/CHANGELOG.md) - Version history

### Legal
- [DISCLAIMER.md](../docs/DISCLAIMER.md) - Legal disclaimer and authorized use

---

## 🎯 Key Features

- **50+ operations** across network, web, and Windows protocols
- **Persistent context** - Set target/cred once, use everywhere
- **Interactive selection** - fzf-powered fuzzy search
- **Auto-service detection** - Nmap results auto-populate modules
- **Web dashboard** - Mobile-friendly visual interface
- **Background scanning** - Continue working while scans run
- **Workspace isolation** - Organize by engagement

---

## 💡 Common Tasks

| Task | Command |
|------|---------|
| Search for modules | `search <query>` |
| Search for operations | `ops <query>` |
| Browse interactively | `module select` |
| Add target | `target <ip>` |
| Add credential | `cred <user:pass>` |
| Run module | `use <module>` then `run` |
| View detected services | `services` |
| Start web portal | `webserver start` |
| Get help | `help` |

---

## 🔗 External Links

- [GitHub Repository](https://github.com/jeremylaratro/purplesploit)
- [Report Issues](https://github.com/jeremylaratro/purplesploit/issues)
- [Discussions](https://github.com/jeremylaratro/purplesploit/discussions)

---

## 📝 Documentation Index

```
wiki/
├── README.md                 # This file - Documentation index
├── Commands-Reference.md     # Complete command tables
├── Framework-Guide.md        # Architecture and concepts
└── Web-Portal.md            # Web interface guide

docs/
├── CONTRIBUTING.md          # Developer guide
├── CHANGELOG.md             # Version history
└── DISCLAIMER.md            # Legal disclaimer
```

---

**Last Updated**: v6.7.1
**Philosophy**: Search. Select. Exploit.

*For questions or contributions, see [CONTRIBUTING.md](../docs/CONTRIBUTING.md)*
