# Quick Start - PurpleSploit Rich TUI

Get started with the new Python Rich-based TUI in under 5 minutes!

## Installation

### Step 1: Install Python Dependencies

```bash
cd /home/user/purplesploit_private/python
pip3 install rich prompt_toolkit
```

Or install all dependencies:

```bash
pip3 install -r requirements.txt
```

### Step 2: Make the launcher executable

```bash
chmod +x bin/purplesploit-rich
```

## Launch

```bash
./bin/purplesploit-rich
```

You should see the beautiful PurpleSploit ASCII banner!

## First Steps

### 1. Set Up Your Workspace

When you first launch, you'll see the main menu. Let's set up your environment:

1. Select **"Settings"** from the main menu (usually option 12)
2. Choose **"Manage Workspaces"**
3. Press **'c'** to create a new workspace
4. Enter a name (e.g., "my-test")
5. Press **'s'** to switch to it
6. Press **'b'** to go back

### 2. Add a Target

1. From Settings menu, select **"Manage Targets"**
2. Press **'a'** to add a target
3. Enter the IP address (e.g., "192.168.1.100")
4. Press **'s'** to set it as current
5. Enter the target number or IP
6. Press Enter to continue

### 3. Set Credentials (Optional)

1. From Settings menu, select **"Manage Credentials"**
2. Press **'u'** for username/password auth
   - Or press **'h'** for NTLM hash auth
3. Enter your credentials
4. Press Enter to continue

### 4. Run a Service Scan

1. From Settings menu, select **"Run Service Scan"**
2. Type **"quick"** and press Enter (or just press Enter for default)
3. Wait for the scan to complete
4. You'll see all detected services with icons

### 5. Execute Tools

Now you're ready to run tools!

1. Press **'b'** to go back to main menu
2. Notice that categories with detected services are **highlighted with colored icons**
3. Select a category (e.g., "SMB Operations" if SMB was detected)
4. The tool menu will appear
5. Select a tool to execute

## Quick Reference

### Menu Navigation

- **1-9**: Select menu item by number
- **b** or **back**: Go back to previous menu
- **q** or **quit**: Exit application
- **Ctrl+C**: Cancel operation

### Common Operations

**Switch workspace:**
1. Settings → Manage Workspaces → (s)witch → Enter number or name

**Add target:**
1. Settings → Manage Targets → (a)dd → Enter IP

**Set variable:**
1. Settings → Set Variables → Enter name → Enter value

**Scan target:**
1. Settings → Run Service Scan → Choose type

## Interactive Mode

For command-line interface with autocomplete:

```bash
./bin/purplesploit-rich --interactive
```

Then try:

```bash
workspace list
target set 192.168.1.100
set LHOST 10.10.14.5
scan quick
menu  # Return to menu mode
```

Type **Tab** for autocomplete!

## Example Session

```bash
# Launch TUI
./bin/purplesploit-rich

# [Main Menu appears]
# Select: 12. Settings

# [Settings Menu appears]
# Select: 1. Manage Targets
# Enter: a (add)
# Enter: 192.168.1.100
# Enter: s (set)
# Enter: 1

# [Back to Settings Menu]
# Select: 5. Run Service Scan
# Enter: quick

# [Scan completes, services detected]
# Press Enter

# [Back to Settings Menu]
# Select: 7. Back

# [Main Menu - notice highlighted tools!]
# Select: 4. SMB Operations

# [SMB Menu appears with all SMB tools]
# Select your tool...
```

## Tips

1. **Service highlighting**: Tools glow when their service is detected - focus on these first!

2. **Context panel**: Always check the top panel to see your current workspace, target, and credentials

3. **Service icons**:
   - 🗄️ SMB
   - 📁 LDAP
   - 🖥️ WinRM
   - 🗃️ MSSQL
   - Green = detected, Red = not detected

4. **Autocomplete**: In interactive mode, use Tab to complete commands

5. **Variables**: Set common variables early:
   - LHOST (your IP)
   - LPORT (your port)
   - DOMAIN (target domain)

## What's Different from Bash TUI?

**Same:**
- All bash tools and scripts
- All data and databases
- Workspace system
- Framework variables

**New:**
- Beautiful Rich tables and panels
- Better visual organization
- Colored service indicators
- More intuitive navigation
- Python-powered UI

## Troubleshooting

**Can't find the script:**
```bash
cd /home/user/purplesploit_private
./bin/purplesploit-rich
```

**Missing modules:**
```bash
pip3 install rich prompt_toolkit
```

**Framework errors:**
Make sure you're in the project root directory!

## Next Steps

- Read the full [Rich TUI Documentation](RICH_TUI.md)
- Explore the [Main README](../README.md) for framework details
- Check out [Module Examples](examples/)

## Support

For issues or questions:
- Check docs/RICH_TUI.md for detailed information
- Review docs/INTERFACES.md for interface comparison
- Check the main README.md

Happy hacking! 🎯
