# PurpleSploit TUI Setup Guide

## Visual Enhancements & Color Support

The PurpleSploit TUI has been enhanced with rich colors, gradients, and visual elements to improve the user experience. This guide helps you configure your terminal for optimal display.

## Terminal Requirements

### Required Features
- **UTF-8 encoding support** - For box drawing characters and emojis
- **256-color support** - For color gradients and themes
- **True color (24-bit) support** - Optional, for best visual experience

### Recommended Terminals

#### Linux
- **Kitty** ⭐ Best choice - Full unicode and true color support
- **Alacritty** - Fast GPU-accelerated terminal
- **GNOME Terminal** - Good default option
- **Konsole** - KDE's terminal with excellent support
- **Terminator** - Feature-rich with good unicode support

#### macOS
- **iTerm2** ⭐ Best choice for macOS
- **Kitty** - Cross-platform excellence
- **Alacritty** - Fast and reliable

#### Windows
- **Windows Terminal** ⭐ Modern and feature-complete
- **WSL2 + Any Linux terminal**
- **ConEmu** - Older but functional

### NOT Recommended
- ❌ Basic xterm (limited color support)
- ❌ Linux console/TTY (no unicode)
- ❌ Very old terminal emulators

## Terminal Configuration

### 1. Verify UTF-8 Encoding

Check your locale settings:
```bash
locale | grep -i utf
```

Should show UTF-8 encoding. If not, set it:
```bash
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```

Add to your `~/.bashrc` or `~/.zshrc`:
```bash
echo 'export LANG=en_US.UTF-8' >> ~/.bashrc
echo 'export LC_ALL=en_US.UTF-8' >> ~/.bashrc
```

### 2. Verify Color Support

Test 256 colors:
```bash
for i in {0..255}; do
    printf "\x1b[48;5;%sm%3d\e[0m " "$i" "$i"
    if (( i == 15 )) || (( i > 15 )) && (( (i-15) % 6 == 0 )); then
        printf "\n"
    fi
done
```

You should see a full color palette.

### 3. Configure TERM Variable

For best results, use one of these TERM values:
```bash
export TERM=xterm-256color
# OR
export TERM=screen-256color  # If using tmux/screen
```

Add to your shell config:
```bash
echo 'export TERM=xterm-256color' >> ~/.bashrc
```

## Troubleshooting Encoding Issues

### Issue: Box Characters Display as Question Marks

**Problem:** Terminal doesn't support UTF-8

**Solutions:**
1. Set UTF-8 locale (see above)
2. Switch to a modern terminal emulator
3. In terminal settings, enable UTF-8 character encoding

### Issue: Emojis Display Incorrectly

**Problem:** Missing emoji font support

**Solutions:**
1. Install emoji fonts:
   ```bash
   # Debian/Ubuntu
   sudo apt install fonts-noto-color-emoji

   # Arch Linux
   sudo pacman -S noto-fonts-emoji

   # macOS (usually has built-in support)
   ```

2. Update font cache:
   ```bash
   fc-cache -f -v
   ```

### Issue: Colors Look Washed Out or Wrong

**Problem:** Limited color support

**Solutions:**
1. Verify TERM variable is set to 256color variant
2. Check terminal preferences for color scheme settings
3. Update terminal to latest version

### Issue: Text Overlaps or Misaligns

**Problem:** Font doesn't support box-drawing characters

**Solutions:**
1. Use a monospace font with good unicode support:
   - **Recommended:** Fira Code, JetBrains Mono, Cascadia Code
   - **Also good:** DejaVu Sans Mono, Source Code Pro

2. Configure in terminal settings:
   - Gnome Terminal: Preferences → Profile → Text → Font
   - Kitty: Edit `~/.config/kitty/kitty.conf`:
     ```
     font_family JetBrains Mono
     ```

## FZF Color Customization

The TUI uses custom FZF color schemes. You can customize these in `purplesploit-tui.sh`:

```bash
--color="fg:#d0d0d0,bg:#000000,hl:#5f87af,fg+:#00ff00,bg+:#262626,hl+:#5fd7ff"
```

Color components:
- `fg` - Foreground text color
- `bg` - Background color
- `hl` - Highlight color (matching text)
- `fg+` - Selected item foreground
- `bg+` - Selected item background
- `hl+` - Selected item highlight
- `prompt` - Prompt color
- `pointer` - Selection pointer
- `marker` - Marked items

## Testing Your Setup

Run this test script to verify everything works:

```bash
#!/bin/bash
# Color test
echo -e "\033[1;31mRed\033[0m \033[1;32mGreen\033[0m \033[1;33mYellow\033[0m \033[1;34mBlue\033[0m"

# Unicode test
echo "Box: ┌─┐│└─┘ Arrows: ▶◀▲▼ Bullets: ●○◆"

# Emoji test
echo "Emojis: 🌐 🔒 🛠️ 💼 🤖 ⚙️ 🚪"

# Gradient test
echo -e "\033[95mPurple\033[35m->Magenta\033[96m->Cyan\033[36m->DarkCyan\033[0m"
```

If all elements display correctly, you're ready to use the enhanced TUI!

## Quick Fix for SSH Sessions

If colors don't work over SSH:

1. On your LOCAL machine, update SSH config (`~/.ssh/config`):
   ```
   Host *
       SendEnv LANG LC_*
   ```

2. On the REMOTE server, edit `/etc/ssh/sshd_config`:
   ```
   AcceptEnv LANG LC_*
   ```

3. Restart SSH service:
   ```bash
   sudo systemctl restart sshd
   ```

## Alternative: Disable Colors

If you can't fix encoding issues, you can disable colors:

```bash
# Set NO_COLOR environment variable
export NO_COLOR=1

# Or use the simple TUI instead
./bin/purplesploit-tui-simple.sh
```

## Performance Notes

- **Tmux/Screen users:** Use `TERM=screen-256color`
- **Slow terminals:** Colors may cause slight delay on very slow connections
- **WSL users:** Ensure Windows Terminal is updated to latest version

## Getting Help

If you continue to have display issues:

1. Check your terminal's documentation for UTF-8/unicode support
2. Verify font installation with: `fc-list | grep -i mono`
3. Test in a different terminal emulator
4. Check the terminal's character encoding settings (should be UTF-8)

## Visual Theme Customization

You can customize colors by editing `core/visual_theme.sh`:

```bash
# Change color definitions
BRIGHT_MAGENTA="\033[95m"
BRIGHT_CYAN="\033[96m"
# etc...
```

Or modify the enhanced banner function `show_enhanced_banner()` to use different colors.

## Summary Checklist

- ✅ Terminal supports UTF-8 encoding
- ✅ TERM variable set to `xterm-256color`
- ✅ Locale set to UTF-8 (LANG=en_US.UTF-8)
- ✅ Modern terminal emulator installed
- ✅ Monospace font with unicode support configured
- ✅ Emoji font package installed (optional)
- ✅ Colors and unicode characters display correctly

Once all items are checked, the PurpleSploit TUI will display beautifully!
