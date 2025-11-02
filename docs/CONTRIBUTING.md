# Contributing to PurpleSploit

Thank you for your interest in contributing to PurpleSploit! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request:

1. Check existing issues to avoid duplicates
2. Create a new issue with a clear title and description
3. Include steps to reproduce (for bugs)
4. Specify your environment (OS, Python version, etc.)

### Code Contributions

1. **Fork the repository**
   ```bash
   git clone https://github.com/jeremylaratro/purplesploit.git
   cd purplesploit
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Test your changes thoroughly

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: Brief description of your changes"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**
   - Provide a clear description of changes
   - Reference any related issues
   - Explain testing performed

## Development Guidelines

### Code Style

#### Bash Scripts
- Use meaningful variable names
- Add comments for complex functions
- Follow existing indentation (4 spaces)
- Use `set -e` for error handling
- Quote variables to prevent word splitting

Example:
```bash
# Good
function enumerate_users() {
    local target="$1"
    local username="$2"

    if [[ -z "$target" ]]; then
        echo "Error: Target required"
        return 1
    fi

    nxc smb "$target" -u "$username" --users
}

# Bad
function enum() {
    nxc smb $1 -u $2 --users
}
```

#### Navi Cheatsheets
- Group related commands under same tags
- Provide clear descriptions
- Include example values
- Use consistent formatting

Format:
```
% nxc, protocol, category

# Clear description of what command does
nxc <protocol> <target> -u <username> -p <password> <flags>

$ target: echo "192.168.1.10"
$ username: echo "administrator"
$ password: echo "Password123"
```

### Testing

Before submitting:

1. **Test basic functionality**
   ```bash
   ./plat02.sh  # Verify menu navigation
   navi         # Verify cheatsheet loads
   ```

2. **Test your specific changes**
   - Test all code paths
   - Verify error handling
   - Check for unintended side effects

3. **Test on different systems** (if possible)
   - Kali Linux
   - Ubuntu
   - Debian

### Documentation

When adding features:

1. Update README.md if user-facing
2. Add comments in code
3. Update QUICKSTART.txt if adding common workflows
4. Add examples to nxc-fixed.cheat if adding NXC commands

## Areas for Contribution

### High Priority

1. **Testing & Bug Fixes**
   - Test on various Linux distributions
   - Fix reported bugs
   - Improve error handling

2. **NXC Command Templates**
   - Add missing NXC commands
   - Update deprecated commands
   - Add new modules

3. **Documentation**
   - Improve existing docs
   - Add tutorials
   - Create video guides

### Medium Priority

1. **Feature Enhancements**
   - Add new testing workflows
   - Improve menu navigation
   - Add export/import for configurations

2. **Framework Improvements**
   - Better error messages
   - Progress indicators
   - Log management

3. **Integration**
   - Add more tool integrations
   - API development
   - Plugin system

### Nice to Have

1. **UI Improvements**
   - Better color schemes
   - ASCII art banners
   - Progress bars

2. **Automation**
   - Automated testing workflows
   - Report generation
   - Results parsing

3. **Additional Protocols**
   - More protocol support
   - Cloud service testing
   - Container testing

## Adding New NXC Commands

To add commands to the cheatsheet:

1. Edit `nxc-fixed.cheat`
2. Follow the existing format
3. Group by protocol and category
4. Test with Navi

Example addition:
```bash
% nxc, smb, new-category

# Description of new command
nxc smb <target> -u <username> -p <password> --new-flag

$ target: echo "192.168.1.10"
$ username: echo "administrator"
$ password: echo "Password123"
```

## Modifying plat02.sh

When adding features to the main framework:

1. **Add menu option**
   ```bash
   function show_main_menu() {
       echo "1. Existing Option"
       echo "2. Your New Option"
   }
   ```

2. **Implement functionality**
   ```bash
   function your_new_feature() {
       # Add implementation
       echo "Running new feature..."
   }
   ```

3. **Add to menu handler**
   ```bash
   case $choice in
       1) existing_function ;;
       2) your_new_feature ;;
   esac
   ```

4. **Test thoroughly**
   ```bash
   ./plat02.sh
   # Navigate to your new option
   # Verify it works as expected
   ```

## Commit Message Guidelines

Use clear, descriptive commit messages:

```
Add: New feature description
Fix: Bug fix description
Update: Change to existing feature
Docs: Documentation changes
Refactor: Code refactoring
Test: Testing changes
```

Examples:
- `Add: SMB relay attack workflow to plat02.sh`
- `Fix: Web target URL concatenation bug`
- `Update: Improve error handling in credential management`
- `Docs: Add troubleshooting section to README`

## Pull Request Guidelines

### PR Title Format
```
[Type] Brief description

Types: Feature, Fix, Docs, Refactor, Test
```

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring

## Testing
Describe testing performed

## Checklist
- [ ] Code follows project style
- [ ] Documentation updated
- [ ] Tested on Linux
- [ ] No breaking changes (or documented)
```

## Code Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, PR will be merged
4. Your contribution will be credited

## Questions?

- Open an issue for questions
- Discussion tab for general questions
- Email maintainer for private matters

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers
- Focus on what's best for the project
- Show empathy towards others
- Accept constructive criticism gracefully

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing others' private information
- Other unprofessional conduct

### Enforcement

Violations may result in:
1. Warning
2. Temporary ban
3. Permanent ban

Report violations to the maintainer.

## Legal

### License Agreement

By contributing, you agree that your contributions will be licensed under the same license as the project.

### Security

**IMPORTANT**: Only contribute features for authorized security testing. Do not submit:
- Malicious code or exploits
- Code designed to harm systems
- Credential harvesting tools
- Unauthorized access mechanisms

All contributions must be for defensive security purposes.

### Responsible Disclosure

If you discover a security vulnerability:
1. Do NOT open a public issue
2. Email maintainer directly
3. Provide details and reproduction steps
4. Allow time for fix before public disclosure

## Getting Help

### Resources

- [NetExec Documentation](https://www.netexec.wiki/)
- [Navi Documentation](https://github.com/denisidoro/navi)
- [Bash Scripting Guide](https://tldp.org/LDP/abs/html/)

### Community

- GitHub Discussions
- Issue tracker
- Pull request comments

## Thank You!

Your contributions make PurpleSploit better for everyone. We appreciate your time and effort!

---

**Remember**: This tool is for authorized security testing only. Ensure all contributions align with ethical security practices.
