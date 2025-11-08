# Security Policy

## Reporting a Vulnerability

We take the security of PurpleSploit seriously. If you discover a security vulnerability in this project, we appreciate your help in disclosing it to us responsibly.

### What to Report

Please report any security issues including:

- **Code vulnerabilities** that could be exploited
- **Command injection** or other injection vulnerabilities
- **Authentication/authorization bypasses**
- **Insecure data handling** or storage
- **Dependency vulnerabilities** with security implications
- **Information disclosure** issues
- **Any other security concerns**

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by:

1. **Opening a private security advisory** on GitHub:
   - Go to the repository's "Security" tab
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **OR email the maintainers directly** with:
   - Subject line: `[SECURITY] Brief description`
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### What to Include

A good security report should include:

- **Description**: Clear explanation of the vulnerability
- **Impact**: What can an attacker do with this vulnerability?
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Proof of Concept**: Code or commands demonstrating the issue (if applicable)
- **Suggested Fix**: Your recommendations for fixing (optional but appreciated)
- **Environment**: Version of PurpleSploit, OS, Python version, etc.

### What to Expect

After you submit a vulnerability report:

1. **Acknowledgment**: Within 48 hours, we'll acknowledge receipt
2. **Assessment**: Within 7 days, we'll assess severity and validity
3. **Updates**: We'll keep you informed of our progress
4. **Fix Timeline**: Critical issues will be addressed immediately; others based on severity
5. **Disclosure**: We'll coordinate disclosure timing with you
6. **Credit**: With your permission, we'll credit you in release notes

### Disclosure Policy

We follow **coordinated disclosure**:

- **Do not** publicly disclose the vulnerability until we've released a fix
- Allow us **reasonable time** to fix the issue (typically 90 days)
- We'll work with you on the **disclosure timeline**
- We'll credit you when the fix is released (unless you prefer anonymity)

### Supported Versions

We provide security updates for:

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | ✅ Yes            |
| 2.x     | ⚠️ Limited        |
| < 2.0   | ❌ No             |

### Security Best Practices for Users

When using PurpleSploit:

#### Secure Your Environment
- **Run in isolated environments** (VMs, containers)
- **Use dedicated systems** for penetration testing
- **Keep tools updated** to latest versions
- **Review code** before running on production systems

#### Protect Sensitive Data
- **Never commit credentials** to version control
- **Use workspace isolation** for different engagements
- **Encrypt sensitive data** at rest
- **Securely delete** results when engagement is complete

#### Network Security
- **Use VPNs** when testing remote systems
- **Isolate test networks** from production
- **Monitor your traffic** during testing
- **Follow scope restrictions** strictly

#### Authentication
- **Rotate credentials** after testing
- **Use service accounts** when possible
- **Implement least privilege** for testing accounts
- **Log all authentication attempts**

### Known Security Considerations

#### By Design
PurpleSploit is designed to:
- Execute system commands (by design as a pentesting tool)
- Store credentials locally (encrypted when possible)
- Make network connections to target systems
- Read/write files in the workspace

These are **intentional features** but require:
- Proper authorization before use
- Secure host environment
- Trusted input only
- Regular security updates

#### User Responsibilities
Users must:
- ✅ Obtain proper authorization
- ✅ Secure their testing environment
- ✅ Protect stored credentials
- ✅ Follow responsible disclosure
- ✅ Comply with applicable laws

### Dependencies

We regularly monitor dependencies for vulnerabilities:

- **Python dependencies**: Checked via Dependabot
- **System tools**: Users responsible for keeping updated (nmap, netexec, impacket, etc.)
- **Known issues**: Listed in releases when applicable

To check your installation:
```bash
# Check Python dependencies
pip list --outdated

# Verify tool versions
nmap --version
netexec --version
```

### Security Updates

Security updates are released:
- **Critical**: Within 24-48 hours
- **High**: Within 1 week
- **Medium**: Within 1 month
- **Low**: Next regular release

Subscribe to releases to stay informed:
- Watch the repository
- Enable security alerts
- Check release notes regularly

### Bug Bounty Program

Currently, we do not have a formal bug bounty program. However:
- We deeply appreciate security research
- We'll credit responsible disclosure in release notes
- We're committed to addressing valid vulnerabilities promptly

### Security Hardening Tips

#### For Developers
```bash
# Run security checks
bandit -r python/
safety check
pip-audit
```

#### For Users
```bash
# Verify file integrity
sha256sum purplesploit-tui.sh

# Check for malicious modifications
git verify-commit HEAD

# Review changes before updating
git diff v3.2..v3.3
```

### Questions?

If you have questions about:
- **Security features**: Open a GitHub Discussion
- **Security vulnerabilities**: Use private reporting (see above)
- **Security best practices**: Check documentation or open a Discussion

### Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

<!-- Future contributors will be listed here -->
*No vulnerabilities reported yet. Be the first to help secure PurpleSploit!*

---

## Legal Notice

This project is for **authorized security testing only**. Reporting a vulnerability in PurpleSploit itself is different from using PurpleSploit to test other systems.

- **Testing PurpleSploit**: Please report responsibly as described above
- **Using PurpleSploit**: Only on systems you're authorized to test

See [DISCLAIMER.md](DISCLAIMER.md) for full legal terms.

---

**Thank you for helping keep PurpleSploit and its users safe!**
