# AI Automation - PurpleSploit

## Overview

The AI Automation module integrates AI assistants (OpenAI GPT-4 and Claude) with PurpleSploit to enable intelligent, automated penetration testing workflows. This feature uses a Model Context Protocol (MCP) server to allow AI models to execute commands and tools on a Kali Linux machine.

## ⚠️ Important Security Notice

This feature enables AI models to execute arbitrary commands on your system. Use only:
- In authorized penetration testing environments
- With proper isolation (VMs, containers)
- In controlled lab environments
- Never on production systems without explicit authorization

## Features

### 🤖 Supported AI Providers
- **OpenAI GPT-4** - Advanced reasoning and tool use
- **Claude (Anthropic)** - Latest Sonnet models with enhanced capabilities

### 🔧 Capabilities
- Execute shell commands via AI natural language
- Automated nmap scanning with intelligent analysis
- Multi-step pentesting workflows
- Context-aware security assessments
- Background command execution
- Detailed output analysis

## Architecture

```
┌─────────────────┐
│  PurpleSploit   │
│      TUI        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AI Automation  │
│     Module      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────┐
│ ai_kali_client  │─────▶│ MCP Server   │
│   (Python)      │      │ (Kali API)   │
└────────┬────────┘      └──────┬───────┘
         │                       │
         ▼                       ▼
┌─────────────────┐      ┌──────────────┐
│  OpenAI/Claude  │      │ Kali Linux   │
│      API        │      │   Machine    │
└─────────────────┘      └──────────────┘
```

## Prerequisites

### 1. Python Dependencies

Install required Python packages:

```bash
pip3 install --user openai anthropic requests
```

Check installation:
```bash
python3 -c "import openai, anthropic, requests; print('✓ All packages installed')"
```

### 2. API Keys

#### For OpenAI (GPT-4):
```bash
export OPENAI_API_KEY='sk-your-api-key-here'
```

Add to `~/.bashrc` or `~/.zshrc` for persistence:
```bash
echo "export OPENAI_API_KEY='sk-your-api-key-here'" >> ~/.bashrc
source ~/.bashrc
```

#### For Claude (Anthropic):
```bash
export ANTHROPIC_API_KEY='sk-ant-your-api-key-here'
```

Add to profile:
```bash
echo "export ANTHROPIC_API_KEY='sk-ant-your-api-key-here'" >> ~/.bashrc
source ~/.bashrc
```

### 3. MCP Server (Kali API)

You need a running MCP server that provides the Kali API endpoint. This can be:
- Local server: `http://localhost:8000`
- Remote Kali machine: `http://192.168.1.100:8000`
- Docker container: `http://kali-container:8000`

The MCP server must expose these endpoints:
- `GET /health` - Health check
- `POST /api/command` - Execute shell command
- `POST /api/tools/nmap` - Run nmap scan

## Quick Start

### 1. Launch PurpleSploit TUI
```bash
./purplesploit-tui.sh
```

### 2. Navigate to AI Automation
From the main menu, select:
```
┌ AI AUTOMATION ─────────────────────────
AI Automation (OpenAI/Claude)
```

### 3. Check Dependencies
First time setup - verify all dependencies are installed:
```
Check Dependencies
```

This will check for:
- Python 3
- pip3
- openai package
- anthropic package
- requests package

### 4. Configure AI Provider
```
Configure AI Provider
```

Select your provider:
- **OpenAI (GPT-4)** - Default model: `gpt-4o`
- **Claude (Anthropic)** - Default model: `claude-sonnet-4-20250514`

Optional: Specify custom model name

### 5. Configure MCP Server
```
Configure MCP Server
```

Enter your MCP server URL:
- Local: `http://localhost:8000`
- Remote: `http://192.168.1.100:8000`

Set timeout (default: 3600 seconds / 1 hour)

### 6. Launch AI Assistant
```
Launch AI Assistant
```

This opens an interactive chat session with the AI.

## Usage Examples

### Example 1: Basic Reconnaissance
```
You: Scan the target 192.168.1.100 and tell me what services are running

🤖 Assistant: I'll run an nmap scan to identify services...
🔧 Running nmap scan on 192.168.1.100
✅ Nmap scan completed

Based on the scan results, I found:
- Port 22: OpenSSH 8.2p1 (SSH)
- Port 80: Apache httpd 2.4.41 (HTTP)
- Port 445: Samba smbd 4.11.6 (SMB)
- Port 3306: MySQL 8.0.23 (Database)

The target appears to be a Linux web server with SMB file sharing enabled...
```

### Example 2: Enumeration Workflow
```
You: Check if SMB allows anonymous login, then enumerate shares

🤖 Assistant: I'll test anonymous SMB access first...
🔧 Executing: nxc smb 192.168.1.100 -u '' -p ''
✅ Command completed (exit code: 0)

Anonymous access is allowed! Now enumerating shares...
🔧 Executing: nxc smb 192.168.1.100 -u '' -p '' --shares
✅ Command completed (exit code: 0)

Found accessible shares:
- IPC$ (IPC share)
- public (READ access)
- backup (READ access)

The 'backup' share might contain sensitive data. Should I enumerate its contents?
```

### Example 3: Multi-Step Attack Chain
```
You: Perform a full SMB enumeration workflow: test auth, list shares, check for vulnerabilities

🤖 Assistant: I'll execute a comprehensive SMB assessment...

Step 1: Testing authentication...
🔧 Executing: nxc smb 192.168.1.100 -u guest -p ''

Step 2: Enumerating shares...
🔧 Executing: nxc smb 192.168.1.100 -u guest -p '' --shares

Step 3: Checking vulnerabilities...
🔧 Executing: nxc smb 192.168.1.100 -M ms17-010
🔧 Executing: nxc smb 192.168.1.100 -M zerologon

Assessment complete. Summary:
- Guest access: Enabled
- Shares: 4 found (2 readable)
- Vulnerabilities: None detected
- Risk level: Medium (guest access enabled)
```

## Configuration Files

### AI Config Location
```
~/.purplesploit/ai_config
```

Contains:
- AI_PROVIDER (openai/claude)
- AI_MODEL (model name)
- MCP_SERVER_URL (server endpoint)
- AI_TIMEOUT (command timeout)

### View Configuration
From the AI Automation menu:
```
View Current Configuration
```

## Available Commands in AI Chat

Once in the AI assistant session:

- **Natural language queries** - "scan this target", "check SMB", "enumerate users"
- **Direct commands** - "run nmap -sV 192.168.1.100"
- **Multi-step workflows** - "scan, enumerate, then check for vulnerabilities"
- **quit/exit/q** - Exit the AI session

## Testing MCP Connection

Before launching the AI assistant:

```
Test MCP Connection
```

This performs a health check on the configured MCP server to ensure connectivity.

## Advanced Usage

### Custom Models

When configuring AI provider, you can specify custom models:

**OpenAI:**
- gpt-4o (default)
- gpt-4o-mini
- gpt-4-turbo

**Claude:**
- claude-sonnet-4-20250514 (default)
- claude-opus-4-20250514
- claude-3-5-sonnet-20241022

### Command Timeouts

For long-running commands (large scans, brute force attempts), increase the timeout:

```
Configure MCP Server
→ Timeout: 7200 (2 hours)
```

### Background Execution

The AI can utilize PurpleSploit's background job system:
```
You: Run a full port scan in the background while I work on other things
```

## Troubleshooting

### Error: "AI provider not configured"
**Solution:** Run "Configure AI Provider" first

### Error: "MCP server not configured"
**Solution:** Run "Configure MCP Server" and set the server URL

### Error: "OPENAI_API_KEY not set"
**Solution:**
```bash
export OPENAI_API_KEY='sk-your-key-here'
```

### Error: "Cannot connect to Kali API server"
**Solutions:**
1. Verify MCP server is running: `curl http://localhost:8000/health`
2. Check firewall rules
3. Verify URL is correct in configuration
4. Check MCP server logs

### Error: "ModuleNotFoundError: No module named 'openai'"
**Solution:**
```bash
pip3 install --user openai anthropic requests
```

### Connection Timeout
**Solutions:**
1. Increase timeout in MCP Server configuration
2. Check network connectivity to MCP server
3. Verify MCP server is responding: `curl -X POST http://localhost:8000/api/command -H "Content-Type: application/json" -d '{"command":"echo test"}'`

## Best Practices

### 1. Start Simple
Begin with basic commands to ensure everything works:
```
You: Run 'whoami' on the Kali machine
```

### 2. Verify Output
Always review AI-generated commands before they execute. The AI shows commands before execution.

### 3. Use Targeted Queries
Be specific about what you want:
- ✅ "Scan 192.168.1.100 for web services"
- ❌ "Scan everything"

### 4. Iterative Approach
Build on previous results:
```
You: Scan the target
You: Now enumerate the SMB service you found
You: Check if that share contains sensitive files
```

### 5. Context Awareness
The AI maintains conversation history, so you can reference previous findings:
```
You: Use the credentials from that dump to authenticate to SMB
```

## Security Considerations

### Isolation
- Run MCP server in isolated environment (VM/container)
- Never point to production systems
- Use dedicated test networks

### API Key Security
- Never commit API keys to git
- Use environment variables
- Rotate keys regularly
- Monitor API usage for anomalies

### Command Validation
- Review AI-generated commands
- The AI shows commands before execution
- Use timeouts to prevent runaway processes
- Monitor system resources

### Logging
- All AI sessions are logged
- Review logs for unexpected behavior
- MCP server logs all executed commands

## Integration with PurpleSploit Features

The AI assistant can leverage all PurpleSploit capabilities:

### Workspaces
```
You: Create a new workspace for this assessment
```

### Credentials
```
You: Add these credentials to the database: admin/Password123
```

### Target Management
```
You: Add 192.168.1.0/24 to targets
```

### Service Detection
```
You: Check what services are running on my current target
```

## Limitations

1. **AI Knowledge Cutoff** - AI models have training data cutoffs, may not know about very recent tools/exploits
2. **Command Execution** - AI can only execute what the MCP server allows
3. **Context Window** - Long conversations may exceed context limits
4. **Rate Limits** - API providers have rate limits on requests
5. **Cost** - OpenAI/Claude APIs are paid services

## Examples of AI-Driven Workflows

### Full Network Assessment
```
You: I need to assess the network 192.168.1.0/24. Perform a comprehensive scan, identify services, check for common vulnerabilities, and generate a summary report.
```

### Targeted Service Exploitation
```
You: Target has SMB on 445. Test for guest access, enumerate shares, spider for sensitive files, check for MS17-010
```

### Credential Attacks
```
You: I have a user list in users.txt. Test these against SSH on 192.168.1.50 with password 'Summer2024!'
```

### Post-Exploitation
```
You: I have SMB access to 192.168.1.100. Dump credentials, check for privilege escalation paths, and enumerate the domain
```

## Manual Command Execution

You can also use the AI client directly from command line:

```bash
cd /home/user/purplesploit
python3 tools/ai_kali_client.py \
  --server http://localhost:8000 \
  --provider claude \
  --model claude-sonnet-4-20250514 \
  --timeout 3600
```

Arguments:
- `--server` - MCP server URL (required)
- `--provider` - openai or claude (required)
- `--api-key` - API key (or use env var)
- `--model` - Custom model name
- `--timeout` - Timeout in seconds (default: 3600)

## Contributing

To extend AI capabilities:

1. Add new tool definitions in `tools/ai_kali_client.py`
2. Implement handlers in `UniversalKaliAgent` class
3. Update system prompt to describe new capabilities
4. Add corresponding MCP server endpoints

## References

- [OpenAI Function Calling](https://platform.openai.com/docs/guides/function-calling)
- [Claude Tool Use](https://docs.anthropic.com/claude/docs/tool-use)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [PurpleSploit Documentation](../README.md)

## Support

For issues or questions:
1. Check "Check Dependencies" in AI Automation menu
2. Review "Test MCP Connection" output
3. Check `~/.purplesploit/ai_config` settings
4. Verify API keys are set correctly
5. Check MCP server logs

---

**Version:** 1.0
**Last Updated:** 2025-11-03
**Integrated with:** PurpleSploit Framework 2.0
