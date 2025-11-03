#!/usr/bin/env python3
"""
Universal AI Kali MCP Client
Supports both OpenAI and Claude (Anthropic) APIs
Integrated with PurpleSploit Framework
"""

import os
import sys
import json
import requests
import argparse
from typing import Optional

class KaliAPIClient:
    """Client for interacting with Kali API server"""

    def __init__(self, server_url, timeout=3600):
        self.server_url = server_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()

    def check_health(self):
        """Check if the Kali API server is healthy"""
        try:
            response = self.session.get(
                f"{self.server_url}/health",
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Health check failed: {e}")
            return False

    def execute_command(self, command):
        """Execute a command on the Kali server"""
        try:
            response = self.session.post(
                f"{self.server_url}/api/command",
                json={"command": command},
                timeout=self.timeout
            )
            response.raise_for_status()
            result = response.json()

            # Map API response to expected format
            return {
                "success": result.get("success", False),
                "output": result.get("stdout", "") + result.get("stderr", ""),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "exit_code": result.get("return_code", 1),
                "timed_out": result.get("timed_out", False),
                "partial_results": result.get("partial_results", False)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "stdout": "",
                "stderr": "",
                "exit_code": 1
            }


class UniversalKaliAgent:
    """Universal AI Agent supporting OpenAI and Claude APIs"""

    SYSTEM_PROMPT = """You are a penetration testing assistant with access to a Kali Linux machine via function calls.

ABSOLUTE CRITICAL RULES - FOLLOW THESE OR YOU WILL FAIL:
1. You MUST use the execute_shell_command or run_nmap functions for EVERY command - NEVER simulate, guess, or make up output
2. You DO NOT know what is on the target system - you MUST execute commands to find out
3. NEVER say things like "the /home directory is empty" unless you actually received that exact output from a function call
4. If asked to run a command, you MUST call the function - do not provide example output or hypothetical results
5. You CANNOT see the filesystem, network, or system - you can ONLY see what functions return
6. After receiving function output, display it EXACTLY in a code block, then provide analysis
7. If you try to answer without calling a function when you should, you are FAILING your task

When a user asks you to run something, your response flow MUST be:
1. Call the appropriate function (execute_shell_command or run_nmap)
2. Wait for the real output
3. Display that exact output in a code block
4. Then provide your analysis

NEVER skip step 1. NEVER make up output. ALWAYS use functions when asked to execute commands or scans."""

    def __init__(self, api_key, kali_server_url, provider="openai", model=None, timeout=3600):
        self.provider = provider.lower()
        self.kali_client = KaliAPIClient(kali_server_url, timeout)

        if self.provider == "openai":
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key)
            self.model = model or "gpt-4o"
            self.conversation_history = [
                {"role": "system", "content": self.SYSTEM_PROMPT}
            ]
        elif self.provider == "claude":
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
            self.model = model or "claude-sonnet-4-20250514"
            self.conversation_history = []
        else:
            raise ValueError(f"Unknown provider: {provider}")

        # Define tools
        self.tools = self._get_tools()

    def _get_tools(self):
        """Get tool definitions for the current provider"""
        if self.provider == "openai":
            return [
                {
                    "type": "function",
                    "function": {
                        "name": "execute_shell_command",
                        "description": "Execute any shell command on the Kali Linux machine.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "string",
                                    "description": "The shell command to execute"
                                }
                            },
                            "required": ["command"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "run_nmap",
                        "description": "Run nmap port scanner",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "target": {"type": "string", "description": "Target IP/hostname"},
                                "scan_type": {"type": "string", "description": "Scan flags", "default": "-sV"},
                                "ports": {"type": "string", "description": "Port specification"},
                                "additional_args": {"type": "string", "description": "Additional arguments"}
                            },
                            "required": ["target"]
                        }
                    }
                }
            ]
        else:  # Claude
            return [
                {
                    "name": "execute_shell_command",
                    "description": "Execute any shell command on the Kali Linux machine.",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to execute"
                            }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "run_nmap",
                    "description": "Run nmap port scanner",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target IP/hostname"},
                            "scan_type": {"type": "string", "description": "Scan flags"},
                            "ports": {"type": "string", "description": "Port specification"},
                            "additional_args": {"type": "string", "description": "Additional arguments"}
                        },
                        "required": ["target"]
                    }
                }
            ]

    def execute_shell_command(self, command):
        """Execute command via Kali API"""
        print(f"\n🔧 Executing: {command}")
        result = self.kali_client.execute_command(command)

        if result.get("success"):
            exit_code = result.get('exit_code', 0)
            print(f"✅ Command completed (exit code: {exit_code})")
            output = result.get("stdout", "") + result.get("stderr", "")
            return {
                "success": True,
                "output": output,
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "exit_code": exit_code
            }
        else:
            print(f"❌ Command failed: {result.get('error', 'Unknown error')}")
            return {
                "success": False,
                "error": result.get("error", "Unknown error"),
                "output": result.get("output", "")
            }

    def run_nmap(self, target, scan_type="-sV", ports=None, additional_args=None):
        """Run nmap via specialized API endpoint"""
        print(f"\n🔧 Running nmap scan on {target}")
        try:
            payload = {"target": target, "scan_type": scan_type}
            if ports:
                payload["ports"] = ports
            if additional_args:
                payload["additional_args"] = additional_args

            response = self.kali_client.session.post(
                f"{self.kali_client.server_url}/api/tools/nmap",
                json=payload,
                timeout=self.kali_client.timeout
            )
            response.raise_for_status()
            result = response.json()

            if result.get("success"):
                print(f"✅ Nmap scan completed")
                return {
                    "success": True,
                    "output": result.get("stdout", "") + result.get("stderr", ""),
                    "exit_code": result.get("return_code", 0)
                }
            else:
                print(f"❌ Nmap scan failed")
                return result
        except Exception as e:
            print(f"❌ Nmap scan error: {e}")
            return {"success": False, "error": str(e), "output": ""}

    def chat_openai(self, user_message):
        """Handle OpenAI chat"""
        self.conversation_history.append({"role": "user", "content": user_message})

        while True:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.conversation_history,
                tools=self.tools,
                tool_choice="auto"
            )

            message = response.choices[0].message
            self.conversation_history.append({
                "role": "assistant",
                "content": message.content,
                "tool_calls": message.tool_calls
            })

            if message.tool_calls:
                for tool_call in message.tool_calls:
                    function_name = tool_call.function.name
                    function_args = json.loads(tool_call.function.arguments)

                    if function_name == "execute_shell_command":
                        result = self.execute_shell_command(function_args["command"])
                    elif function_name == "run_nmap":
                        result = self.run_nmap(
                            target=function_args["target"],
                            scan_type=function_args.get("scan_type", "-sV"),
                            ports=function_args.get("ports"),
                            additional_args=function_args.get("additional_args")
                        )
                    else:
                        result = {"error": f"Unknown function: {function_name}"}

                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(result)
                    })
                continue
            else:
                return message.content

    def chat_claude(self, user_message):
        """Handle Claude chat"""
        self.conversation_history.append({"role": "user", "content": user_message})

        while True:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.SYSTEM_PROMPT,
                messages=self.conversation_history,
                tools=self.tools
            )

            # Add assistant response to history
            self.conversation_history.append({
                "role": "assistant",
                "content": response.content
            })

            # Check for tool use
            tool_use_blocks = [block for block in response.content if block.type == "tool_use"]

            if tool_use_blocks:
                tool_results = []
                for tool_use in tool_use_blocks:
                    tool_name = tool_use.name
                    tool_input = tool_use.input

                    if tool_name == "execute_shell_command":
                        result = self.execute_shell_command(tool_input["command"])
                    elif tool_name == "run_nmap":
                        result = self.run_nmap(
                            target=tool_input["target"],
                            scan_type=tool_input.get("scan_type", "-sV"),
                            ports=tool_input.get("ports"),
                            additional_args=tool_input.get("additional_args")
                        )
                    else:
                        result = {"error": f"Unknown tool: {tool_name}"}

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use.id,
                        "content": json.dumps(result)
                    })

                # Add tool results to conversation
                self.conversation_history.append({
                    "role": "user",
                    "content": tool_results
                })
                continue
            else:
                # Extract text response
                text_blocks = [block.text for block in response.content if hasattr(block, "text")]
                return "\n".join(text_blocks)

    def chat(self, user_message):
        """Route to appropriate chat handler"""
        if self.provider == "openai":
            return self.chat_openai(user_message)
        else:
            return self.chat_claude(user_message)


def main():
    parser = argparse.ArgumentParser(
        description="Universal AI Kali Client - OpenAI and Claude support"
    )
    parser.add_argument("--server", required=True, help="Kali API server URL")
    parser.add_argument("--provider", choices=["openai", "claude"], required=True,
                       help="AI provider to use")
    parser.add_argument("--api-key", help="API key (or use OPENAI_API_KEY/ANTHROPIC_API_KEY env var)")
    parser.add_argument("--model", help="Model to use (default: gpt-4o for OpenAI, claude-sonnet-4-20250514 for Claude)")
    parser.add_argument("--timeout", type=int, default=3600,
                       help="Command timeout in seconds (default: 3600)")

    args = parser.parse_args()

    # Get API key
    if args.provider == "openai":
        api_key = args.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("❌ Error: OpenAI API key not provided!")
            print("   Set OPENAI_API_KEY or use --api-key")
            sys.exit(1)
    else:  # claude
        api_key = args.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            print("❌ Error: Claude API key not provided!")
            print("   Set ANTHROPIC_API_KEY or use --api-key")
            sys.exit(1)

    # Initialize agent
    print(f"🚀 Initializing {args.provider.upper()} Kali Agent...")
    agent = UniversalKaliAgent(
        api_key=api_key,
        kali_server_url=args.server,
        provider=args.provider,
        model=args.model,
        timeout=args.timeout
    )

    # Health check
    print(f"🔍 Checking connection to {args.server}...")
    if not agent.kali_client.check_health():
        print("❌ Cannot connect to Kali API server!")
        sys.exit(1)

    print("✅ Connected to Kali API server")
    print(f"🤖 Provider: {args.provider.upper()}")
    print(f"🤖 Model: {agent.model}")
    print(f"⏱️  Timeout: {args.timeout} seconds ({args.timeout//60} minutes)")
    print("\n" + "="*60)
    print("AI Kali Agent Ready!")
    print("Type your security testing queries or 'quit' to exit")
    print("="*60 + "\n")

    # Main chat loop
    while True:
        try:
            user_input = input("You: ").strip()

            if not user_input:
                continue

            if user_input.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break

            print("\n🤖 Assistant: ", end="", flush=True)
            response = agent.chat(user_input)
            print(response)
            print()

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}\n")


if __name__ == "__main__":
    main()
