"""
AI Automation Module

AI-assisted pentesting automation using OpenAI or Anthropic.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List
import os
import sys


class AIAutomationModule(BaseModule):
    """
    AI Automation - AI-assisted pentesting workflows.

    Uses AI models to suggest next steps, analyze results, and
    automate decision-making in penetration tests.
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "AI Automation"

    @property
    def description(self) -> str:
        return "AI-assisted pentesting automation with OpenAI/Claude integration"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "ai"

    def get_operations(self) -> List[Dict[str, Any]]:
        """Return list of AI automation operations."""
        return [
            {
                "name": "Chat",
                "description": "Interactive AI chat for pentesting assistance",
                "handler": self.op_chat
            },
            {
                "name": "Suggest Next Steps",
                "description": "AI suggests next pentesting steps based on detected services",
                "handler": self.op_suggest
            },
            {
                "name": "Analyze Context",
                "description": "AI analyzes current pentest context and attack surface",
                "handler": self.op_analyze
            },
            {
                "name": "Automate Workflow",
                "description": "AI-driven automated pentesting workflow execution",
                "handler": self.op_automate
            },
        ]

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "PROVIDER": {
                "value": "openai",
                "required": False,
                "description": "AI provider (openai or anthropic)",
                "default": "openai"
            },
            "API_KEY": {
                "value": None,
                "required": False,
                "description": "API key (or set OPENAI_API_KEY/ANTHROPIC_API_KEY env var)",
                "default": None
            },
            "MODEL": {
                "value": "gpt-4",
                "required": False,
                "description": "Model to use (gpt-4, gpt-3.5-turbo, claude-3-sonnet-4, etc.)",
                "default": "gpt-4"
            },
            "PROMPT": {
                "value": None,
                "required": False,
                "description": "Custom prompt or question for AI (used in chat/analyze ops)",
                "default": None
            },
            "CONTEXT": {
                "value": None,
                "required": False,
                "description": "Additional context or data to analyze",
                "default": None
            }
        })

    def run(self) -> Dict[str, Any]:
        """
        Execute AI automation (legacy - use operations instead).

        Returns:
            Dictionary with error directing to use operations
        """
        return {
            "success": False,
            "error": "This module uses operations. Please select an operation to run.",
            "hint": "Available operations: Chat, Suggest Next Steps, Analyze Context, Automate Workflow"
        }

    def _get_api_key(self) -> tuple[str, str]:
        """
        Get API key for the configured provider.

        Returns:
            Tuple of (api_key, error_message). If successful, error_message is None.
        """
        provider = self.get_option("PROVIDER")
        api_key = self.get_option("API_KEY")

        # Get API key from env if not provided
        if not api_key:
            if provider == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
            elif provider == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY")

        if not api_key:
            error = f"No API key provided. Set {provider.upper()}_API_KEY environment variable or use API_KEY option."
            return None, error

        return api_key, None

    def _get_context_info(self) -> Dict[str, Any]:
        """
        Get current framework context.

        Returns:
            Dictionary with current target, credentials, services, etc.
        """
        current_target = self.framework.session.targets.get_current()
        current_cred = self.framework.session.credentials.get_current()
        services = self.framework.session.services.services

        return {
            "target": current_target,
            "credentials": current_cred.get("username") if current_cred else None,
            "services": services,
            "recent_modules": [entry["command"] for entry in self.framework.session.command_history[-5:]],
        }

    # ==================== OPERATION HANDLERS ====================

    def op_chat(self) -> Dict[str, Any]:
        """
        Interactive AI chat operation.

        Provides an interactive chat interface with the AI for pentesting assistance.
        """
        self.log("Starting AI chat session...", "info")

        api_key, error = self._get_api_key()
        if error:
            return {"success": False, "error": error}

        provider = self.get_option("PROVIDER")
        model = self.get_option("MODEL")

        # Get initial prompt if provided
        initial_prompt = self.get_option("PROMPT")

        # Try to import required libraries
        try:
            if provider == "openai":
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
            elif provider == "anthropic":
                import anthropic
                client = anthropic.Anthropic(api_key=api_key)
            else:
                return {"success": False, "error": f"Unknown provider: {provider}"}
        except ImportError as e:
            return {
                "success": False,
                "error": f"Failed to import {provider} library. Install with: pip install {provider}"
            }

        # Get context for system prompt
        context_info = self._get_context_info()

        system_prompt = f"""You are a penetration testing assistant integrated with PurpleSploit framework.

Current Context:
- Target: {context_info.get('target')}
- Credentials: {context_info.get('credentials') or 'None'}
- Detected Services: {list(context_info.get('services', {}).keys())}
- Recent Commands: {context_info.get('recent_modules', [])}

Provide concise, actionable pentesting advice and suggest specific PurpleSploit modules to use."""

        self.log(f"Using {provider} ({model})", "success")
        self.log("Type 'exit' or 'quit' to end chat session", "info")
        print()

        # Initialize conversation
        messages = []

        # Add initial prompt if provided
        if initial_prompt:
            user_input = initial_prompt
        else:
            try:
                user_input = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                return {"success": True, "message": "Chat session ended"}

        # Chat loop
        while user_input.lower() not in ['exit', 'quit', 'q']:
            if not user_input:
                try:
                    user_input = input("You: ").strip()
                    continue
                except (EOFError, KeyboardInterrupt):
                    break

            # Add user message
            messages.append({"role": "user", "content": user_input})

            try:
                # Call AI
                if provider == "openai":
                    response = client.chat.completions.create(
                        model=model,
                        messages=[{"role": "system", "content": system_prompt}] + messages,
                        temperature=0.7
                    )
                    assistant_message = response.choices[0].message.content
                elif provider == "anthropic":
                    response = client.messages.create(
                        model=model,
                        max_tokens=4096,
                        system=system_prompt,
                        messages=messages
                    )
                    # Extract text from response
                    assistant_message = ""
                    for block in response.content:
                        if hasattr(block, 'text'):
                            assistant_message += block.text

                # Add assistant response to history
                messages.append({"role": "assistant", "content": assistant_message})

                # Display response
                print(f"\nAI: {assistant_message}\n")

            except Exception as e:
                self.log(f"Error during chat: {str(e)}", "error")
                return {"success": False, "error": str(e)}

            # Get next input
            try:
                user_input = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

        return {
            "success": True,
            "message": "Chat session completed",
            "conversation_length": len(messages)
        }

    def op_suggest(self) -> Dict[str, Any]:
        """
        Suggest next pentesting steps operation.

        Analyzes detected services and suggests next pentesting steps.
        """
        self.log("Analyzing services and generating suggestions...", "info")

        context_info = self._get_context_info()
        result = self._suggest_next_steps(context_info)

        # Display suggestions nicely
        if result.get("success") and result.get("suggestions"):
            print("\n=== AI Pentesting Suggestions ===\n")
            for i, suggestion in enumerate(result["suggestions"], 1):
                priority = suggestion.get("priority", "info").upper()
                module = suggestion.get("module", "N/A")
                reason = suggestion.get("reason", "")

                print(f"{i}. [{priority}] {module}")
                print(f"   {reason}\n")

        return result

    def op_analyze(self) -> Dict[str, Any]:
        """
        Analyze pentest context operation.

        Analyzes current pentesting context including targets, services, and attack surface.
        """
        self.log("Analyzing current pentest context...", "info")

        context_info = self._get_context_info()
        user_context = self.get_option("CONTEXT")

        result = self._analyze_context(context_info, user_context)

        # Display analysis nicely
        if result.get("success") and result.get("analysis"):
            analysis = result["analysis"]
            print("\n=== AI Context Analysis ===\n")
            print(f"Target: {analysis.get('target_summary')}")
            print(f"Detected Services: {', '.join(analysis.get('detected_services', [])) or 'None'}")
            print(f"\nAttack Surface:")
            attack_surface = analysis.get('attack_surface', {})
            print(f"  Total Services: {attack_surface.get('total_services', 0)}")
            print(f"  High Value Targets: {', '.join(attack_surface.get('high_value_targets', [])) or 'None'}")
            print(f"  Weak Protocols: {', '.join(attack_surface.get('weak_protocols', [])) or 'None'}")
            print(f"\nRecommendations:")
            for i, rec in enumerate(analysis.get('recommendations', []), 1):
                print(f"  {i}. {rec}")
            print()

        return result

    def op_automate(self) -> Dict[str, Any]:
        """
        Automated workflow operation.

        Executes automated pentesting workflows based on AI analysis.
        """
        self.log("Starting automated workflow...", "info")

        context_info = self._get_context_info()
        result = self._automate_workflow(context_info)

        return result

    # ==================== HELPER METHODS ====================

    def _analyze_context(self, context_info: Dict, user_context: str = None) -> Dict[str, Any]:
        """
        Analyze current pentest context.

        Args:
            context_info: Current framework context
            user_context: Additional user-provided context

        Returns:
            Analysis results
        """
        # For now, return a structured analysis
        # In production, this would call OpenAI/Claude API

        analysis = {
            "success": True,
            "analysis": {
                "target_summary": self._summarize_target(context_info["target"]),
                "detected_services": list(context_info["services"].keys()) if context_info["services"] else [],
                "attack_surface": self._assess_attack_surface(context_info),
                "recommendations": self._generate_recommendations(context_info),
            }
        }

        self.log("AI analysis complete", "success")
        return analysis

    def _suggest_next_steps(self, context_info: Dict) -> Dict[str, Any]:
        """
        Suggest next pentesting steps.

        Args:
            context_info: Current framework context

        Returns:
            Suggested steps
        """
        suggestions = []

        # Analyze what's been done and what's next
        services = context_info.get("services", {})

        if not services:
            suggestions.append({
                "priority": "high",
                "module": "recon/nmap",
                "reason": "No services detected yet. Run nmap scan to discover attack surface."
            })

        for target, target_services in services.items():
            if "smb" in target_services and not any("smb" in cmd for cmd in context_info.get("recent_modules", [])):
                suggestions.append({
                    "priority": "high",
                    "module": "network/nxc_smb",
                    "reason": f"SMB detected on {target}. Enumerate shares and check for anonymous access."
                })

            if "ldap" in target_services:
                suggestions.append({
                    "priority": "medium",
                    "module": "network/nxc_ldap",
                    "reason": f"LDAP detected on {target}. Enumerate AD users and check for AS-REP roasting."
                })

            if "http" in target_services:
                suggestions.append({
                    "priority": "medium",
                    "module": "web/feroxbuster",
                    "reason": f"HTTP service detected on {target}. Discover hidden endpoints and files."
                })

        return {
            "success": True,
            "suggestions": suggestions if suggestions else [{
                "priority": "info",
                "module": None,
                "reason": "Continue reconnaissance or try alternative attack vectors."
            }]
        }

    def _automate_workflow(self, context_info: Dict) -> Dict[str, Any]:
        """
        Automate pentesting workflow.

        Args:
            context_info: Current framework context

        Returns:
            Automation results
        """
        return {
            "success": True,
            "message": "Automated workflow execution not yet implemented. Use 'suggest' action for recommendations.",
            "note": "This feature will automatically execute suggested modules based on detected services."
        }

    def _summarize_target(self, target: Dict) -> str:
        """Summarize target information."""
        if not target:
            return "No target configured"

        ip = target.get("ip") or target.get("url", "unknown")
        target_type = target.get("type", "unknown")
        return f"{target_type} target: {ip}"

    def _assess_attack_surface(self, context_info: Dict) -> Dict[str, Any]:
        """Assess attack surface based on detected services."""
        services = context_info.get("services", {})

        attack_surface = {
            "total_services": sum(len(s) for s in services.values()),
            "high_value_targets": [],
            "weak_protocols": [],
        }

        for target, target_services in services.items():
            if "smb" in target_services:
                attack_surface["high_value_targets"].append(f"{target}:SMB")
            if "ldap" in target_services:
                attack_surface["high_value_targets"].append(f"{target}:LDAP")
            if "winrm" in target_services:
                attack_surface["weak_protocols"].append(f"{target}:WinRM")

        return attack_surface

    def _generate_recommendations(self, context_info: Dict) -> list:
        """Generate security recommendations."""
        recommendations = []

        services = context_info.get("services", {})

        if not services:
            recommendations.append("Start with network reconnaissance (nmap)")

        if context_info.get("credentials"):
            recommendations.append("Valid credentials available - attempt authenticated enumeration")
        else:
            recommendations.append("No credentials configured - try anonymous/guest access")

        return recommendations
