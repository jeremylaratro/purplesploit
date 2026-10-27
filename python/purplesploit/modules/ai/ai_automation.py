"""
AI Automation Module

AI-assisted pentesting automation using OpenAI or Anthropic.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List
import os
import json

from purplesploit.ai.advisory import AdvisoryService
from purplesploit.ai.providers import AdvisoryProvider, DEFAULT_MODELS
from purplesploit.ai.recommender import ModuleRecommender


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
                "name": "Propose Workflow",
                "description": "Generate and save an advisory draft workflow without execution",
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
                "value": None,
                "required": False,
                "description": "Provider model override (otherwise use the provider default)",
                "default": None
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
            "hint": "Available operations: Chat, Suggest Next Steps, Analyze Context, Propose Workflow"
        }

    def _get_api_key(self) -> tuple[str, str]:
        """
        Get API key for the configured provider.

        Returns:
            Tuple of (api_key, error_message). If successful, error_message is None.
        """
        provider = self.get_option("PROVIDER")
        if provider not in DEFAULT_MODELS:
            return None, f"Unknown provider: {provider}"
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
        model = self.get_option("MODEL") or DEFAULT_MODELS.get(provider)

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
        except ImportError:
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
                    response = client.responses.create(
                        model=model,
                        instructions=system_prompt,
                        input=messages,
                    )
                    assistant_message = response.output_text
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
        try:
            result = self._advisory().analyze(prompt=self.get_option("CONTEXT") or self.get_option("PROMPT"))
            print(json.dumps(result["analysis"], indent=2))
            return result
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def op_automate(self) -> Dict[str, Any]:
        """
        Automated workflow operation.

        Executes automated pentesting workflows based on AI analysis.
        """
        try:
            return self._advisory().propose_workflow(prompt=self.get_option("PROMPT"))
        except Exception as exc:
            return {"success": False, "error": str(exc), "executed": False}

    def _advisory(self):
        provider_name = self.get_option("PROVIDER")
        if provider_name not in DEFAULT_MODELS:
            raise ValueError(f"Unknown provider: {provider_name}")
        api_key, _ = self._get_api_key()
        provider = AdvisoryProvider(provider_name, self.get_option("MODEL"), api_key) if api_key else None
        return AdvisoryService(self.framework, provider=provider,
                               workflows=getattr(self.framework, "workflow_engine", None))

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
        return self._advisory().analyze(observations=context_info.get("observations"), prompt=user_context)

    def _suggest_next_steps(self, context_info: Dict) -> Dict[str, Any]:
        """
        Suggest next pentesting steps.

        Args:
            context_info: Current framework context

        Returns:
            Suggested steps
        """
        recommender = ModuleRecommender(self.framework)
        return {"success": True, "mode": "local", "suggestions": [item.to_dict() for item in recommender.get_recommendations(
            observations=context_info.get("observations"))]}

    def _automate_workflow(self, context_info: Dict) -> Dict[str, Any]:
        """
        Automate pentesting workflow.

        Args:
            context_info: Current framework context

        Returns:
            Automation results
        """
        return self._advisory().propose_workflow(observations=context_info.get("observations"))

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
