"""
AI Automation Module

AI-assisted pentesting automation using OpenAI or Anthropic.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any
import os


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
                "description": "Model to use (gpt-4, gpt-3.5-turbo, claude-3-opus, etc.)",
                "default": "gpt-4"
            },
            "ACTION": {
                "value": "analyze",
                "required": False,
                "description": "Action: analyze, suggest, automate",
                "default": "analyze"
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
        Execute AI automation.

        Returns:
            Dictionary with AI suggestions and analysis
        """
        provider = self.get_option("PROVIDER")
        api_key = self.get_option("API_KEY")
        model = self.get_option("MODEL")
        action = self.get_option("ACTION")
        context = self.get_option("CONTEXT")

        # Get API key from env if not provided
        if not api_key:
            if provider == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
            elif provider == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY")

        if not api_key:
            return {
                "success": False,
                "error": f"No API key provided. Set {provider.upper()}_API_KEY environment variable or use API_KEY option."
            }

        # Get current framework context
        current_target = self.framework.session.targets.get_current()
        current_cred = self.framework.session.credentials.get_current()
        services = self.framework.session.services.services

        # Build context message
        context_info = {
            "target": current_target,
            "credentials": current_cred.get("username") if current_cred else None,
            "services": services,
            "recent_modules": [entry["command"] for entry in self.framework.session.command_history[-5:]],
        }

        # Perform action
        if action == "analyze":
            result = self._analyze_context(context_info, context)
        elif action == "suggest":
            result = self._suggest_next_steps(context_info)
        elif action == "automate":
            result = self._automate_workflow(context_info)
        else:
            return {
                "success": False,
                "error": f"Unknown action: {action}"
            }

        return result

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
