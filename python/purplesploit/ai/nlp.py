"""
Natural Language Query Handler for PurpleSploit

Processes natural language questions about the pentest context
and provides intelligent responses.
"""

from typing import Dict, Any, List, Optional, Tuple
import re


class NLPQueryHandler:
    """
    Handles natural language queries about pentesting context.

    Supports questions like:
    - "What can I do with these SMB shares?"
    - "How do I escalate privileges?"
    - "What should I try next?"
    """

    def __init__(self, framework=None):
        self.framework = framework

        # Intent patterns
        self.intent_patterns = {
            "next_steps": [
                r"what.*(should|can|could).*(do|try|run).*next",
                r"what.*next.*step",
                r"suggest.*module",
                r"recommend.*action",
                r"what.*now",
            ],
            "service_actions": [
                r"what.*(can|could).*(do|try).*with.*(smb|ldap|http|ssh|rdp|winrm|kerberos|dns)",
                r"how.*(attack|exploit|enumerate).*(smb|ldap|http|ssh|rdp|winrm|kerberos|dns)",
                r"(smb|ldap|http|ssh|rdp|winrm|kerberos|dns).*options",
            ],
            "privilege_escalation": [
                r"(how|what).*(escalate|privesc|privilege)",
                r"become.*(admin|root|system)",
                r"get.*(higher|more).*privilege",
            ],
            "lateral_movement": [
                r"(how|what).*(lateral|move|pivot)",
                r"access.*other.*(machine|host|computer)",
                r"spread.*network",
            ],
            "credential_harvest": [
                r"(get|find|extract|harvest|dump).*(credential|password|hash)",
                r"where.*(password|credential)",
                r"crack.*hash",
            ],
            "status_query": [
                r"(what|show).*(found|discovered|have)",
                r"current.*(status|state|progress)",
                r"summary",
            ],
            "module_help": [
                r"how.*(use|run).*(module|tool)",
                r"help.*(with|using)",
                r"explain.*module",
            ],
            "attack_path": [
                r"(attack|exploitation).*(path|chain|route)",
                r"how.*(get|reach).*domain.*admin",
                r"way.*(compromise|pwn)",
            ],
        }

        # Response templates
        self.response_templates = {
            "next_steps": self._respond_next_steps,
            "service_actions": self._respond_service_actions,
            "privilege_escalation": self._respond_privesc,
            "lateral_movement": self._respond_lateral,
            "credential_harvest": self._respond_creds,
            "status_query": self._respond_status,
            "module_help": self._respond_module_help,
            "attack_path": self._respond_attack_path,
        }

    def process_query(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process a natural language query.

        Args:
            query: Natural language question
            context: Optional context dict with services, creds, etc.

        Returns:
            Response dict with answer and suggestions
        """
        query = query.lower().strip()
        context = context or {}

        # Load context from framework if not provided
        if self.framework and not context:
            context = self._load_framework_context()

        # Detect intent
        intent, extracted = self._detect_intent(query)

        if not intent:
            return {
                "success": False,
                "message": "I couldn't understand your question. Try asking about:\n"
                          "- What to do next\n"
                          "- How to attack a specific service (SMB, HTTP, etc.)\n"
                          "- How to escalate privileges\n"
                          "- How to harvest credentials",
            }

        # Generate response
        handler = self.response_templates.get(intent)
        if handler:
            return handler(query, context, extracted)

        return {"success": False, "message": "No handler for detected intent"}

    def _detect_intent(
        self,
        query: str,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Detect the intent of a query."""
        extracted = {}

        for intent, patterns in self.intent_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, query, re.IGNORECASE)
                if match:
                    # Extract any captured groups
                    groups = match.groups()
                    if groups:
                        extracted["matched_groups"] = groups

                    # Extract service mentions
                    services = re.findall(
                        r"(smb|ldap|http|https|ssh|rdp|winrm|kerberos|dns|ftp|mssql)",
                        query,
                        re.IGNORECASE
                    )
                    if services:
                        extracted["services"] = [s.lower() for s in services]

                    return intent, extracted

        return None, {}

    def _load_framework_context(self) -> Dict[str, Any]:
        """Load context from framework."""
        context = {
            "services": [],
            "credentials": [],
            "targets": [],
            "findings": [],
        }

        if not self.framework:
            return context

        try:
            # Get services
            services = self.framework.database.get_all_services()
            context["services"] = [s.to_dict() for s in services]

            # Get credentials
            creds = self.framework.database.get_all_credentials()
            context["credentials"] = [c.to_dict() for c in creds]

            # Get targets
            targets = self.framework.database.get_all_targets()
            context["targets"] = [t.to_dict() for t in targets]

            # Get current target
            if hasattr(self.framework, 'session'):
                context["current_target"] = self.framework.session.get_current_target()

        except Exception:
            pass

        return context

    def _respond_next_steps(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to 'what next' questions."""
        services = context.get("services", [])
        creds = context.get("credentials", [])

        suggestions = []

        if not services:
            suggestions.append({
                "action": "Run reconnaissance",
                "module": "recon/nmap",
                "reason": "No services discovered yet. Start with network scanning.",
                "priority": "high",
            })
        else:
            # Analyze services and suggest
            from .recommender import ModuleRecommender
            recommender = ModuleRecommender(self.framework)
            recommendations = recommender.get_recommendations(
                services=services,
                credentials=creds,
            )

            for rec in recommendations[:5]:
                suggestions.append({
                    "action": rec.reason,
                    "module": rec.module_path,
                    "priority": rec.priority.value,
                })

        return {
            "success": True,
            "message": "Based on your current context, here are my suggestions:",
            "suggestions": suggestions,
            "context_summary": {
                "services_found": len(services),
                "credentials_available": len(creds) > 0,
            },
        }

    def _respond_service_actions(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to service-specific questions."""
        target_services = extracted.get("services", [])

        if not target_services:
            return {
                "success": False,
                "message": "Please specify a service (SMB, HTTP, LDAP, etc.)",
            }

        has_creds = len(context.get("credentials", [])) > 0

        from .recommender import ModuleRecommender
        recommender = ModuleRecommender(self.framework)

        all_actions = []
        for service in target_services:
            recs = recommender.get_recommendations_for_service(
                service=service,
                has_creds=has_creds,
            )
            all_actions.extend([
                {
                    "service": service.upper(),
                    "module": r.module_path,
                    "description": r.reason,
                    "priority": r.priority.value,
                }
                for r in recs
            ])

        return {
            "success": True,
            "message": f"Here's what you can do with {', '.join(s.upper() for s in target_services)}:",
            "actions": all_actions,
            "tip": "Use 'use <module>' to select a module, then 'options' to see parameters.",
        }

    def _respond_privesc(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to privilege escalation questions."""
        suggestions = []

        # Windows privesc
        suggestions.append({
            "category": "Windows",
            "techniques": [
                "Token impersonation (SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege)",
                "Service misconfiguration (unquoted paths, weak permissions)",
                "AlwaysInstallElevated",
                "Credential harvesting (SAM, LSASS, cached creds)",
                "Kernel exploits (if outdated)",
            ],
            "modules": ["impacket/secretsdump", "post/windows_privesc"],
        })

        # Linux privesc
        suggestions.append({
            "category": "Linux",
            "techniques": [
                "SUID binaries (find / -perm -4000)",
                "Sudo misconfigurations (sudo -l)",
                "Capabilities (getcap -r /)",
                "Cron jobs with weak permissions",
                "Kernel exploits (if outdated)",
                "Writable /etc/passwd or shadow",
            ],
            "modules": ["post/linux_privesc"],
        })

        # AD-specific
        if any("ldap" in str(s).lower() for s in context.get("services", [])):
            suggestions.append({
                "category": "Active Directory",
                "techniques": [
                    "Kerberoasting (service account hashes)",
                    "AS-REP Roasting (users without pre-auth)",
                    "DCSync (if you have replication rights)",
                    "Pass the Hash/Ticket",
                    "BloodHound path analysis",
                ],
                "modules": [
                    "impacket/kerberoast",
                    "impacket/asreproast",
                    "impacket/secretsdump",
                ],
            })

        return {
            "success": True,
            "message": "Here are privilege escalation techniques to consider:",
            "suggestions": suggestions,
            "tip": "Run 'linpeas.sh' or 'winPEAS.exe' for automated enumeration.",
        }

    def _respond_lateral(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to lateral movement questions."""
        has_creds = len(context.get("credentials", [])) > 0

        techniques = []

        if has_creds:
            techniques.extend([
                {
                    "name": "Pass the Hash",
                    "module": "network/nxc_smb",
                    "description": "Use NTLM hash for authentication",
                    "requires": "NTLM hash",
                },
                {
                    "name": "Pass the Ticket",
                    "module": "impacket/psexec",
                    "description": "Use Kerberos ticket for authentication",
                    "requires": "Kerberos ticket",
                },
                {
                    "name": "WMI Execution",
                    "module": "impacket/wmiexec",
                    "description": "Execute commands via WMI",
                    "requires": "Valid credentials",
                },
                {
                    "name": "PSExec",
                    "module": "impacket/psexec",
                    "description": "Remote service execution",
                    "requires": "Admin credentials",
                },
                {
                    "name": "WinRM",
                    "module": "network/nxc_winrm",
                    "description": "PowerShell remoting",
                    "requires": "Valid credentials + WinRM enabled",
                },
            ])
        else:
            techniques.append({
                "name": "Credential Harvesting Required",
                "description": "You need credentials first. Try:\n"
                             "- SMB share enumeration\n"
                             "- Kerberoasting\n"
                             "- AS-REP Roasting\n"
                             "- LLMNR/NBT-NS poisoning",
            })

        # Add pivoting
        techniques.append({
            "name": "Network Pivoting",
            "module": "deploy/ligolo",
            "description": "Tunnel traffic through compromised host",
            "requires": "Shell access on pivot host",
        })

        return {
            "success": True,
            "message": "Lateral movement techniques:",
            "techniques": techniques,
            "tip": "Always check for local admin rights with 'nxc smb <target> -u user -p pass --local-auth'",
        }

    def _respond_creds(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to credential harvesting questions."""
        techniques = [
            {
                "name": "SMB Share Spider",
                "module": "network/nxc_smb",
                "operation": "spider",
                "description": "Search shares for files containing credentials",
                "files_to_find": [
                    "Groups.xml (GPP passwords)",
                    "web.config",
                    "*.config files",
                    "unattend.xml",
                    "*.ps1 scripts",
                ],
            },
            {
                "name": "Kerberoasting",
                "module": "impacket/kerberoast",
                "description": "Get service account hashes to crack offline",
                "requires": "Valid domain credentials",
            },
            {
                "name": "AS-REP Roasting",
                "module": "impacket/asreproast",
                "description": "Get hashes for users without pre-auth",
                "requires": "User list only",
            },
            {
                "name": "Secretsdump",
                "module": "impacket/secretsdump",
                "description": "Dump SAM, SECURITY, cached credentials",
                "requires": "Local admin access",
            },
            {
                "name": "LSASS Dump",
                "description": "Dump LSASS process memory for credentials",
                "tools": ["mimikatz", "procdump", "comsvcs.dll"],
                "requires": "Admin access + LSASS not protected",
            },
            {
                "name": "DCSync",
                "module": "impacket/secretsdump",
                "description": "Replicate AD credentials (domain controller sync)",
                "requires": "Replication rights (Domain Admin or similar)",
            },
        ]

        return {
            "success": True,
            "message": "Credential harvesting techniques:",
            "techniques": techniques,
            "cracking_tip": "Use hashcat or john to crack obtained hashes:\n"
                          "  hashcat -m 18200 asrep.txt wordlist.txt  # AS-REP\n"
                          "  hashcat -m 13100 kerberoast.txt wordlist.txt  # Kerberoast",
        }

    def _respond_status(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to status queries."""
        services = context.get("services", [])
        creds = context.get("credentials", [])
        targets = context.get("targets", [])

        # Count services by type
        service_counts = {}
        for svc in services:
            svc_name = svc.get("service", "unknown")
            service_counts[svc_name] = service_counts.get(svc_name, 0) + 1

        return {
            "success": True,
            "message": "Current assessment status:",
            "status": {
                "targets": len(targets),
                "services_discovered": len(services),
                "service_breakdown": service_counts,
                "credentials_found": len(creds),
                "current_target": context.get("current_target"),
            },
            "next_steps": "Use 'ai suggest' for recommendations based on this status.",
        }

    def _respond_module_help(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to module help questions."""
        return {
            "success": True,
            "message": "Module usage help:",
            "commands": [
                "search <term>     - Search for modules",
                "use <module>      - Select a module",
                "options           - Show module options",
                "set <opt> <val>   - Set an option",
                "run               - Execute the module",
                "ops               - Show module operations (if available)",
            ],
            "example": "use network/nxc_smb\n"
                      "set RHOST 192.168.1.100\n"
                      "ops  # See available operations\n"
                      "run",
        }

    def _respond_attack_path(
        self,
        query: str,
        context: Dict[str, Any],
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Respond to attack path questions."""
        services = context.get("services", [])
        creds = context.get("credentials", [])

        from .attack_paths import AttackPathAnalyzer
        analyzer = AttackPathAnalyzer(self.framework)

        paths = analyzer.analyze(
            services=services,
            credentials=creds,
        )

        if not paths:
            return {
                "success": True,
                "message": "No viable attack paths found with current resources.",
                "suggestion": "Run more enumeration to discover attack vectors.",
            }

        path_summaries = []
        for path in paths[:3]:
            path_summaries.append({
                "name": path.name,
                "probability": f"{path.total_probability:.0%}",
                "complexity": path.complexity,
                "steps": len(path.steps),
                "first_step": path.steps[0].name if path.steps else "N/A",
            })

        return {
            "success": True,
            "message": "Viable attack paths based on current context:",
            "paths": path_summaries,
            "tip": "Use 'ai attack-path <name>' for detailed steps.",
        }
