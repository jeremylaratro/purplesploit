"""Shared shell-free Impacket adapters and structured output helpers."""

import re
import shlex

from purplesploit.core.module import ExternalToolModule


def observation(kind, target, **attributes):
    """Keep secrets in attributes, never in the observation's target."""
    return {"kind": kind, "target": str(target or ""), "attributes": attributes}


def account(identity, domain=""):
    if "\\" in identity:
        return tuple(identity.split("\\", 1))
    if "@" in identity:
        username, realm = identity.rsplit("@", 1)
        return realm, username
    return domain, identity


class ImpacketAdapter(ExternalToolModule):
    """Build argv directly while retaining the legacy command preview API."""

    emits = ()
    interactive = False

    def build_command(self):
        return shlex.join(self.build_argv())

    def authentication_argv(self, remote=True):
        domain = self.get_option("DOMAIN") or ""
        username = self.get_option("USERNAME") or ""
        password = self.get_option("PASSWORD")
        hash_value = self.get_option("HASH")
        target = f"{domain}/{username}"
        if password is not None and not hash_value:
            target += f":{password}"
        if remote:
            target += f"@{self.get_option('RHOST') or ''}"
        argv = [self.tool_name, target]
        if hash_value:
            argv += ["-hashes", str(hash_value)]
        elif password is None:
            argv.append("-no-pass")
        return argv

    def get_operation_manifest(self):
        required = [key for key, value in self.options.items() if value.get("required")]
        return [{
            "id": "run", "name": self.name, "description": self.description,
            "handler": self.run, "tool": self.tool_name,
            "requires": required,
            "optional": [key for key in self.options if key not in required],
            "interactive": self.interactive and not bool(self.get_option("COMMAND")),
            "background": False, "emits": list(self.emits),
            "supported_tool_versions": [],
            "tool_version_status": "Upstream CLI source checked; installed version unavailable",
            "standards": [], "subcategory": "impacket",
        }]

    def run(self):
        if not self.check_tool_installed():
            return {"success": False, "error": f"Tool not found: {self.tool_name}. Please install it first."}
        try:
            result = self.execute_command(self.build_argv())
            parsed = self.parse_output(result.get("stdout", ""))
            if not result.get("success"):
                parsed["observations"] = [item for item in parsed.get("observations", [])
                                          if item.get("kind") != "session"]
            result["parsed"] = parsed
            result["observations"] = parsed.get("observations", [])
            if parsed.get("credentials"):
                result["credentials"] = parsed["credentials"]
            return result
        except (ValueError, OSError) as exc:
            return {"success": False, "error": str(exc)}

    def roast_observations(self, output, kind):
        observations, credentials = [], []
        for line in output.splitlines():
            line = line.strip()
            pattern = (r"\$krb5asrep\$(?:\d+\$)?([^:]+):" if kind == "asrep"
                       else r"\$krb5tgs\$\d+\$\*?([^$]+)\$([^$]+)\$")
            match = re.search(pattern, line)
            if not match:
                continue
            if kind == "asrep":
                domain, username = account(match[1], self.get_option("DOMAIN") or "")
            else:
                domain, username = match[2], match[1].lstrip("*")
            record = {"username": username, "domain": domain, "hash": line[match.start():],
                      "hash_type": f"krb5{kind}", "source": self.tool_name,
                      "credential_type": "offline_hash", "authenticated": False}
            credentials.append(record)
            observations.append(observation("user", username, username=username, domain=domain))
            observations.append(observation("credential", self.get_option("RHOST") or domain, **record))
            observations.append(observation("resource", self.get_option("RHOST") or domain,
                                            resource_type="hash_artifact", **record))
        return observations, credentials

    def execution_observations(self, results):
        # A shell prompt or actual command output is evidence; a startup banner is not.
        output = [line for line in results["command_output"]
                  if not line.startswith("Impacket v") and line.strip()]
        executed = bool(results["shell_obtained"] or (self.get_option("COMMAND") and output))
        results["success"] = executed
        results["observations"] = []
        if executed:
            results["observations"].append(observation(
                "session", self.get_option("RHOST"), protocol="smb", service=self.tool_name,
                username=self.get_option("USERNAME"), domain=self.get_option("DOMAIN"),
                execution_status="observed", shell_obtained=results["shell_obtained"],
            ))
        return results
