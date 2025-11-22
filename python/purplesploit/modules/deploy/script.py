"""
Script Deployment Module

Deploy enumeration scripts (WinPEAS, LinPEAS, custom scripts) to target systems.
Supports multiple deployment methods: NXC, SSH, SMB, PSExec.
"""

from purplesploit.core.module import BaseModule
import subprocess
from pathlib import Path
from typing import Dict, Any, List


class ScriptDeployModule(BaseModule):
    """
    Script Deployment - Deploy enumeration scripts to targets.

    Deploys enumeration scripts like WinPEAS, LinPEAS, or custom scripts
    to target systems with automatic execution and output capture.
    """

    def __init__(self, framework):
        super().__init__(framework)

    @property
    def name(self) -> str:
        return "Script Deploy"

    @property
    def description(self) -> str:
        return "Deploy enumeration scripts (WinPEAS, LinPEAS, custom) to targets"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "deploy"

    def get_operations(self) -> List[Dict[str, Any]]:
        """Return list of script deployment operations."""
        return [
            {
                "name": "Deploy WinPEAS via NXC",
                "description": "Deploy WinPEAS enumeration script using NetExec - Windows targets",
                "handler": self.deploy_winpeas_nxc
            },
            {
                "name": "Deploy WinPEAS via SMB",
                "description": "Deploy WinPEAS via SMB share upload - Windows targets",
                "handler": self.deploy_winpeas_smb
            },
            {
                "name": "Deploy WinPEAS via PSExec",
                "description": "Deploy WinPEAS using Impacket PSExec - Windows targets",
                "handler": self.deploy_winpeas_psexec
            },
            {
                "name": "Deploy LinPEAS via SSH",
                "description": "Deploy LinPEAS enumeration script via SSH - Linux/Unix targets",
                "handler": self.deploy_linpeas_ssh
            },
            {
                "name": "Deploy LinPEAS via NXC",
                "description": "Deploy LinPEAS using NetExec SSH module - Linux/Unix targets",
                "handler": self.deploy_linpeas_nxc
            },
            {
                "name": "Deploy Custom Script via NXC",
                "description": "Deploy custom script using NetExec (auto-detects OS)",
                "handler": self.deploy_script_nxc
            },
            {
                "name": "Deploy Custom Script via SSH",
                "description": "Deploy custom script via SSH - Linux/Unix targets",
                "handler": self.deploy_script_ssh
            },
            {
                "name": "Deploy Custom Script via SMB",
                "description": "Deploy custom script via SMB - Windows targets",
                "handler": self.deploy_script_smb
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
                "description": "Path to script file to deploy",
                "default": None
            },
            "REMOTE_PATH": {
                "value": None,
                "required": False,
                "description": "Remote path where script will be deployed",
                "default": None
            },
            "EXECUTE": {
                "value": True,
                "required": False,
                "description": "Execute the script after deployment",
                "default": True
            },
            "EXEC_ARGS": {
                "value": "",
                "required": False,
                "description": "Arguments to pass when executing the script",
                "default": ""
            },
            "TARGET_OS": {
                "value": "windows",
                "required": False,
                "description": "Target OS (windows, linux)",
                "default": "windows"
            },
            "SCRIPT_TYPE": {
                "value": "custom",
                "required": False,
                "description": "Type of script (winpeas, linpeas, custom)",
                "default": "custom"
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

            # Execute via WMI
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
