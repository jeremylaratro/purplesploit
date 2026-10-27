"""Secret-safe, host-key-verifying SSH/SCP execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
from typing import Callable


@dataclass(frozen=True)
class RemoteResult:
    success: bool
    argv: list[str]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    error: str | None = None

    def to_dict(self):
        return dict(self.__dict__)


class SecureSSHRunner:
    """OpenSSH runner that requires verified host keys and non-argv auth."""

    def __init__(
        self,
        host: str,
        username: str,
        *,
        known_hosts: str | Path,
        identity_file: str | Path | None = None,
        port: int = 22,
        executor: Callable | None = None,
    ):
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host or ""):
            raise ValueError("Invalid SSH host")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", username or ""):
            raise ValueError("Invalid SSH username")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid SSH port")
        self.known_hosts = Path(known_hosts).expanduser().resolve()
        if not self.known_hosts.is_file():
            raise FileNotFoundError("A populated known_hosts file is required")
        if self.known_hosts.stat().st_mode & 0o022:
            raise PermissionError("known_hosts must not be group/world writable")
        self.identity_file = Path(identity_file).expanduser().resolve() if identity_file else None
        if self.identity_file is not None:
            if not self.identity_file.is_file():
                raise FileNotFoundError("SSH identity file not found")
            if self.identity_file.stat().st_mode & 0o077:
                raise PermissionError("SSH identity file must have mode 0600 or stricter")
        self.host = host
        self.username = username
        self.port = port
        self.executor = executor or subprocess.run

    def _options(self) -> list[str]:
        options = [
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-p",
            str(self.port),
        ]
        if self.identity_file is not None:
            options.extend(["-i", str(self.identity_file)])
        return options

    @staticmethod
    def _remote_path(value: str) -> str:
        if (
            not isinstance(value, str)
            or not value.startswith("/")
            or any(character in value for character in "\r\n\0")
        ):
            raise ValueError("Remote paths must be absolute and contain no control characters")
        normalized = str(PurePosixPath(value))
        if ".." in PurePosixPath(normalized).parts:
            raise ValueError("Remote path traversal is not allowed")
        return normalized

    def _run(self, argv: list[str], timeout: float) -> RemoteResult:
        try:
            completed = self.executor(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return RemoteResult(
                completed.returncode == 0,
                list(argv),
                completed.returncode,
                completed.stdout or "",
                completed.stderr or "",
                None if completed.returncode == 0 else f"OpenSSH exited {completed.returncode}",
            )
        except subprocess.TimeoutExpired as exc:
            return RemoteResult(
                False, list(argv), -1, exc.stdout or "", exc.stderr or "", "OpenSSH timed out"
            )
        except OSError as exc:
            return RemoteResult(False, list(argv), -1, error=str(exc))

    def upload(self, local_path: str | Path, remote_path: str, *, timeout=60) -> RemoteResult:
        local = Path(local_path).expanduser().resolve()
        if not local.is_file():
            raise FileNotFoundError(local)
        remote = self._remote_path(remote_path)
        options = self._options()
        # scp spells the port flag as -P.
        index = options.index("-p")
        options[index] = "-P"
        argv = ["scp", *options, "--", str(local), f"{self.username}@{self.host}:{remote}"]
        return self._run(argv, timeout)

    def execute(self, arguments: list[str], *, timeout=60, background=False) -> RemoteResult:
        if (
            not isinstance(arguments, list)
            or not arguments
            or any(not isinstance(item, str) or "\0" in item for item in arguments)
        ):
            raise ValueError("Remote commands require a nonempty argument vector")
        command = shlex.join(arguments)
        if background:
            command = f"nohup {command} </dev/null >/dev/null 2>&1 &"
        argv = [
            "ssh",
            *self._options(),
            "--",
            f"{self.username}@{self.host}",
            "sh",
            "-c",
            shlex.quote(command),
        ]
        return self._run(argv, timeout)

    def deploy(
        self,
        local_path: str | Path,
        remote_path: str,
        *,
        arguments: list[str] | None = None,
        execute=True,
        background=False,
        cleanup_on_failure=True,
        timeout=120,
    ) -> dict:
        remote = self._remote_path(remote_path)
        uploaded = self.upload(local_path, remote, timeout=min(timeout, 60))
        if not uploaded.success:
            return {"success": False, "stage": "upload", "upload": uploaded.to_dict()}
        execution = None
        if execute:
            chmod = self.execute(["chmod", "u+x", remote], timeout=min(timeout, 60))
            if not chmod.success:
                execution = chmod
            else:
                execution = self.execute(
                    [remote, *(arguments or [])], timeout=timeout, background=background
                )
            if not execution.success and cleanup_on_failure:
                cleanup = self.execute(["rm", "-f", "--", remote], timeout=30)
            else:
                cleanup = None
        else:
            cleanup = None
        success = uploaded.success and (execution is None or execution.success)
        return {
            "success": success,
            "stage": "complete" if success else "execute",
            "remote_path": remote,
            "upload": uploaded.to_dict(),
            "execution": execution.to_dict() if execution else None,
            "cleanup": cleanup.to_dict() if cleanup else None,
            "output": execution.stdout if execution else "",
            "error": None if success else (execution.error if execution else uploaded.error),
        }
