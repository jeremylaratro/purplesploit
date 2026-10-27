"""Secret references, encrypted local storage, and recursive redaction."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from threading import RLock
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken


SECRET_SCHEME = "secret://"
SECRET_KEY_PATTERN = re.compile(
    r"(?:password|passwd|passphrase|token|secret|api[_-]?key|private[_-]?key|"
    r"client[_-]?secret|webhook(?:_url)?|authorization|cookie|hash)$",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_secret_key(name: Any) -> bool:
    return isinstance(name, str) and bool(SECRET_KEY_PATTERN.search(name))


@dataclass(frozen=True)
class SecretReference:
    id: str
    provider: str = "local"
    label: str = ""

    @property
    def uri(self) -> str:
        return f"{SECRET_SCHEME}{self.provider}/{self.id}"

    @classmethod
    def parse(cls, value: str) -> "SecretReference":
        if not isinstance(value, str) or not value.startswith(SECRET_SCHEME):
            raise ValueError("Not a secret reference")
        path = value[len(SECRET_SCHEME) :].split("/", 1)
        if len(path) != 2 or not all(path):
            raise ValueError("Malformed secret reference")
        return cls(id=path[1], provider=path[0])


class InMemorySecretProvider:
    name = "memory"

    def __init__(self):
        self._values: dict[str, dict[str, Any]] = {}

    def set(self, value: str, *, label: str = "", secret_id: str | None = None) -> SecretReference:
        if not isinstance(value, str) or not value:
            raise ValueError("Secret values must be nonempty strings")
        secret_id = secret_id or str(uuid4())
        self._values[secret_id] = {"value": value, "label": label, "updated_at": _now()}
        return SecretReference(secret_id, self.name, label)

    def get(self, reference: SecretReference | str) -> str:
        reference = SecretReference.parse(reference) if isinstance(reference, str) else reference
        if reference.provider != self.name:
            raise ValueError("Secret reference belongs to another provider")
        try:
            return self._values[reference.id]["value"]
        except KeyError as exc:
            raise KeyError(reference.uri) from exc

    def delete(self, reference: SecretReference | str) -> bool:
        reference = SecretReference.parse(reference) if isinstance(reference, str) else reference
        return self._values.pop(reference.id, None) is not None

    def list(self) -> list[dict[str, str]]:
        return [
            {
                "reference": SecretReference(key, self.name, value["label"]).uri,
                "label": value["label"],
                "updated_at": value["updated_at"],
            }
            for key, value in sorted(self._values.items())
        ]


class EncryptedFileSecretProvider:
    """Fernet-encrypted local vault with a separately permissioned key file."""

    name = "local"

    def __init__(self, path: str | Path, *, key_path: str | Path | None = None):
        self.path = Path(path)
        self.key_path = Path(key_path) if key_path else self.path.with_suffix(".key")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        self._lock = RLock()
        self._key = self._load_key()
        self._fernet = Fernet(self._key)
        if not self.path.exists():
            self._write({"version": 1, "secrets": {}})
        else:
            self._read()

    def _load_key(self) -> bytes:
        environment = os.getenv("PURPLESPLOIT_SECRET_KEY")
        if environment:
            key = environment.encode("ascii")
            Fernet(key)
            return key
        if self.key_path.exists():
            key = self.key_path.read_bytes().strip()
            try:
                Fernet(key)
            except (ValueError, InvalidToken) as exc:
                raise ValueError("Invalid local secret key") from exc
            if self.key_path.stat().st_mode & 0o077:
                raise PermissionError("Secret key file must not be group/world accessible")
            return key
        key = Fernet.generate_key()
        descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return key

    def _read(self) -> dict[str, Any]:
        with self._lock:
            try:
                plaintext = self._fernet.decrypt(self.path.read_bytes())
                value = json.loads(plaintext)
            except (InvalidToken, json.JSONDecodeError) as exc:
                raise ValueError("Secret store cannot be decrypted or is malformed") from exc
            if value.get("version") != 1 or not isinstance(value.get("secrets"), dict):
                raise ValueError("Unsupported secret store format")
            return value

    def _write(self, value: dict[str, Any]) -> None:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = self._fernet.encrypt(encoded)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as stream:
                temporary = Path(stream.name)
                os.chmod(temporary, 0o600)
                stream.write(ciphertext)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def set(self, value: str, *, label: str = "", secret_id: str | None = None) -> SecretReference:
        if not isinstance(value, str) or not value:
            raise ValueError("Secret values must be nonempty strings")
        secret_id = secret_id or str(uuid4())
        with self._lock:
            document = self._read()
            created = document["secrets"].get(secret_id, {}).get("created_at", _now())
            document["secrets"][secret_id] = {
                "value": value,
                "label": label,
                "created_at": created,
                "updated_at": _now(),
            }
            self._write(document)
        return SecretReference(secret_id, self.name, label)

    def get(self, reference: SecretReference | str) -> str:
        reference = SecretReference.parse(reference) if isinstance(reference, str) else reference
        if reference.provider != self.name:
            raise ValueError("Secret reference belongs to another provider")
        try:
            return self._read()["secrets"][reference.id]["value"]
        except KeyError as exc:
            raise KeyError(reference.uri) from exc

    def delete(self, reference: SecretReference | str) -> bool:
        reference = SecretReference.parse(reference) if isinstance(reference, str) else reference
        with self._lock:
            document = self._read()
            if document["secrets"].pop(reference.id, None) is None:
                return False
            self._write(document)
            return True

    def list(self) -> list[dict[str, str]]:
        return [
            {
                "reference": SecretReference(key, self.name, value["label"]).uri,
                "label": value["label"],
                "created_at": value["created_at"],
                "updated_at": value["updated_at"],
            }
            for key, value in sorted(self._read()["secrets"].items())
        ]

    def backup(self, directory: str | Path) -> dict[str, Any]:
        """Create a complete encrypted recovery set; protect it as sensitive."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        vault = directory / "secrets.vault"
        key = directory / "secrets.key"
        for source, target in ((self.path, vault), (self.key_path, key)):
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)
        return {
            "vault": vault.name,
            "vault_sha256": hashlib.sha256(vault.read_bytes()).hexdigest(),
            "key": key.name,
            "key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
        }


class SecretRedactor:
    """Redact secret-shaped fields, references, and registered plaintext values."""

    def __init__(self, provider=None, replacement="[REDACTED]"):
        self.provider = provider
        self.replacement = replacement

    def known_values(self) -> set[str]:
        if self.provider is None:
            return set()
        values = set()
        for item in self.provider.list():
            try:
                value = self.provider.get(item["reference"])
            except (KeyError, ValueError):
                continue
            if len(value) >= 4:
                values.add(value)
        return values

    def redact_text(self, value: str) -> str:
        result = value
        result = re.sub(r"secret://[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.replacement, result)
        result = re.sub(
            r"(?i)(password|passwd|passphrase|token|secret|api[_-]?key|authorization)"
            r"(\s*[:=]\s*)([^\s,;]+)",
            lambda match: match.group(1) + match.group(2) + self.replacement,
            result,
        )
        for secret in sorted(self.known_values(), key=len, reverse=True):
            result = result.replace(secret, self.replacement)
        return result

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: self.replacement
                if is_secret_key(key) and item not in (None, "")
                else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)
        if isinstance(value, str):
            return self.redact_text(value)
        return deepcopy(value)


def externalize_secrets(value: dict[str, Any], provider, *, namespace: str) -> dict[str, Any]:
    """Replace sensitive leaf fields with references before normal persistence."""
    result = deepcopy(value)

    def walk(item, path):
        if isinstance(item, dict):
            for key in list(item):
                child_path = [*path, str(key)]
                if is_secret_key(key) and isinstance(item[key], str) and item[key]:
                    if item[key].startswith(SECRET_SCHEME):
                        SecretReference.parse(item[key])
                    else:
                        stable = hashlib.sha256(
                            (namespace + ":" + "/".join(child_path)).encode()
                        ).hexdigest()[:32]
                        item[key] = provider.set(
                            item[key], label=f"{namespace}:{'/'.join(child_path)}", secret_id=stable
                        ).uri
                else:
                    walk(item[key], child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, [*path, str(index)])

    walk(result, [])
    return result


def resolve_secrets(value: Any, provider) -> Any:
    if isinstance(value, dict):
        return {key: resolve_secrets(item, provider) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_secrets(item, provider) for item in value]
    if isinstance(value, str) and value.startswith(SECRET_SCHEME):
        return provider.get(value)
    return deepcopy(value)
