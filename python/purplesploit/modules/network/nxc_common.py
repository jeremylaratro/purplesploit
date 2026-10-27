"""Shared NetExec argv construction and conservative text observations.

NetExec has no stable JSON output across supported releases. Only recognizable
records are interpreted here; the original subprocess result is always retained.
"""

import re
import shlex
from typing import Any


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_LINE = re.compile(r"^\s*(?P<label>[\w-]+)\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+(?P<body>.*)$")
_ACCOUNT = re.compile(r"(?:(?P<domain>[^\s\\:]+)\\)?(?P<username>[^\s\\:]+):")
_PROTOCOLS = {"smb", "ldap", "ldaps", "winrm", "rdp", "ssh", "mssql"}


def _value(value: str) -> Any:
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.isdecimal():
        return int(value)
    return value


def _policy_value(name: str, value: str) -> Any:
    normalized = value.strip().lower()
    if name == "channel_binding":
        return re.sub(r"[ -]+", "_", normalized)
    if normalized in {"enforced", "enabled", "required"}:
        return True
    if normalized in {"none", "disabled", "not enforced", "not required"}:
        return False
    if normalized == "unknown":
        return None
    return _value(value)


def parse_nxc_output(output: str, protocol: str, arguments=(), username=None) -> list[dict[str, Any]]:
    """Parse supported NetExec/CME line formats without inferring from exit status.

    Host is the observation target; named AD objects live in attributes. An auth
    result describes the attempted identity and status, never a discovered secret.
    """
    observations = []
    seen = set()
    arguments = list(arguments)
    mode = None
    for flag, section in (("--users", "users"), ("--local-users", "users"),
                          ("--groups", "groups"), ("--shares", "shares"),
                          ("--sessions", "sessions"), ("--loggedon-users", "sessions"),
                          ("--pass-pol", "policy"), ("--rid-brute", "rid")):
        if flag in arguments:
            mode = section
            break
    module = arguments[arguments.index("-M") + 1].lower() if "-M" in arguments else ""
    modes = {"machines": "computers", "enum_trusts": "trusts", "adcs": "adcs",
             "get-desc-users": "users", "user-desc": "users"}
    mode = modes.get(module, mode)
    if "--computers" in arguments:
        mode = "computers"
    if "--query" in arguments:
        query = arguments[arguments.index("--query") + 1].lower()
        if "objectclass=trusteddomain" in query:
            mode = "trusts"
        elif "objectclass=computer" in query:
            mode = "computers"
    if "-x" in arguments:
        command = arguments[arguments.index("-x") + 1]
        if command == "cat /etc/passwd":
            mode = "passwd"
        elif command == "net user":
            mode = "net_users"
    sections = {}
    session_types = {}
    trust_records = {}
    query_objects = {}
    hostnames = {}

    def add(kind, host, port, service, **attributes):
        if kind not in {"host", "service"}:
            add("host", host, port, service, hostname=hostnames.get((host, port), ""))
            add("service", host, port, service, state="open")
        item = {"kind": kind, "target": host, "port": port,
                "protocol": "tcp", "service": service, "attributes": attributes}
        key = repr(item)
        if key not in seen:
            seen.add(key)
            observations.append(item)

    for raw_line in output.splitlines():
        line = _ANSI.sub("", raw_line)
        match = _LINE.match(line)
        if not match:
            continue
        label, host, port, hostname, body = match.group("label", "host", "port", "name", "body")
        port = int(port)
        service = label.lower() if label.lower() in _PROTOCOLS else protocol
        if not 0 < port <= 65535:
            continue
        hostnames[(host, port)] = hostname
        marker = body[:3] if body[:3] in {"[+]", "[-]", "[*]", "[!]"} else ""
        text = body[3:].strip() if marker else body.strip()
        metadata = dict(re.findall(r"\(([\w -]+):\s*([^)]*)\)", text))
        for key, value in metadata.items():
            normalized = key.lower().replace(" ", "_")
            if normalized in {"signing", "nla", "smbv1", "smbv2", "smbv3", "channel_binding"}:
                add("policy", host, port, service, name=normalized, value=_policy_value(normalized, value))
            elif normalized == "domain" and value:
                add("domain", host, port, service, name=value)
        if marker == "[*]" and (metadata or text.startswith("SSH-")):
            add("host", host, port, service, hostname=hostname)
            add("service", host, port, service, state="open")
            details = {key.lower().replace(" ", "_"): _value(value) for key, value in metadata.items()}
            banner = text.split(" (", 1)[0].strip()
            add("service", host, port, service, banner=banner, **details)

        # Authentication markers also prefix unrelated enumeration messages. A
        # credential-shaped account prefix is required before treating one as auth.
        account = _ACCOUNT.match(text) if marker in {"[+]", "[-]"} else None
        if account and (account["domain"] or account["username"] == username):
            status = re.search(r"\b(?:STATUS_[A-Z_]+|KDC_ERR_[A-Z_]+|[A-Z_]*LOGON_FAILURE)\b", text)
            add("identity", host, port, service, username=account["username"],
                domain=account["domain"] or "", authenticated=marker == "[+]",
                admin="pwn3d!" in text.lower(), status=status[0] if status else
                ("success" if marker == "[+]" else "failure"))
            continue

        lower = text.lower()
        current = sections.get((host, port), mode)
        headings = (("shares", ("enumerated shares",)),
                    ("users", ("enumerated users", "username", "user name")),
                    ("groups", ("enumerated groups", "enumerated domain group", "groupname", "group name", "-group-")),
                    ("sessions", ("enumerated sessions", "enumerated logged_on", "loggedon users", "logged on users")),
                    ("policy", ("password policy for", "dumping password policy")))
        for section, needles in headings:
            if any(lower.startswith(needle) for needle in needles):
                sections[(host, port)] = section
                current = section
                if section == "sessions":
                    session_types[(host, port)] = "logged" in lower
        if re.match(r"Share\s+Permissions\b", text, re.I):
            sections[(host, port)] = current = "shares"
        if not text or re.fullmatch(r"[-=\s]+", text):
            continue

        signing = re.search(r"(?:ldap\s+)?signing\s*(?::|is|=)?\s*(?:not\s+)?(?:required|enforced|enabled|disabled|true|false)", text, re.I)
        if signing and ("sign" in module or "ldap-checker" == module):
            value = not bool(re.search(r"not\s+(?:required|enforced)|disabled|false", signing[0], re.I))
            add("policy", host, port, service, name="signing", value=value)

        share = re.match(r"(\S+)\s+((?:READ|WRITE)(?:\s*\([^)]*\))?(?:\s*,\s*(?:READ|WRITE)(?:\s*\([^)]*\))?)*|NO ACCESS)(?=\s|$)\s*(.*)", text, re.I)
        if current == "shares" and share:
            permissions = [part.strip().upper() for part in share[2].split(",")]
            add("share", host, port, service, name=share[1], permissions=permissions,
                remark=share[3], readable="READ" in permissions,
                writable=any(permission.startswith("WRITE") for permission in permissions))
        elif current == "shares" and not marker:
            # NetExec prints inaccessible shares with a blank permissions column.
            columns = re.split(r"\s{2,}", text)
            if len(columns) >= 2 and not lower.startswith("share"):
                add("share", host, port, service, name=columns[0], permissions=[],
                    remark=" ".join(columns[1:]), readable=False, writable=False)

        rid = re.match(r"(\d+):\s+([^\\\s]+)\\(.+?)\s+\((SidType\w+)\)", text)
        if rid:
            kind = {"SidTypeUser": "user", "SidTypeGroup": "group", "SidTypeAlias": "group"}.get(rid[4])
            if kind:
                add(kind, host, port, service, name=rid[3], domain=rid[2], rid=int(rid[1]))
        elif current == "users":
            user = re.match(r"(?:(\S+)\\)?(\S+)\s+(?:\d{4}-\d{2}-\d{2}|<never>|\d+|badpwdcount:)", text, re.I)
            explicit = re.match(r"(?:User(?:name)?):\s*(?:(\S+)\\)?(\S+)", text, re.I)
            user = explicit or user
            if user and user[2].lower() not in {"username", "name", "last"}:
                add("user", host, port, service, name=user[2], domain=user[1] or "")
            elif module in {"get-desc-users", "user-desc"}:
                description = re.match(r"(\S+)\s+(?:description:\s*)?(.+)", text)
                if description and not marker:
                    add("user", host, port, service, name=description[1], description=description[2])
        elif current == "groups":
            group = re.match(r"(.+?)\s+(?:membercount:\s*)?(\d+)(?:\s+(.*))?$", text, re.I)
            if group and not lower.startswith(("group", "enumerat")):
                attributes = {"name": group[1].strip()}
                attributes["member_count"] = int(group[2])
                if group[3]:
                    attributes["description"] = group[3]
                add("group", host, port, service, **attributes)
        elif current == "sessions":
            logged_on = session_types.get((host, port), "--loggedon-users" in arguments)
            session = re.search(r"(?:User(?:name)?):\s*(\S+).*?(?:IP|Source|Client):\s*(\S+)", text, re.I)
            if not session:
                session = re.search(r"(?:IP|Source|Client):\s*(\S+).*?User(?:name)?:\s*(\S+)", text, re.I)
                if session:
                    add("session", host, port, service, username=session[2], client=session[1],
                        logged_on=logged_on)
            else:
                add("session", host, port, service, username=session[1], client=session[2],
                    logged_on=logged_on)
            if not session:
                legacy_session = re.match(r"(\\\\\S+|\d[\d.:]+)\s+User:\s*(\S+)", text, re.I)
                if legacy_session:
                    add("session", host, port, service, username=legacy_session[2], client=legacy_session[1].lstrip("\\"),
                        logged_on=False)
                account = re.match(r"([^\s\\]+)\\([^\s]+)(?:\s+(.+))?$", text)
                if account:
                    logon_server = re.search(r"logon_server:\s*(\S+)", account[3] or "", re.I)
                    add("session", host, port, service, domain=account[1], username=account[2],
                        detail=account[3] or "", logged_on=logged_on,
                        logon_server=logon_server[1] if logon_server else "")
        elif current == "policy":
            policy = re.match(r"([\w][\w ()/-]+?):\s*(.+)$", text)
            if policy and any(word in policy[1].lower() for word in ("password", "lockout", "age", "history", "threshold")):
                name = re.sub(r"\W+", "_", policy[1].strip().lower()).strip("_")
                add("policy", host, port, service, name=name, value=_value(policy[2]))
        elif current == "computers":
            computer = re.search(r"(?:sAMAccountName|Computer|Name)(?::\s*|\s+)(\S+)", text, re.I)
            if not computer:
                computer = re.match(r"(\S+\$)(?:\s|$)", text)
            if computer:
                add("computer", host, port, service, name=computer[1])
        elif current == "trusts":
            response = re.match(r"Response for object:\s*(.+)$", text, re.I)
            if response:
                query_objects[(host, port)] = response[1]
            attribute = re.match(r"(trustPartner|trustDirection|trustAttributes)(?::\s*|\s+)(.+)$", text, re.I)
            if attribute:
                record_key = (host, port, service, query_objects.get((host, port), ""))
                trust_records.setdefault(record_key, {})[attribute[1].lower()] = _value(attribute[2])
            trust = re.search(r"(?:Trusted? Domain|Domain(?:Name)?):\s*(\S+)", text, re.I)
            if trust:
                add("domain", host, port, service, name=trust[1], relationship="trust", detail=text)
            else:
                trust = re.match(r"(\S+)\s+->\s+(Inbound|Outbound|Bidirectional)\s+->\s+(.+)", text, re.I)
                if trust:
                    add("domain", host, port, service, name=trust[1], relationship="trust",
                        direction=trust[2].lower(), trust_attributes=[part.strip() for part in trust[3].split(",")])
        elif current == "adcs":
            adcs = re.search(r"(?:Found\s+)?(PKI Enrollment Server|PKI Enrollment WebService|Certificate Template|CA|CN|Certificate Authority):\s*(.+)", text, re.I)
            if adcs:
                add("resource", host, port, service, type="adcs", name=adcs[2].strip(),
                    field=adcs[1].lower().replace(" ", "_"))
        elif current == "passwd":
            user = re.match(r"([^:]+):[^:]*:(\d+):(\d+):([^:]*):([^:]*):([^:]*)$", text)
            if user:
                add("user", host, port, service, name=user[1], uid=int(user[2]),
                    gid=int(user[3]), home=user[5], shell=user[6])
        elif current == "net_users" and not marker and not lower.startswith(("user accounts", "the command", "---")):
            for name in text.split():
                add("user", host, port, service, name=name)
    for (host, port, service, distinguished_name), attributes in trust_records.items():
        if attributes.get("trustpartner"):
            direction = attributes.get("trustdirection")
            add("domain", host, port, service, name=attributes["trustpartner"], relationship="trust",
                direction={1: "inbound", 2: "outbound", 3: "bidirectional"}.get(direction, direction),
                trust_attributes=attributes.get("trustattributes"), distinguished_name=distinguished_name)
    return observations


class NXCModuleMixin:
    """Shared subprocess boundary; legacy fixed argument fragments remain accepted."""

    def _auth_argv(self):
        username = self.get_option("USERNAME")
        if not username:
            return []
        hash_value = self.get_option("HASH")
        return ["-u", str(username), "-H" if hash_value else "-p",
                str(hash_value if hash_value else self.get_option("PASSWORD") or "")]

    def _run_nxc(self, protocol, extra_args=(), timeout=300, authenticate=True):
        arguments = shlex.split(extra_args) if isinstance(extra_args, str) else list(extra_args)
        target = self.get_option("RHOST")
        if not target:
            return {"success": False, "error": "RHOST is required", "observations": []}
        argv = ["nxc", protocol, str(target)]
        if authenticate:
            argv.extend(self._auth_argv())
            domain = self.get_option("DOMAIN")
            if domain and domain != "WORKGROUP" and "-d" not in arguments:
                argv.extend(["-d", str(domain)])
            auth_type = self.get_option("AUTH_TYPE") or "domain"
            flag = {"local": "--local-auth", "kerberos": "--kerberos", "windows": "--windows-auth"}.get(auth_type)
            if flag and flag not in arguments:
                argv.append(flag)
        argv.extend(arguments)
        result = self.execute_command(argv, timeout=timeout)
        # Preserve stdout, stderr, output, status, execution records and unknown
        # tool fields. Only add independently parsed observations.
        output = result.get("stdout") or result.get("output") or ""
        observations = parse_nxc_output(str(output), protocol, arguments, username=self.get_option("USERNAME"))
        result["observations"] = list(result.get("observations") or []) + observations
        return result

    def _operation_manifest(self, operations, interactive=(), emits=None):
        emits = emits or {}
        for operation in operations:
            handler = operation["handler"]
            optional = [key for key in ("USERNAME", "PASSWORD", "HASH", "DOMAIN", "AUTH_TYPE", "SWITCHES")
                        if key in self.options]
            if handler == "op_spider_configured":
                optional.extend(["SPIDER_SHARE", "SPIDER_PATTERN"])
            if handler in {"op_nla", "op_ms17_010", "op_smbghost"}:
                optional = [key for key in ("SWITCHES",) if key in self.options]
            operation.update(id=handler.removeprefix("op_").replace("_", "-"),
                             interactive=handler in interactive, background=False,
                             requires=["RHOST"], optional=optional,
                             emits=list(dict.fromkeys(["host", "service", "identity", "domain", "policy", *emits.get(handler, [])])), tool="nxc")
            if handler == "op_pass_the_hash_configured":
                operation["requires"] = ["RHOST", "USERNAME", "HASH"]
                operation["optional"] = [key for key in optional if key not in {"USERNAME", "HASH", "PASSWORD"}]
            if handler == "op_nla":
                operation["emits"] = ["host", "service", "domain", "policy"]
        return operations
