"""Web adapter observations and a deliberately passive HTML form importer."""

from html.parser import HTMLParser
import json
import re
import shlex
from urllib.parse import urljoin, urlsplit

from purplesploit.core.module import ExternalToolModule


def observation(kind, url, **attributes):
    """Return an Observation-compatible record without inventing provenance."""
    parts = urlsplit(str(url))
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = None
    return {
        "kind": kind, "target": str(url), "port": port,
        "protocol": "tcp", "service": parts.scheme or "http",
        "attributes": {
            "url": str(url), "scheme": parts.scheme, "host": parts.hostname,
            "port": port, **attributes,
        },
    }


def json_records(output):
    """Accept JSON arrays/objects and JSONL; retain malformed-line diagnostics."""
    errors = []
    try:
        data = json.loads(output)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = []
        for number, line in enumerate(output.splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                records.extend(item if isinstance(item, list) else [item])
            except json.JSONDecodeError as exc:
                errors.append({"line": number, "error": exc.msg})
    return [item for item in records if isinstance(item, dict)], errors


class WebToolModule(ExternalToolModule):
    """Parse real process output consistently for direct and catalog operations."""

    emits = ["http_endpoint"]
    supported_tool_versions = ["installed CLI; see operation output for diagnostics"]

    def get_operations(self):
        return [{"name": "Run", "handler": "run", "description": self.description,
                 "interactive": False, "emits": list(self.emits)}]

    def get_operation_manifest(self):
        from purplesploit.core.execution import normalize_operation
        operations = self.get_operations() or [{
            "name": "Run", "handler": "run", "description": self.description,
        }]
        manifests = []
        for operation in operations:
            item = dict(operation)
            item.setdefault("interactive", False)
            item.setdefault("emits", list(self.emits))
            item.setdefault("supported_tool_versions", list(self.supported_tool_versions))
            item.setdefault("background", "background" in str(item.get("handler", "")))
            manifests.append(normalize_operation(item, self))
        return manifests

    def execute_command(self, command, timeout=None, background=False):
        argv = shlex.split(command) if isinstance(command, str) else list(command)
        if self.tool_path and argv:
            argv[0] = str(self.tool_path)
        result = super().execute_command(argv, timeout=timeout, background=background)
        if not result.get("background") and hasattr(self, "parse_output"):
            parsed = self.parse_output(result.get("stdout", ""))
            result["parsed"] = parsed
            result["observations"] = parsed.get("observations", [])
        return result


class FormParser(HTMLParser):
    """Extract recorded forms, named controls, method and action without fetching."""

    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url = url
        self.base_url = url
        self.forms = []
        self.current = None
        self.controls = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and attrs.get("href"):
            self.base_url = urljoin(self.url, attrs["href"])
        if tag == "form":
            self.current = {
                "id": attrs.get("id") or f"form-{len(self.forms) + 1}",
                "action": urljoin(self.base_url, attrs.get("action") or self.url),
                "method": attrs.get("method", "get").upper(),
                "enctype": attrs.get("enctype", "application/x-www-form-urlencoded"),
                "parameters": [], "source_url": self.url,
            }
            self.forms.append(self.current)
        elif tag in {"input", "select", "textarea", "button"} and attrs.get("name"):
            control = {"name": attrs["name"], "type": attrs.get("type", tag),
                       "value": attrs.get("value", ""), "required": "required" in attrs,
                       "disabled": "disabled" in attrs}
            self.controls.append((attrs.get("form"), self.current, control))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def parse_html_forms(html, url):
    """Import recorded HTML for workflow forms_found and parameter test plans."""
    parser = FormParser(url)
    parser.feed(html)
    parser.close()
    by_id = {form["id"]: form for form in parser.forms}
    for form_id, parent, control in parser.controls:
        form = by_id.get(form_id) if form_id else parent
        if form is not None:
            form["parameters"].append(control)
    observations = []
    for form in parser.forms:
        observations.append(observation("form", form["action"], **form))
        for parameter in form["parameters"]:
            observations.append(observation("parameter", form["action"], **parameter,
                                            method=form["method"], form_id=form["id"],
                                            location="query" if form["method"] == "GET" else "body",
                                            source_url=url))
    return {"forms": parser.forms, "forms_found": bool(parser.forms),
            "observations": observations}


def strip_ansi(output):
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
