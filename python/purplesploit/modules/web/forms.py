"""Import form observations from recorded HTML without issuing requests."""

from pathlib import Path

from purplesploit.core.module import BaseModule
from purplesploit.web_observations import parse_html_forms


class HTMLFormsModule(BaseModule):
    name = property(lambda self: "Recorded HTML Forms")
    description = property(lambda self: "Import forms and named parameters from recorded HTML")
    author = property(lambda self: "PurpleSploit Team")
    category = property(lambda self: "web")

    def _init_options(self):
        super()._init_options()
        for name in ("URL", "HTML_FILE"):
            self.options[name] = {"value": None, "default": None, "required": True,
                                  "description": "Source URL" if name == "URL" else "Recorded HTML file"}

    def get_operations(self):
        return [{"name": "Import Forms", "handler": "op_import_forms", "interactive": False,
                 "requires": ["URL", "HTML_FILE"], "emits": ["form", "parameter"],
                 "description": self.description, "supported_tool_versions": ["Python 3 html.parser"]}]

    def op_import_forms(self):
        url, path = self.get_option("URL"), self.get_option("HTML_FILE")
        if not url or not path:
            return {"success": False, "error": "URL and HTML_FILE required"}
        try:
            parsed = parse_html_forms(Path(path).read_text(encoding="utf-8", errors="replace"), url)
        except OSError as exc:
            return {"success": False, "error": str(exc)}
        return {"success": True, "parsed": parsed, "observations": parsed["observations"],
                "artifacts": [str(path)], "forms": parsed["forms"], "forms_found": parsed["forms_found"]}

    def run(self):
        return self.op_import_forms()
