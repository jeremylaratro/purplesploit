"""Minimal local plugin: no external tools or network access required."""

from purplesploit.core.module import BaseModule


class HelloModule(BaseModule):
    name = "Hello demo"
    description = "Demonstrate a plugin operation through normal framework execution."
    author = "PurpleSploit"
    category = "utility"

    def get_operations(self):
        return [{"id": "greet", "name": "Greet", "handler": "greet"}]

    def greet(self):
        return {"success": True, "message": "Hello from hello-demo", "observations": []}

    def run(self):
        return self.greet()
