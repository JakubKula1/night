import crossplane
from rich.console import Console
import json
from rich import print as rprint


console = Console()


class NginxParser:
    def __init__(self, config_path):
        self.config_path = config_path

    def parse(self):
        """
        Parses the Nginx configuration file
        :return: a structured dictionary (Abstract Syntax Tree)
        """
        payload = crossplane.parse(self.config_path, combine=False)
        if payload.get('status') != 'ok' or payload.get('errors'):

            console.print(f"\n[yellow][!] Warning: Crossplane flagged syntax/context warnings in '{self.config_path}'.[/yellow]")
            if self.config_path != "/etc/nginx/nginx.conf":
                console.print("[dim]    This usually happens with uncommon file paths (test files) - NIGHT will proceed to scan the AST anyway.[/dim]")
            console.print("[dim]    Crossplane warnings:[/dim]")
            for err in payload.get('errors', []):
                console.print(f"[dim]    - {err.get('error')}[/dim]")
            console.print()

        # Debug
        # rprint(json.dumps(payload, indent=4))
        return payload