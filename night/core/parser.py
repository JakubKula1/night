import crossplane
import json
from rich import print as rprint


class NginxParser:
    def __init__(self, config_path):
        self.config_path = config_path

    def parse(self):
        """
        Parses the Nginx configuration file
        :return: a structured dictionary (Abstract Syntax Tree)
        """
        payload = crossplane.parse(self.config_path, combine=False)
        if payload['status'] != 'ok':
            raise Exception(f"Failed to parse Nginx config: {payload['errors']}")

        # Debug
        # rprint(json.dumps(payload, indent=4))
        return payload