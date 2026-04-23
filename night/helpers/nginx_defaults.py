"""
    Loads nginx_defaults.json and provides:
        - A nested dit (by module): nginx_defaults_nested
        - A flat dict ("directive_name": "default_value"): nginx_defaults_flat
"""

import json
import os.path
from pathlib import Path

def load_nginx_defaults(json_path: str = "./night/helpers/nginx_defaults.json") -> dict:
    """Load the raw JSON (nested by module) into a Python dict."""
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Could not find {json_path}")
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def flatten_defaults(nested: dict) -> dict:
    flat: dict = {}

    for module, directives in nested.items():
        if module == "_metadata":
            continue
        if not isinstance(directives, dict):
            continue
        # Skip info-only sections
        if list(directives.keys()) == ["_note"]:
            continue

        for directive, default in directives.items():
            if directive == "_note":
                continue
            if default is None:  # explicitly null → no meaningful default
                continue

            if directive in flat:
                existing = flat[directive]
                # Collect duplicates into a list
                if isinstance(existing, list):
                    if default not in existing:
                        existing.append(default)
                else:
                    if existing != default:
                        flat[directive] = [existing, default]
            else:
                flat[directive] = default

    return flat


def main():
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(curr_dir, "nginx_defaults.json")
    nested = load_nginx_defaults(json_path)
    flat = flatten_defaults(nested)
    return flat