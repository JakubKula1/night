# night/rules/injections.py
"""
Injection & Variable Misuse Rule Module
Checks for:
  - INJ-001: CRLF injection via $uri / $document_uri
  - INJ-002: if-in-location with non-safe directives
  - INJ-003: SCRIPT_NAME variable misuse
"""

import re

SAFE_IF_DIRECTIVES = {'return', 'rewrite', 'set'}
CRLF_RISK_DIRECTIVES = {'return', 'add_header', 'rewrite', 'proxy_pass'}
UNSAFE_VARS = re.compile(r'\$(uri|document_uri)\b')
SAFE_VAR = re.compile(r'\$request_uri\b')

def check(block, file_path, state, context_name):
    findings =[]

    for directive in block:
        cmd = directive.get('directive')
        args = directive.get('args',[])
        line = directive.get('line')

        if not args:
            continue

        arg_str = " ".join(args)

        # ---------------------------------------------------------------------
        # INJ-001: CRLF injection via $uri / $document_uri
        # ---------------------------------------------------------------------
        if cmd in CRLF_RISK_DIRECTIVES:
            if UNSAFE_VARS.search(arg_str) and not SAFE_VAR.search(arg_str):
                findings.append({   # harden: use $request_uri instead to preserve the raw URI
                    'rule_id': 'INJ-001',
                    'rule': 'CRLF Injection via $uri / $document_uri (CWE-93)',
                    'description': f"Directive '{cmd}' uses $uri or $document_uri, which are decoded/normalized and can enable CRLF injection attacks.",
                    'file': file_path,
                    'line': line
                })

        # ---------------------------------------------------------------------
        # INJ-003: SCRIPT_NAME variable misuse
        # ---------------------------------------------------------------------
        if cmd == 'fastcgi_param' and len(args) >= 2:
            param_name = args[0]
            param_val = args[1]
            if param_name == 'SCRIPT_NAME' and '$fastcgi_script_name' in param_val:
                findings.append({   # harden: use $fastcgi_script_name only when PATH_INFO is not involved
                    'rule_id': 'INJ-003',
                    'rule': 'SCRIPT_NAME Variable Misuse (CWE-20)',
                    'description': "fastcgi_param SCRIPT_NAME is set to $fastcgi_script_name while PATH_INFO is used, which may lead to unintended script execution.",
                    'file': file_path,
                    'line': line
                })

        # -------------------------------------------------------------------------
        # INJ-002: Unsafe if-in-location ("If Is Evil" trap)
        # -------------------------------------------------------------------------
        if context_name == 'location' and cmd == 'if':
            if_block = directive.get('block', [])
            for sub in if_block:
                sub_cmd = sub.get('directive', '')
                if sub_cmd and sub_cmd not in SAFE_IF_DIRECTIVES:
                    findings.append({
                        'rule_id': 'INJ-002',
                        'rule': 'Unsafe Directive Inside if-in-location (CWE-670)',
                        'description': f"'if' block inside a 'location' context contains directive '{sub_cmd}' - only 'return', 'rewrite' and 'set' are safe here (Nginx documentation).",
                        'file': file_path,
                        'line': directive.get('line', '')
                    })
                    break

    return findings