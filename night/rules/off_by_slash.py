from urllib.parse import urlparse


def check(ast, file_path):
    findings = []

    def traverse(block):
        for directive in block:
            cmd = directive.get('directive')
            args = directive.get('args', [])

            if cmd == 'location' and args:
                if args[0] in ['=', '^~']:  # The first argument might be a location modifier
                    location_path = args[1]
                elif args[0] in ['~', '~*']:
                    continue  # Skip regex locations -> no off-by-slash vulnerability
                else:
                    location_path = args[0]

                # Check directives inside current location block
                for inner_dir in directive.get('block', []):
                    inner_cmd = inner_dir.get('directive')
                    inner_args = inner_dir.get('args')

                    # Check for Alias Off-by-Slash
                    if inner_cmd == 'alias' and inner_args:
                        alias_path = inner_args[0]
                        if location_path.endswith('/') != alias_path.endswith('/'):
                            findings.append({
                                'rule': 'Alias Traversal / Off-By-Slash (CWE-22)',
                                'description': f"Mismatch in trailing slashes between location '{location_path}' and alias '{alias_path}'. This allows arbitrary file reading.",
                                'file': file_path,
                                'line': inner_dir.get('line')
                            })

                    # Check for Proxy_Pass Off-by-Slash
                    if inner_cmd == 'proxy_pass' and inner_args:
                        proxy_url = inner_args[0]
                        parsed_url = urlparse(proxy_url)    # Parse the URL to ignore query parameters if any exist

                        if parsed_url.path:
                            if location_path.endswith('/') != parsed_url.path.endswith('/'):
                                findings.append({
                                    'rule': 'proxy_pass SSRF / Off-By-Slash (CWE-918)',
                                    'description': f"Mismatch in trailing slashes between location '{location_path}' and proxy_pass '{proxy_url}'. This allows backend SSRF traversal.",
                                    'file': file_path,
                                    'line': inner_dir.get('line')
                                })

            # Recursive check of nested location blocks
            if 'block' in directive:
                traverse(directive['block'])

    traverse(ast)
    return findings