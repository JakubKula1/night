def check(ast, file_path):
    findings = []

    def traverse(block):
        # Nginx defaults
        server_tokens_found = False

        for directive in block:
            cmd = directive.get('directive')
            args = directive.get('args', [])

            # Check: Directory Listing (autoindex on)
            if cmd == 'autoindex' and args and args[0] == 'on':
                findings.append({
                    'rule': 'Directory Listing Enabled (CWE-548)',
                    'description': "The 'autoindex on' directive allows attackers to see all files in the directory.",
                    'file': file_path,
                    'line': directive.get('line')
                })

            # Check: Server Tokens explicitly on
            if cmd == 'server_tokens':
                server_tokens_found = True
                if args and args[0] == 'on':
                    findings.append({
                        'rule': 'Server Version Leak (CWE-200)',
                        'description': "The 'server_tokens on' directive leaks the exact Nginx version.",
                        'file': file_path,
                        'line': directive.get('line')
                    })

            # If the directive has a block (like http{}, server{}, location{}), recurse into it
            if 'block' in directive:
                traverse(directive['block'])

    traverse(ast)
    return findings