def check(ast, file_path):
    findings = []

    def traverse(block):
        for directive in block:
            cmd = directive.get('directive')
            args = directive.get('args', [])

            # Check: error_log off trap
            if cmd == 'error_log' and args and args[0] == 'off':
                findings.append({
                    'rule': 'The error_log "off" Trap',
                    'description': "In Nginx, 'error_log off;' creates a literal file named 'off' on the disk. Use '/dev/null' instead.",
                    'file': file_path,
                    'line': directive.get('line')
                })

            if 'block' in directive:
                traverse(directive['block'])

    traverse(ast)
    return findings