def check(block, file_path, state, context_name):
    findings = []

    def is_explicitly_set(directive_name):
        return any(d.get('directive') == directive_name for d in block)

    for directive in block:
        cmd = directive.get('directive')
        args = directive.get('args', [])
        line = directive.get('line')

        if not args:
            continue

        arg_str = " ".join(args)

        if cmd == 'server_tokens':
            if arg_str == 'off':
                state['server_tokens'] = 'off'
            else:
                findings.append({
                    'rule_id': 'DC-001',
                    'rule': 'Server Version Leak (CWE-200)',
                    'description': "'server_tokens on' directive leaks the exact Nginx version.",
                    'file': file_path, 'line': line
                })

        elif cmd == 'merge_slashes' and arg_str == 'off':
            findings.append({
                'rule_id': 'DC-002',
                'rule': 'Merge Slashes Disabled (CWE-22)',
                'description': "The 'merge_slashes off' directive allows WAF bypass via ///path.",
                'file': file_path, 'line': line
            })

        elif cmd == 'autoindex' and arg_str == 'on':
            findings.append({
                'rule_id': 'DC-003',
                'rule': 'Directory Listing Enabled (CWE-548)',
                'description': "Explicit 'autoindex on' directive allows arbitrary file browsing.",
                'file': file_path, 'line': line
            })

        # TODO change to check if this is/can be a real meaningful path later
        elif cmd == 'error_log' and arg_str == 'off':
            findings.append({
                'rule_id': 'DC-004',
                'rule': 'The error_log "off" Trap',
                'description': "In Nginx, 'error_log off;' creates a literal file named 'off' on the disk. Use '/dev/null' instead.",
                'file': file_path, 'line': line
            })

    if state.get('server_tokens') == 'on' and not is_explicitly_set('server_tokens'):
        findings.append({
            'rule_id': 'DC-001',
            'rule': 'Server Version Leak (CWE-200)',
            'description': "'server_tokens on' directive leaks the exact Nginx version.",
            'file': file_path, 'line': "Inherited/Default"
        })

    if state.get('merge_slashes') == 'off' and not is_explicitly_set('merge_slashes'):
        findings.append({
            'rule_id': 'DC-002',
            'rule': 'Merge Slashes Disabled (CWE-22)',
            'description': "Inherited 'merge_slashes off' directive allows WAF bypass for this server block.",
            'file': file_path, 'line': "Inherited"
        })

    return findings