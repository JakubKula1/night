SECURITY_HEADERS = {
    'x-frame-options',
    'x-content-type-options',
    'x-xss-protection',
    'content-security-policy',
    'strict-transport-security',
    'referrer-policy',
    'permissions-policy',
}

FINGERPRINT_HEADERS = {
    'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
    'x-generator', 'x-drupal-cache', 'x-varnish',
    'via', 'server',
}


def check(block, file_path, state, context_name):
    findings = []

    if 'active_headers' not in state:
        state['active_headers'] = set()

    current_block_headers = set()
    for directive in block:
        if directive.get('directive') == 'add_header' and directive.get('args'):
            current_block_headers.add(directive['args'][0].lower())

    # add_header inheritance problem if add_header_inherit is on
    # harden: define add_header_inherit merge (at the highest possible context - http)
    if current_block_headers:
        parent_headers = state['active_headers']
        if state['add_header_inherit'] != 'merge' and context_name != 'http':
            lost_headers = parent_headers - current_block_headers
            if lost_headers:
                trap_line = next((d['line'] for d in block if d.get('directive') == 'add_header'), "N/A")
                findings.append({
                    'rule_id': 'HDR-003',
                    'rule': 'add_header Inheritance Break (CWE-16)',
                    'description': f"Using 'add_header' here silently drops all headers inherited from the parent block.",
                    'file': file_path,
                    'line': trap_line
                })
            state['active_headers'] = current_block_headers
        else:
            state['active_headers'] = parent_headers | current_block_headers


    for directive in block:
        cmd = directive.get('directive')
        args = directive.get('args', [])
        line = directive.get('line')

        # Exposing technology via add_header
        # harden: just remove the header
        if cmd == 'add_header' and args:
            hdr_name = args[0].lower()
            if hdr_name in FINGERPRINT_HEADERS:
                findings.append({
                    'rule_id': 'HDR-001',
                    'rule': f'Information Disclosure via HTTP Header: {hdr_name} (CWE-200)',
                    'description': f"'add_header {args[0]}' reveals technology stack details.",
                    'file': file_path,
                    'line': line
                })

        # proxy_pass_header that leaks backend info
        # harden: use 'proxy_hide_header {hdr_name};' instead
        if cmd == 'proxy_pass_header' and args:
            hdr_name = args[0].lower()
            if hdr_name in FINGERPRINT_HEADERS:
                findings.append({
                    'rule_id': 'HDR-002',
                    'rule': f'Backend Fingerprinting via proxy_pass_header (CWE-200)',
                    'description': f"'proxy_pass_header {args[0]}' passes the backend's {hdr_name} header to clients, exposing server technology.",
                    'file': file_path,
                    'line': line
                })

    # Missing security headers
    # harden: add missing security headers
    if context_name in ('http', 'server', 'location', 'if'):
        missing = SECURITY_HEADERS - state['active_headers']
        if missing:
            findings.append({
                'rule_id': 'HDR-004',
                'rule': 'Missing Security HTTP Headers (CWE-693)',
                'description': f"Context {context_name} missing recommended security headers: [green]{', '.join(missing)}[/green]",
                'file': file_path,
                'line': 'Inherited/Default'
            })

    # Serving uploaded files without Content-Security-Policy
    upload_indicators = ['upload', 'uploads', 'media', 'files', 'user-content', 'static']
    for directive in block:
        cmd = directive.get('directive')
        args = directive.get('args', [])
        line = directive.get('line')

        if cmd in ['root', 'alias'] and args:
            path_val = args[0].lower()
            if any(ind in path_val for ind in upload_indicators):
                if 'content-security-policy' not in state['active_headers']:
                    findings.append({   # harden: add add_header Content-Security-Policy "default-src 'none'"; (and set default_type application/octet-stream;)
                        'rule_id': 'HDR-005',
                        'rule': 'Uploaded File Serving Without Content Security Policy (CWE-79)',
                        'description': f"Path '{args[0]}' appears to serve user-uploaded content but lacks a 'Content-Security-Policy' header, which can lead to XSS.",
                        'file': file_path,
                        'line': line
                    })
                has_default_type = any(
                    d.get('directive') == 'default_type' and 'octet-stream' in " ".join(d.get('args', []))
                    for d in block
                )
                if not has_default_type:    # harden: add default_type application/octet-stream;
                    findings.append({
                        'rule_id': 'HDR-006',
                        'rule': 'Uploaded File Serving Without Forced MIME Type (CWE-79)',
                        'description': f"Path '{args[0]}' serves user content without 'default_type application/octet-stream', which can lead to browser executing uploaded scripts.",
                        'file': file_path,
                        'line': line
                    })

    return findings