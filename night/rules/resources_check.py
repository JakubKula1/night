# night/rules/resources_check.py
"""
Performance & Resource Limit Rule Module
Checks for:
  - RES-001: File descriptor exhaustion (worker_connections vs worker_rlimit_nofile)
  - RES-002: Missing or unsafe buffer limits (client_max_body_size)
  - RES-003: Missing rate limiting
"""


def _parse_size_to_bytes(val):
    """Converts Nginx values (k, m, g) to bytes for comparisons."""
    if val is None: return None
    if isinstance(val, list): val = val[0]
    val = str(val).strip().lower()

    if "|" in val: val = val.split("|")[0]  # pick one by the platform (x86/x32/x86-64 | x64)

    units = {'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3}
    if val[-1] in units:
        try:
            return int(val[:-1]) * units[val[-1]]
        except ValueError:
            return None
    try:
        return int(val)
    except ValueError:
        return None


def _get_line(block, directive_name):
    for d in block:
        if d.get('directive') == directive_name:
            return d.get('line')
    return "Inherited"


def check(block, file_path, state, context_name):
    findings = []

    # -------------------------------------------------------------------------
    # RES-001: File descriptor exhaustion (worker_connections vs worker_rlimit_nofile)
    # -------------------------------------------------------------------------
    if context_name in ['global', 'main', 'events']:
        w_conns = _parse_size_to_bytes(state.get('worker_connections'))   # context: events
        r_limit = _parse_size_to_bytes(state.get('worker_rlimit_nofile')) # context: main/global

        # harden: set worker_rlimit_nofile to 2*worker_connections
        if w_conns and w_conns > 512:
            if r_limit is None:
                findings.append({
                    'rule_id': 'RES-001',
                    'rule': 'File descriptor exhaustion (CWE-400)',
                    'description': f"Server has {w_conns} connections but 'worker_rlimit_nofile' is not set.",
                    'file': file_path, 'line': "Default"
                })
            elif r_limit < (w_conns * 2):
                findings.append({
                    'rule_id': 'RES-001',
                    'rule': 'Insufficient worker_rlimit_nofile (CWE-400)',
                    'description': f"The rlimit ({r_limit}) should be at least double the connections ({w_conns * 2}).",
                    'file': file_path, 'line': _get_line(block, 'worker_rlimit_nofile')
                })

    # -------------------------------------------------------------------------
    # RES-002/RES-003: RAM exhaustion prevention
    # -------------------------------------------------------------------------
    if context_name in ['http', 'server', 'location']:
        max_body = state.get('client_max_body_size')
        if max_body == '0':
            findings.append({   # harden: set client_max_body_size to 1m
                'rule_id': 'RES-002',
                'rule': 'Unlimited client_max_body_size (CWE-770)',
                'description': "Setting 'client_max_body_size 0' disables upload limits, making the server vulnerable to DoS via disk/RAM exhaustion.",
                'file': file_path, 'line': _get_line(block, 'client_max_body_size')
            })

        buf_size = _parse_size_to_bytes(state.get('client_body_buffer_size'))
        if buf_size and buf_size > (128 * 1024):
            findings.append({   # harden: set client_body_buffer_size to 8k
                'rule_id': 'RES-003',
                'rule': 'Excessive client_body_buffer_size (CWE-770)',
                'description': f"Buffer size ({state.get('client_body_buffer_size')}) is too high - large buffers can lead to rapid RAM exhaustion under load.",
                'file': file_path, 'line': _get_line(block, 'client_body_buffer_size')
            })

    # -------------------------------------------------------------------------
    # RES-004: Missing rate limiting (web context level control)
    # -------------------------------------------------------------------------
    # harden:
    # to http: limit_req_zone $server_name zone=perserver:10m rate=5r/m;
    # to each server: limit_req zone=perserver burst=10 nodelay;
    if context_name in ['http', 'server', 'location']:
        has_limit = any(state.get(d) for d in ['limit_req', 'limit_conn'])  # context for both: http, server, location and both have no default (not in the state)
        if not has_limit:
            findings.append({
                'rule_id': 'RES-004',
                'rule': 'Missing Rate Limiting (CWE-307)',
                'description': "No 'limit_req' or 'limit_conn' defined - vulnerable to brute-force/DoS.",
                'file': file_path, 'line': 'Default'
            })

    return findings