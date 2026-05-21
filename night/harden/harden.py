import re
import os
import shutil
from pathlib import Path
from rich.console import Console

console = Console()

BACKUP_SUFFIX = ".night-original"

SECURITY_HEADERS_BLOCK = """\
    # Security headers (injected by NIGHT hardening)
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
    add_header_inherit merge;
"""

RATE_LIMIT_ZONE = '    limit_req_zone $binary_remote_addr zone=nightlimit:10m rate=10r/s;  # Injected by NIGHT\n'
RATE_LIMIT_REQ = '    limit_req zone=nightlimit burst=20 nodelay;  # Injected by NIGHT\n'


def _backup(path: str) -> str:
    backup = path + BACKUP_SUFFIX
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
        console.print(f"  [dim]Backed up {path} → {backup}[/dim]")
    return backup


def _read(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.readlines()


def _write(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _line_idx(line_number: int) -> int:
    return max(0, int(line_number) - 1)


def _insert_after_opening_brace(lines: list[str], context: str, content: str) -> bool:
    in_block = False
    for i, line in enumerate(lines):
        if not in_block and re.match(rf'^\s*{context}\s*\{{', line):
            lines.insert(i + 1, content)
            return True
        if not in_block and re.match(rf'^\s*{context}\s*$', line):
            in_block = True
        elif in_block and line.strip() == '{':
            lines.insert(i + 1, content)
            return True
    return False


class Fixer:
    def __init__(self, lines: list[str], file_path: str):
        self.lines = lines
        self.file_path = file_path
        self.applied: list[str] = []

    def _log(self, rule_id: str, msg: str):
        self.applied.append(f"{rule_id}: {msg}")
        console.print(f"  [bold green]+[/bold green] [{rule_id}] {msg}")

    def _warn(self, rule_id: str, msg: str):
        self.applied.append(f"{rule_id}: MANUAL REVIEW REQUIRED — {msg}")
        console.print(f"  [bold yellow]![/bold yellow] [{rule_id}] {msg}")

    def sub_line(self, rule_id: str, lineno: int, pattern: str, replacement: str, msg: str):
        idx = _line_idx(lineno)
        new, n = re.subn(pattern, replacement, self.lines[idx])
        if n:
            self.lines[idx] = new
            self._log(rule_id, f"{msg} at line {lineno}")

    def route_explicit(self, rule_id: str, lineno: int, rule: str, desc: str):
        idx = _line_idx(lineno)
        line_content = self.lines[idx]

        if "server_tokens" in line_content or rule_id == 'INF-001':
            self.sub_line(rule_id, lineno, r'\bserver_tokens\s+on\b', 'server_tokens off', "Disabled server_tokens")

        elif "merge_slashes" in line_content or rule_id == 'RTE-001':
            self.sub_line(rule_id, lineno, r'\bmerge_slashes\s+off\b', 'merge_slashes on', "Enabled merge_slashes")

        elif "autoindex" in line_content or rule_id == 'INF-002':
            self.sub_line(rule_id, lineno, r'\bautoindex\s+on\b', 'autoindex off', "Disabled directory listing")

        elif "error_log" in line_content or rule_id == 'LOG-001':
            self.sub_line(rule_id, lineno, r'\berror_log\s+off\b', 'error_log /dev/null', "Fixed error_log trap")

        elif "client_max_body_size" in line_content or rule_id == 'DOS-002':
            self.sub_line(rule_id, lineno, r'\bclient_max_body_size\s+0\b', 'client_max_body_size 10m',
                          "Enforced body size limit")

        elif "client_body_buffer_size" in line_content:
            self.sub_line(rule_id, lineno, r'\bclient_body_buffer_size\s+\w+\b', 'client_body_buffer_size 16k',
                          "Reduced body buffer size")

        elif "add_header" in line_content and ("Fingerprinting" in rule or "Information Disclosure" in rule):
            self.lines[idx] = f'    # NIGHT: removed fingerprinting header — {line_content.strip()}\n'
            self._log(rule_id, f"Commented out fingerprinting header at line {lineno}")

        elif "proxy_pass_header" in line_content:
            self.sub_line(rule_id, lineno, r'\bproxy_pass_header\b', 'proxy_hide_header',
                          "Changed proxy_pass_header to proxy_hide_header")

        # SMART OFF-BY-SLASH FIX (Dynamically reads the location block above it)
        elif "alias" in line_content and ("Off-By-Slash" in rule or rule_id == 'RTE-003'):
            needs_slash = False
            # Read upwards to find the location block definition
            for j in range(idx, -1, -1):
                m_loc = re.match(r'^\s*location\s+([^\{]+?)\s*\{', self.lines[j])
                if m_loc:
                    loc_path = m_loc.group(1).strip()
                    needs_slash = loc_path.endswith('/')
                    break

            if needs_slash:
                # Add slash if missing
                new = re.sub(r'(alias\s+[^;]+?)(/?)(\s*;)', r'\1/\3', line_content)
            else:
                # Remove slash if present
                new = re.sub(r'(alias\s+[^;]+?)(/)(\s*;)', r'\1\3', line_content)

            if new != line_content:
                self.lines[idx] = new
                self._log(rule_id, f"Synced alias trailing slash with location at line {lineno}")
            else:
                self._warn(rule_id, f"Could not auto-fix alias at line {lineno} (already matches or parse failed)")

        elif "proxy_pass" in line_content and ("Off-By-Slash" in rule or rule_id == 'RTE-004'):
            self._warn(rule_id, f"Proxy_pass SSRF at line {lineno} requires manual backend routing verification.")

        # CRLF Injection ($uri)
        elif "CRLF" in rule or rule_id == 'RTE-002' or rule_id == 'INJ-001':
            self.sub_line(rule_id, lineno, r'\$(uri|document_uri)\b', '$request_uri', "Replaced unsafe $uri variable")

        # CSP & MIME Types for Uploads
        elif "Content Security Policy" in rule or rule_id == 'HDR-005':
            self.lines.insert(idx + 1,
                              "        add_header Content-Security-Policy \"default-src 'none'\";  # NIGHT: CSP for uploads\n")
            self._log(rule_id, f"Injected CSP header for uploads block after line {lineno}")

        elif "MIME Type" in rule or rule_id == 'HDR-006':
            self.lines.insert(idx + 1,
                              "        default_type application/octet-stream;  # NIGHT: force MIME for uploads\n")
            self._log(rule_id, f"Injected default_type application/octet-stream after line {lineno}")

        # Manual Reviews
        elif "SCRIPT_NAME" in rule or rule_id == 'INJ-003':
            self._warn(rule_id, f"SCRIPT_NAME misuse at line {lineno} requires manual PHP verification.")

    def route_implicit(self, rule_id: str, rule: str, desc: str, global_fixes_run: set):
        content = "".join(self.lines)

        if rule_id == 'INF-001' or "Server Version" in rule:
            if "server_tokens" not in content:
                if _insert_after_opening_brace(self.lines, 'http', '    server_tokens off;  # NIGHT: Hardened\n'):
                    self._log(rule_id, "Injected server_tokens off into http block")

        elif rule_id == 'HDR-004' or "Security HTTP Headers" in rule:
            if 'HDR-004' not in global_fixes_run:
                if _insert_after_opening_brace(self.lines, 'http', SECURITY_HEADERS_BLOCK):
                    self._log(rule_id, "Injected full security headers block into http context")
                    global_fixes_run.add('HDR-004')

        elif rule_id == 'DOS-002' or "client_max_body_size" in rule.lower():
            if "client_max_body_size" not in content:
                if _insert_after_opening_brace(self.lines, 'http',
                                               '    client_max_body_size 10m;  # NIGHT: Enforced limit\n'):
                    self._log(rule_id, "Injected client_max_body_size into http block")

        elif "Rate Limiting" in rule:
            if 'RATE_LIMIT' not in global_fixes_run:
                if "limit_req_zone" not in content:
                    _insert_after_opening_brace(self.lines, 'http', RATE_LIMIT_ZONE+RATE_LIMIT_REQ)
                    self._log(rule_id, "Injected limit_req_zone into http block")
                    self._log(rule_id, "Injected limit_req into http block")

                # for i, line in enumerate(self.lines):
                #     if re.match(r'\s*server\s*\{', line):
                #         self.lines.insert(i + 1, RATE_LIMIT_REQ)
                #         self._log(rule_id, "Injected limit_req into server block")
                #         break
                global_fixes_run.add('RATE_LIMIT')


def harden_config(config_path: str) -> dict:
    from night.core.parser import NginxParser
    from night.core.scanner import Scanner

    console.print(f"\n[bold blue][*] NIGHT harden: scanning {config_path}[/bold blue]")

    parser = NginxParser(config_path)
    payload = parser.parse()
    scanner = Scanner(payload)
    results = scanner.run_all_checks()

    if not results:
        console.print("[bold green][+] No issues found — nothing to harden.[/bold green]")
        return {'findings': 0, 'files_patched': 0, 'applied': [], 'skipped': []}

    total = sum(len(r['occurrences']) for r in results)
    console.print(f"[yellow][!] {total} finding(s) detected. Generating hardened configs...[/yellow]\n")

    # Extract into a flat list of actionable tasks
    tasks = []
    for result in results:
        for occ in result['occurrences']:
            try:
                lineno = int(occ['line'])
                is_explicit = True
            except ValueError:
                lineno = 0
                is_explicit = False

            tasks.append({
                'rule_id': result.get('rule_id', 'UNK'),
                'rule': result.get('rule', ''),
                'desc': result.get('description', ''),
                'lineno': lineno,
                'is_explicit': is_explicit,
                'file': occ['file']
            })

    # Group by File
    by_file = {}
    for t in tasks:
        if t['file']:
            by_file.setdefault(t['file'], []).append(t)

    files_patched = 0
    all_applied = []

    for fpath, file_tasks in by_file.items():
        if not os.path.isfile(fpath):
            continue

        console.print(f"[bold]-- {fpath} --[/bold]")

        explicit_tasks = [t for t in file_tasks if t['is_explicit']]
        explicit_tasks.sort(key=lambda x: x['lineno'], reverse=True)

        implicit_tasks = [t for t in file_tasks if not t['is_explicit']]

        lines = _read(fpath)
        fixer = Fixer(lines, fpath)

        # Explicit first
        for task in explicit_tasks:
            fixer.route_explicit(task['rule_id'], task['lineno'], task['rule'], task['desc'])

        # Implicit/Global last
        global_fixes_run = set()
        for task in implicit_tasks:
            fixer.route_implicit(task['rule_id'], task['rule'], task['desc'], global_fixes_run)

        if fixer.applied:
            _backup(fpath)
            _write(fpath, fixer.lines)
            console.print(f"  [bold green]Written: {fpath}[/bold green]")
            files_patched += 1
            all_applied.extend(fixer.applied)

    return {'findings': total, 'files_patched': files_patched, 'applied': all_applied}