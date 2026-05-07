"""
OWASP ZAP Scanner Module — Passive scanning and active attack testing.
Uses ZAP's CLI / API for automation against DVWA.
"""

import subprocess
import os
import sys
import tempfile
import time
import json
from datetime import datetime


ZAP_CLI_CANDIDATES = [
    "zap.sh", "zap-cli", "/opt/zaproxy/zap.sh",
    "/usr/share/zaproxy/zap.sh", "zaproxy",
]

ZAP_API_PORT = 8090
ZAP_API_KEY = "nightsec"
ZAP_API_BASE = f"http://127.0.0.1:{ZAP_API_PORT}"


def _find_zap():
    for candidate in ZAP_CLI_CANDIDATES:
        r = subprocess.run(f"which {candidate}", shell=True, capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return None


def is_available():
    return _find_zap() is not None


def _zap_api(endpoint, params=None):
    """Hit ZAP REST API. Requires ZAP to be running in daemon mode."""
    try:
        import urllib.request
        import urllib.parse
        base = f"{ZAP_API_BASE}/{endpoint}?apikey={ZAP_API_KEY}"
        if params:
            base += "&" + urllib.parse.urlencode(params)
        with urllib.request.urlopen(base, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {'error': str(e)}


def _start_zap_daemon(zap_bin):
    """Start ZAP in headless daemon mode."""
    cmd = (
        f"{zap_bin} -daemon "
        f"-port {ZAP_API_PORT} "
        f"-config api.key={ZAP_API_KEY} "
        f"-config api.addrs.addr.name=.* "
        f"-config api.addrs.addr.regex=true "
        f"-nostdout"
    )
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[*] Starting ZAP daemon on port {ZAP_API_PORT} ...")
    # Wait for ZAP to be ready
    for i in range(30):
        time.sleep(2)
        r = _zap_api("JSON/core/view/version/")
        if 'version' in r:
            print(f"[+] ZAP ready (version {r['version']})")
            return proc
        sys.stdout.write(f"\r    Waiting for ZAP... ({i*2}s)")
        sys.stdout.flush()
    print("\n[-] ZAP did not start in time.")
    proc.terminate()
    return None


def run_passive_scan(target_url, output_dir=None):
    """Run ZAP passive scan (spider + passive analysis)."""
    zap_bin = _find_zap()
    if not zap_bin:
        print("[-] OWASP ZAP is not installed. Run the install script first.")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir is None:
        output_dir = tempfile.gettempdir()

    output_file = os.path.join(output_dir, f"zap_passive_{timestamp}.html")

    print(f"[*] Running ZAP passive scan against {target_url} ...")

    # Use ZAP baseline scan script if available (Docker-based ZAP)
    baseline = subprocess.run("which zap-baseline.py", shell=True, capture_output=True, text=True)
    if baseline.returncode == 0:
        cmd = f"zap-baseline.py -t {target_url} -r {output_file} --auto"
    else:
        # Fallback: run ZAP in baseline mode directly
        cmd = (
            f"{zap_bin} -quickurl {target_url} "
            f"-quickprogress -quickout {output_file}"
        )

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)

    return {
        'tool': 'zap_passive',
        'target': target_url,
        'output_file': output_file if os.path.exists(output_file) else None,
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode,
        'timestamp': timestamp,
    }


def run_active_scan(target_url, scan_policy="Default Policy", output_dir=None):
    """Run ZAP active scan (injection attacks, DVWA-focused)."""
    zap_bin = _find_zap()
    if not zap_bin:
        print("[-] OWASP ZAP is not installed.")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir is None:
        output_dir = tempfile.gettempdir()

    output_file = os.path.join(output_dir, f"zap_active_{timestamp}.html")

    print(f"[*] Running ZAP ACTIVE scan against {target_url} ...")
    print(f"  [!] ACTIVE SCAN — this will send attack payloads to the target!")
    print(f"  [!] Only use against {target_url} (DVWA test environment)")

    # Full scan with DVWA authentication
    cmd = (
        f"{zap_bin} -quickurl {target_url} "
        f"-quickprogress -quickout {output_file} "
        f"-cmd -addonupdate -addoninstall pscanrules -addoninstall ascanrules"
    )

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)

    return {
        'tool': 'zap_active',
        'target': target_url,
        'output_file': output_file if os.path.exists(output_file) else None,
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode,
        'timestamp': timestamp,
    }


def interactive_run(target_url, output_dir):
    """Interactive ZAP configuration menu."""
    print("\n=== OWASP ZAP — Web Application Security Scanner ===")
    print(f"  Target: {target_url}")
    print()
    print("  ZAP scan modes:")
    print("  1) Passive Scan  — Spider + passive analysis (safe, read-only)")
    print("  2) Active Scan   — Full attack suite: SQLi, XSS, CRLF, SSRF, etc.")
    print("  3) Both          — Passive first, then active")
    print()
    choice = input("  Select mode [1]: ").strip() or "1"

    results = []
    if choice in ("1", "3"):
        r = run_passive_scan(target_url, output_dir)
        if r:
            results.append(r)
            status = "completed" if r['returncode'] == 0 else f"exited ({r['returncode']})"
            print(f"\n[+] ZAP passive scan {status}.")
            if r['output_file']:
                print(f"    Report: {r['output_file']}")

    if choice in ("2", "3"):
        confirm = input("\n  [!] Active scan sends attack payloads. Confirm against DVWA only (y/N): ").strip().lower()
        if confirm == 'y':
            r = run_active_scan(target_url, output_dir=output_dir)
            if r:
                results.append(r)
                status = "completed" if r['returncode'] == 0 else f"exited ({r['returncode']})"
                print(f"\n[+] ZAP active scan {status}.")
                if r['output_file']:
                    print(f"    Report: {r['output_file']}")
        else:
            print("  [*] Active scan skipped.")

    return results if results else None