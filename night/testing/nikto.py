"""
Nikto Scanner Module — Passive/configuration security testing.
"""

import subprocess
import os
import tempfile
from datetime import datetime


def is_available():
    r = subprocess.run("which nikto", shell=True, capture_output=True, text=True)
    return r.returncode == 0


def run(target_url, nginx_host=None, output_dir=None, extra_args=""):
    """
    Run Nikto against the target URL.
    Returns dict with {tool, target, output_file, stdout, returncode, timestamp}.
    """
    if not is_available():
        print("[-] Nikto is not installed. Run the install script first.")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir is None:
        output_dir = tempfile.gettempdir()

    output_file = os.path.join(output_dir, f"nikto_{timestamp}.xml")
    host_arg = f"-vhost {nginx_host}" if nginx_host else ""

    cmd = (
        f"nikto -h {target_url} {host_arg} "
        f"-Format xml -output {output_file} "
        f"-Tuning x {extra_args}"
    )
    # -Tuning x = all tests

    print(f"[*] Running Nikto against {target_url} ...")
    print(f"    Output: {output_file}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    return {
        'tool': 'nikto',
        'target': target_url,
        'output_file': output_file if os.path.exists(output_file) else None,
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode,
        'timestamp': timestamp,
    }


def interactive_run(target_url, output_dir):
    """Interactive Nikto configuration."""
    print("\n=== Nikto — Passive/Configuration Security Scanner ===")
    print(f"  Target: {target_url}")
    print()
    print("  Nikto checks for:")
    print("  • Server version disclosure")
    print("  • Default files and configurations")
    print("  • Outdated software")
    print("  • Dangerous HTTP methods (PUT, DELETE, etc.)")
    print("  • Missing security headers")
    print("  • SSL/TLS configuration issues")
    print()

    nginx_host = input("  Nginx virtual host (leave blank to skip -vhost): ").strip() or None
    extra = input("  Extra Nikto args (leave blank for defaults): ").strip()

    result = run(target_url, nginx_host=nginx_host, output_dir=output_dir, extra_args=extra)
    if result:
        if result['returncode'] == 0 or result['stdout']:
            print(f"\n[+] Nikto completed.")
            print(f"    Report saved to: {result['output_file']}")
        else:
            print(f"[-] Nikto exited with code {result['returncode']}")
            if result['stderr']:
                print(f"    Error: {result['stderr'][:300]}")
    return result