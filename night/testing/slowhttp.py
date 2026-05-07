"""
SlowHTTPTest Scanner Module — Slowloris-type DoS attack simulation.
Tests Nginx's resilience to slow HTTP attacks.
"""

import subprocess
import os
import tempfile
from datetime import datetime


ATTACK_MODES = {
    '1': {
        'name': 'Slowloris (slow headers)',
        'flag': '-H',
        'description': 'Sends headers very slowly to keep connections open indefinitely.'
    },
    '2': {
        'name': 'Slow POST body',
        'flag': '-B',
        'description': 'Sends POST body data very slowly to exhaust worker connections.'
    },
    '3': {
        'name': 'Slow read (RST)',
        'flag': '-R',
        'description': 'Advertises a tiny TCP receive window to slow-read responses.'
    },
    '4': {
        'name': 'Apache Range attack (X)',
        'flag': '-X',
        'description': 'Sends Range header to trigger excessive memory allocation.'
    },
}


def is_available():
    r = subprocess.run("which slowhttptest", shell=True, capture_output=True, text=True)
    return r.returncode == 0


def run(target_url, mode_flag='-H', connections=200, duration=30,
        interval=10, output_dir=None, extra_args=""):
    """
    Run slowhttptest against the target.
    mode_flag: -H (slowloris), -B (slow body), -R (slow read), -X (range)
    """
    if not is_available():
        print("[-] slowhttptest is not installed. Run the install script first.")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir is None:
        output_dir = tempfile.gettempdir()

    output_base = os.path.join(output_dir, f"slowhttp_{timestamp}")

    cmd = (
        f"slowhttptest "
        f"{mode_flag} "
        f"-u {target_url} "
        f"-c {connections} "
        f"-l {duration} "
        f"-i {interval} "
        f"-o {output_base} "
        f"-g "           # generate CSV + HTML report
        f"{extra_args}"
    )

    print(f"[*] Running slowhttptest ({mode_flag}) against {target_url} ...")
    print(f"    Connections: {connections} | Duration: {duration}s | Interval: {interval}s")
    print(f"    Output: {output_base}.*")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=duration + 30)

    html_report = output_base + ".html"
    csv_report = output_base + ".csv"

    return {
        'tool': 'slowhttptest',
        'mode': mode_flag,
        'target': target_url,
        'output_file': html_report if os.path.exists(html_report) else None,
        'csv_file': csv_report if os.path.exists(csv_report) else None,
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode,
        'timestamp': timestamp,
    }


def _parse_result_summary(stdout):
    """Extract key metrics from slowhttptest output."""
    lines = stdout.splitlines()
    summary = []
    keywords = ['service available', 'connections', 'closed', 'pending', 'successful']
    for line in lines:
        if any(kw in line.lower() for kw in keywords):
            summary.append(line.strip())
    return summary


def interactive_run(target_url, output_dir):
    """Interactive slowhttptest configuration."""
    print("\n=== SlowHTTPTest — Slow HTTP DoS Attack Simulator ===")
    print(f"  Target: {target_url}")
    print()
    print("  Attack modes:")
    for key, mode in ATTACK_MODES.items():
        print(f"  {key}) {mode['name']} ({mode['flag']})")
        print(f"     {mode['description']}")
    print()

    mode_choice = input("  Select mode [1]: ").strip() or "1"
    if mode_choice not in ATTACK_MODES:
        mode_choice = "1"
    mode = ATTACK_MODES[mode_choice]

    conns_input = input("  Concurrent connections [200]: ").strip()
    connections = int(conns_input) if conns_input.isdigit() else 200

    dur_input = input("  Test duration in seconds [30]: ").strip()
    duration = int(dur_input) if dur_input.isdigit() else 30

    print(f"\n  [!] This will simulate a {mode['name']} attack against {target_url}")
    print(f"      Only run against your own DVWA test environment!")
    confirm = input("  Proceed? (y/N): ").strip().lower()
    if confirm != 'y':
        print("  [*] Skipped.")
        return None

    result = run(
        target_url,
        mode_flag=mode['flag'],
        connections=connections,
        duration=duration,
        output_dir=output_dir
    )

    if result:
        print(f"\n[+] slowhttptest completed (exit code: {result['returncode']}).")

        # Parse and display summary
        summary = _parse_result_summary(result['stdout'])
        if summary:
            print("  Summary:")
            for line in summary:
                print(f"    {line}")

        # Interpret result
        if result['returncode'] == 0:
            print("  [!] Service was AVAILABLE during the attack — Nginx is handling slow connections.")
        elif result['returncode'] == 1:
            print("  [!] Service became UNAVAILABLE — Nginx may be vulnerable to this slow HTTP attack!")
            print("      Consider: client_header_timeout, client_body_timeout, keepalive_timeout tuning.")

        if result['output_file']:
            print(f"  HTML Report: {result['output_file']}")
        if result['csv_file']:
            print(f"  CSV Data:    {result['csv_file']}")

    return result