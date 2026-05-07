"""
Gobuster Scanner Module — Directory/file brute-forcing and asymmetric load generation.
"""

import subprocess
import os
import tempfile
from datetime import datetime


DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
]

FALLBACK_WORDLIST = "/tmp/gobuster_wordlist.txt"
FALLBACK_WORDS = [
    "admin", "login", "api", "config", "backup", "test", "dev", "staging",
    "uploads", "files", "images", "static", "assets", "js", "css",
    "phpinfo.php", ".git", ".env", "README.md", "robots.txt", "sitemap.xml",
    "wp-admin", "wp-login.php", ".htaccess", ".htpasswd", "server-status",
    "index.php", "index.html", "dashboard", "console", "phpmyadmin",
]


def is_available():
    r = subprocess.run("which gobuster", shell=True, capture_output=True, text=True)
    return r.returncode == 0


def _find_wordlist():
    for wl in DEFAULT_WORDLISTS:
        if os.path.exists(wl):
            return wl
    # Create minimal fallback wordlist
    with open(FALLBACK_WORDLIST, 'w') as f:
        f.write("\n".join(FALLBACK_WORDS))
    print(f"  [!] No standard wordlist found. Using minimal fallback: {FALLBACK_WORDLIST}")
    return FALLBACK_WORDLIST


def run(target_url, wordlist=None, threads=20, extensions="php,html,txt,js",
        output_dir=None, extra_args=""):
    """
    Run Gobuster dir mode against the target URL.
    Returns dict with tool result metadata.
    """
    if not is_available():
        print("[-] Gobuster is not installed. Run the install script first.")
        return None

    if wordlist is None:
        wordlist = _find_wordlist()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir is None:
        output_dir = tempfile.gettempdir()

    output_file = os.path.join(output_dir, f"gobuster_{timestamp}.txt")

    cmd = (
        f"gobuster dir "
        f"-u {target_url} "
        f"-w {wordlist} "
        f"-t {threads} "
        f"-x {extensions} "
        f"-o {output_file} "
        f"--no-error "
        f"{extra_args}"
    )

    print(f"[*] Running Gobuster against {target_url} ...")
    print(f"    Wordlist: {wordlist}")
    print(f"    Threads: {threads} | Extensions: {extensions}")
    print(f"    Output: {output_file}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    return {
        'tool': 'gobuster',
        'target': target_url,
        'output_file': output_file if os.path.exists(output_file) else None,
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode,
        'timestamp': timestamp,
    }


def interactive_run(target_url, output_dir):
    """Interactive Gobuster configuration."""
    print("\n=== Gobuster — Directory & File Discovery / Load Generator ===")
    print(f"  Target: {target_url}")
    print()
    print("  Gobuster checks for:")
    print("  • Hidden directories and files")
    print("  • Backup files (.bak, .old, .zip)")
    print("  • Admin panels and control interfaces")
    print("  • Generates asymmetric load to test Nginx worker/connection limits")
    print()

    wordlist = input("  Wordlist path (leave blank for auto): ").strip() or None
    threads_input = input("  Threads [20]: ").strip()
    threads = int(threads_input) if threads_input.isdigit() else 20
    extensions = input("  File extensions [php,html,txt,js]: ").strip() or "php,html,txt,js"
    extra = input("  Extra args (e.g. --wildcard, -k for TLS skip): ").strip()

    result = run(
        target_url,
        wordlist=wordlist,
        threads=threads,
        extensions=extensions,
        output_dir=output_dir,
        extra_args=extra
    )
    if result:
        print(f"\n[+] Gobuster completed (exit code: {result['returncode']}).")
        if result['output_file']:
            print(f"    Report saved to: {result['output_file']}")
        # Print discovered paths summary
        if result['stdout']:
            lines = [l for l in result['stdout'].splitlines() if l.startswith('/')]
            if lines:
                print(f"    Discovered {len(lines)} path(s):")
                for l in lines[:20]:
                    print(f"      {l}")
                if len(lines) > 20:
                    print(f"      ... and {len(lines)-20} more (see output file)")
    return result