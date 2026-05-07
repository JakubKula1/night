# import sys
# import os
# import tempfile
# from datetime import datetime
# from rich.console import Console
# from rich.table import Table
# from rich import box
#
#
# console = Console()
# DEFAULT_OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "night-reports")
#
# def _import_modules():
#     from . import environment, nikto, gobuster, zap, slowhttp, report
#     return environment, nikto, gobuster, zap, slowhttp, report
#
#
# def _status_icon(ok: bool) -> str:
#     return "[bold green]✔[/bold green]" if ok else "[bold red]✗[/bold red]"
#
#
# def _print_header(environment, nikto, gobuster, zap, slowhttp):
#     # Fetching tool statuses for the table
#     tools_info = [
#         ("Nikto", nikto.is_available()),
#         ("Gobuster", gobuster.is_available()),
#         ("OWASP ZAP", zap.is_available()),
#         ("SlowHTTPTest", slowhttp.is_available()),
#     ]
#
#     dvwa_running = environment.is_container_running()  # Assuming this helper exists in environment.py
#
#     table = Table(title="Night 🔒 Security Test Suite Overview", box=box.DOUBLE_EDGE, expand=True)
#     table.add_column("Tool / Target", style="cyan")
#     table.add_column("Status")
#     table.add_column("Details", style="dim")
#
#     # Add Tools to table
#     for name, available in tools_info:
#         table.add_row(name, _status_icon(available), "Ready" if available else "Not Found")
#
#     table.add_section()
#     table.add_row("DVWA Env", _status_icon(dvwa_running), "http://127.0.0.1:8080" if dvwa_running else "Stopped")
#
#     console.print(table)
#
#
# def run_tests(environment, nikto, gobuster, zap, slowhttp, report, target_url=None, selected_keys=None, output_dir=None):
#     _print_header(environment, nikto, gobuster, zap, slowhttp)
#
#     if not target_url:
#         console.print("\n[bold]Target Configuration[/bold]")
#         target_url = input("  Target URL (Leave blank for DVWA): ").strip()
#
#     if not target_url:
#         console.print("[cyan][*] Auto-starting DVWA test environment...[/cyan]")
#         target_url = environment.ensure_environment()
#         if not target_url:
#             console.print("[bold red][!] Could not start test environment. Exiting.[/bold red]")
#             return
#
#     output_dir = output_dir or DEFAULT_OUTPUT_DIR
#     os.makedirs(output_dir, exist_ok=True)
#
#     # Simplified Tool Dictionary for logic
#     TOOLS = {
#         '1': ('Nikto', nikto),
#         '2': ('Gobuster', gobuster),
#         '3': ('OWASP ZAP', zap),
#         '4': ('SlowHTTPTest', slowhttp),
#     }
#
#     if not selected_keys:
#         console.print("\n  [bold cyan][1][/bold cyan] Nikto         [dim]— Web server vulnerability scanner[/dim]")
#         console.print("  [bold cyan][2][/bold cyan] Gobuster      [dim]— Directory and file brute-forcer[/dim]")
#         console.print("  [bold cyan][3][/bold cyan] OWASP ZAP     [dim]— Automated app security scanner[/dim]")
#         console.print("  [bold cyan][4][/bold cyan] SlowHTTPTest  [dim]— DoS vulnerability tester[/dim]")
#         console.print("  [bold cyan][a][/bold cyan] Run All")
#
#         choice = input("\n  Select tools (e.g. 1 3): ").strip().lower() or 'a'
#         selected_keys = list(TOOLS.keys()) if choice == 'a' else choice.split()
#
#     results = []
#     for key in selected_keys:
#         if key in TOOLS:
#             name, mod = TOOLS[key]
#             if not mod.is_available():
#                 console.print(f"[yellow][!] {name} is not installed. Skipping...[/yellow]")
#                 continue
#
#             console.print(f"\n[bold cyan]── Running {name} ──────────────────────────────────────[/bold cyan]")
#             result = mod.interactive_run(target_url, output_dir)
#             if result:
#                 results.extend(result) if isinstance(result, list) else results.append(result)
#
#     if results:
#         console.print("\n[bold green]✔ Tests complete. Generating unified report...[/bold green]")
#         report_file = report.generate(results, target_url, output_dir)
#         console.print(f"[bold cyan][+] Report saved to:[/bold cyan] {report_file}")
#     else:
#         console.print("\n[bold red][!] No results captured.[/bold red]")
#
#
# def run(args=None) -> None:
#     environment, nikto, gobuster, zap, slowhttp, report = _import_modules()
#
#     while True:
#         try:
#             _print_header()
#             console.print("  [bold cyan][1][/bold cyan] Run Security Tests   [dim]- Launch scans against target[/dim]")
#             console.print("  [bold cyan][2][/bold cyan] Manage Environment   [dim]- Start/Stop/Check DVWA[/dim]")
#             console.print("  [bold cyan][q][/bold cyan] Exit\n")
#
#             choice = input("  Select an option: ").strip().lower()
#
#             if choice == "1":
#                 run_tests(environment=environment, nikto=nikto, gobuster=gobuster, zap=zap, slowhttp=slowhttp, report=report)
#                 input("\n  Press Enter to return to menu...")
#             elif choice == "2":
#                 console.print("\n  [dim]Env:[/dim] [cyan]start[/cyan] | [cyan]stop[/cyan] | [cyan]status[/cyan]")
#                 e_choice = input("  Action: ").strip().lower()
#                 if e_choice == "start":
#                     environment.ensure_environment()
#                 elif e_choice == "stop":
#                     environment.stop_container()
#                 elif e_choice == "status":
#                     environment.print_status()
#             elif choice == "q":
#                 break
#         except KeyboardInterrupt:
#             break
#
#
# if __name__ == "__main__":
#     run()

"""
Night Test Menu — Interactive CLI for web server security testing.
Invoked via: night test  OR  night t

Usage:
  night test              — Launch interactive test menu
  night test env          — Environment management submenu
  night test env setup    — Deploy DVWA test environment
  night test env status   — Show environment status
  night test env stop     — Stop DVWA container
  night test run          — Run all selected tests
"""

import sys
import os
import tempfile
from datetime import datetime

# Ensure parent package is importable when run directly
# sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from . import environment, nikto, gobuster, zap, slowhttp, report


DEFAULT_OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "night-reports")


TOOLS = {
    '1': {'name': 'Nikto',         'module': nikto,    'available': nikto.is_available},
    '2': {'name': 'Gobuster',      'module': gobuster, 'available': gobuster.is_available},
    '3': {'name': 'OWASP ZAP',     'module': zap,      'available': zap.is_available},
    '4': {'name': 'SlowHTTPTest',  'module': slowhttp, 'available': slowhttp.is_available},
}


def _separator(char='─', width=60):
    print(char * width)


def _header():
    _separator('═')
    print("  🔒  Night — Nginx Security Test Suite")
    _separator('═')


def _print_tools_status():
    print("\n  Available tools:")
    for key, tool in TOOLS.items():
        available = tool['available']()
        status = "✔ installed" if available else "✗ not installed"
        print(f"    {key}) {tool['name']:15s}  {status}")
    print()


def _select_tools():
    """Let user pick which tools to run. Returns list of keys."""
    _print_tools_status()
    print("  Select tools to run:")
    print("    a) All tools")
    print("    Or enter numbers separated by space (e.g. 1 3 4)")
    print()
    choice = input("  Selection [a]: ").strip().lower() or 'a'

    if choice == 'a':
        return list(TOOLS.keys())

    selected = []
    for part in choice.split():
        if part in TOOLS:
            selected.append(part)
        else:
            print(f"  [!] Unknown tool '{part}', skipping.")
    return selected


def env_menu(args):
    """Handle environment sub-commands."""
    subcmd = args[0] if args else None

    if subcmd == 'status':
        environment.print_status()
    elif subcmd in ('setup', 'start'):
        url = environment.ensure_environment()
        if url:
            print(f"\n[+] Test environment ready at: {url}")
    elif subcmd == 'stop':
        environment.stop_container()
    elif subcmd == 'remove':
        environment.remove_container()
    else:
        print("\n  Environment management:")
        print("    night test env status   — Show current status")
        print("    night test env setup    — Deploy DVWA")
        print("    night test env start    — Start existing DVWA container")
        print("    night test env stop     — Stop DVWA container")
        print("    night test env remove   — Remove DVWA container")


def run_tests(target_url=None, selected_keys=None, output_dir=None):
    """Run the selected security tests against target."""
    _header()
    print()

    # Resolve target
    if not target_url:
        print("  Test target URL:")
        print("  (Leave blank to auto-start DVWA at http://127.0.0.1:8080)")
        target_url = input("  Target URL: ").strip()

    if not target_url:
        print("\n[*] Starting DVWA test environment...")
        target_url = environment.ensure_environment()
        if not target_url:
            print("[-] Could not start test environment. Exiting.")
            return

    print(f"\n  Target: {target_url}")

    # Resolve output dir
    if not output_dir:
        output_dir = input(f"\n  Report output directory [{DEFAULT_OUTPUT_DIR}]: ").strip() or DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    # Select tools
    if not selected_keys:
        selected_keys = _select_tools()

    if not selected_keys:
        print("[-] No tools selected.")
        return

    print(f"\n  Running {len(selected_keys)} tool(s)...")
    _separator()

    results = []
    for key in selected_keys:
        tool = TOOLS.get(key)
        if not tool:
            continue

        if not tool['available']():
            print(f"\n[!] {tool['name']} is not installed — skipping.")
            print(f"    Run the install script to install it.")
            continue

        result = tool['module'].interactive_run(target_url, output_dir)
        if result:
            if isinstance(result, list):
                results.extend(result)
            else:
                results.append(result)
        _separator()

    # Generate report
    if results:
        print("\n[*] Generating unified report...")
        report_file = report.generate(results, target_url, output_dir)
        print(f"[+] Report saved to: {report_file}")
        print(f"\n    Open in browser:  file://{report_file}")
    else:
        print("\n[!] No results to report.")


def main(args=None):
    """Entry point for 'night test' command."""
    if args is None:
        args = sys.argv[1:]

    # Remove 'test' or 't' from args if called via night CLI
    if args and args[0] in ('test', 't'):
        args = args[1:]

    if args and args[0] == 'env':
        env_menu(args[1:])
        return

    if args and args[0] == 'run':
        target = args[1] if len(args) > 1 else None
        run_tests(target_url=target)
        return

    # Interactive mode
    _header()
    print()
    print("  Commands:")
    print("    1) Run security tests")
    print("    2) Manage test environment (DVWA)")
    print("    3) Check tool installation status")
    print("    q) Quit")
    print()
    choice = input("  Select option: ").strip().lower()

    if choice == '1':
        run_tests()
    elif choice == '2':
        print()
        print("  Environment actions:")
        print("    1) Start / deploy DVWA")
        print("    2) Show status")
        print("    3) Stop DVWA")
        print()
        ec = input("  Select: ").strip()
        if ec == '1':
            env_menu(['setup'])
        elif ec == '2':
            env_menu(['status'])
        elif ec == '3':
            env_menu(['stop'])
    elif choice == '3':
        _print_tools_status()
    elif choice == 'q':
        return
    else:
        print("  Invalid option.")


if __name__ == '__main__':
    main()