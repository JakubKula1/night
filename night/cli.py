import os
import click
from pygments.styles import default
from rich.console import Console
from .core.scanner import Scanner
from .core.parser import NginxParser


console = Console()

BANNER = """[bold cyan]
  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝      
[/bold cyan][dim]Nginx Integrated Guard & Hardening Toolkit\n------------------------------------------[/dim]
"""


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv

        aliases = {
            's': 'scan',
            'h': 'harden',
            't': 'test',
            'p': 'protect',
        }
        if cmd_name in aliases:
            return click.Group.get_command(self, ctx, aliases[cmd_name])

        return None


@click.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """NIGHT - Nginx Integrated Guard & Hardening Toolkit"""
    console.print(BANNER)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@cli.command()
@click.argument('config_path', type=click.Path(exists=True), default='/etc/nginx/nginx.conf')
def scan(config_path):
    """Scan an Nginx configuration for vulnerabilities."""
    console.print(f"[bold blue][*] Starting NIGHT scan on {config_path}...[/bold blue]")

    parser = NginxParser(config_path)
    payload = parser.parse()

    scanner = Scanner(payload)
    results = scanner.run_all_checks()

    if not results:
        console.print("[bold green][+] No vulnerabilities found! Nginx is secure.[/bold green]")
        return

    total_issues = sum(len(res['occurrences']) for res in results)
    console.print(f"[bold red][!] Found {total_issues} misconfigurations:[/bold red]\n")
    for res in results:
        console.print(f"  [red]x {res['rule']}[/red]")
        console.print(f"    [yellow]Description:[/yellow] {res['description']}")
        for occ in res['occurrences']:
            console.print(f"    [dim]File: {occ['file']} (Line: {occ['line']})[/dim]")
        console.print()



@cli.command()
@click.argument('config_path', type=click.Path(), default='/etc/nginx/nginx.conf')
#@click.option('--dry-run', is_flag=True, default=False)
def harden(config_path):
    """Generate a hardened Nginx configuration file."""
    if os.geteuid() != 0:
        console.print("[bold red][x] Error: You must run 'harden' with sudo to modify files.[/bold red]")
        return

    from .harden.harden import harden_config
    summary = harden_config(config_path)

    console.print("\n[bold]-- Hardening Summary --------------------------------[/bold]")
    console.print(f"  Findings detected : [yellow]{summary['findings']}[/yellow]")
    console.print(f"  Files patched     : [green]{summary['files_patched']}[/green]")

    if summary.get('applied'):
        console.print("  Applied fixes:")
        for fix in summary['applied']:
            if 'MANUAL REVIEW' in fix:
                console.print(f"    [yellow]• {fix}[/yellow]")
            else:
                console.print(f"    [green]•[/green] {fix}")

    if summary.get('skipped'):
        console.print("  Skipped files (not on disk):")
        for s in summary['skipped']:
            console.print(f"    [dim]•[/dim] {s}")


@cli.command(context_settings=dict(
    ignore_unknown_options=True,
    allow_extra_args=True,
))
@click.pass_context
def test(ctx):
    """Run a test suite on your Nginx instance."""
    from .testing.menu import main as testing_menu
    testing_menu(ctx.args)


@cli.command()
def protect():
    """Implement active protection modules."""
    if os.geteuid() != 0:
        console.print("[bold red][x] Error: You must run 'protect' with sudo to implement certain changes.[/bold red]")
        return

    from .protection.menu import run as active_defense_menu
    active_defense_menu()


if __name__ == '__main__':
    cli()