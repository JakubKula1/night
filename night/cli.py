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

    console.print(f"[bold red][!] Found {len(results)} misconfigurations:[/bold red]\n")
    for res in results:
        console.print(f"  [red]✗ {res['rule']}[/red]")
        console.print(f"    [yellow]Description:[/yellow] {res['description']}")
        console.print(f"    [dim]File: {res['file']} (Line: {res['line']})[/dim]\n")



@cli.command()
@click.argument('config_path', type=click.Path(), default='/etc/nginx/nginx.conf')
def harden(config_path):
    """Generate a hardened Nginx configuration file."""
    if os.geteuid() != 0:
        console.print("[bold red][✗] Error: You must run 'harden' with sudo to modify files.[/bold red]")
        return

    console.print(f"[bold yellow][*] Hardening {config_path}...[/bold yellow]")
    # TODO implement conf hardening module


@cli.command()
@click.argument('script_path', type=click.Path(), default='./testing/test_all.py')
def test(script_path):
    """Run a test suite on your Nginx instance."""
    # TODO implement test module
    pass


@cli.command()
def protect():
    """Implement active protection modules."""
    if os.geteuid() != 0:
        console.print("[bold red][✗] Error: You must run 'protect' with sudo to implement certain changes.[/bold red]")
        return

    from .protection.menu import run as active_defense_menu
    active_defense_menu()


if __name__ == '__main__':
    cli()