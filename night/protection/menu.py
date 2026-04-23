import os
from rich.console import Console
from rich.table import Table
from rich import box


console = Console()


def _import_modules():
    from . import tls, ufw, ips, waf
    return tls, ufw, ips, waf


def _status_icon(ok: bool) -> str:
    return "[bold green]✔[/bold green]" if ok else "[bold red]✘[/bold red]"


def _print_header(tls_mod, fw_mod, ips_mod, waf_mod) -> None:
    tls_s = tls_mod.status()
    fw_s = fw_mod.status()
    ips_s = ips_mod.status()
    waf_s = waf_mod.status()

    certbot_ok = tls_s.get("certbot_installed", False)
    certs = tls_s.get("certificates", [])
    ufw_ok = fw_s["ufw"].get("active", False)
    nft_ok = fw_s["nftables"].get("service_active", False)
    f2b_ok = ips_s.get("active", False)
    jails = ips_s.get("jails", [])
    lib_ok = waf_s.get("lib_installed", False)
    engine_mode = waf_s.get("engine_mode", "unknown")

    table = Table(title="Active Defense – Security Overview", box=box.DOUBLE_EDGE, expand=True)
    table.add_column("Module", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    table.add_row("TLS", f"Certbot {_status_icon(certbot_ok)}", f"Certs: {', '.join(certs) or 'None'}")
    table.add_row("Firewall", f"UFW {_status_icon(ufw_ok)}", f"nftables: {_status_icon(nft_ok)}")
    table.add_row("IPS", f"Fail2ban {_status_icon(f2b_ok)}", f"Active Jails: {len(jails)}")
    table.add_row("WAF", f"ModSec {_status_icon(lib_ok)}", f"Engine: {engine_mode}")
    console.print(table)


def run() -> None:
    tls_mod, fw_mod, ips_mod, waf_mod = _import_modules()

    while True:
        try:
            #os.system("clear")
            _print_header(tls_mod, fw_mod, ips_mod, waf_mod)
            console.print("  [bold cyan][1][/bold cyan] TLS          – Certbot certificate + hardened SSL/TLS")
            console.print("  [bold cyan][2][/bold cyan] Firewall     – UFW rules + nftables base ruleset")
            console.print("  [bold cyan][3][/bold cyan] IPS          – Fail2ban filters, jails & ban management")
            console.print("  [bold cyan][4][/bold cyan] WAF          – ModSecurity + OWASP CRS")
            console.print("  [bold cyan][5][/bold cyan] Deploy ALL   – Apply sensible defaults for everything")
            console.print("  [bold cyan]\\[q][/bold cyan] Exit\n")
            choice = input("  Select an option: ").strip().lower()

            if choice == "1":
                tls_mod.run_interactive()
            elif choice == "2":
                fw_mod.run_interactive()
            elif choice == "3":
                ips_mod.run_interactive()
            elif choice == "4":
                waf_mod.run_interactive()
            elif choice == "5":
                _deploy_all(tls_mod, fw_mod, ips_mod, waf_mod)
            elif choice == "q":
                break
            else:
                console.print("[yellow]  Invalid option.[/yellow]")
                input("  Press Enter to continue...")

        except KeyboardInterrupt:
            console.print("\n[yellow][!] Operation cancelled by user.[/yellow]")
            break


def _deploy_all(tls_mod, fw_mod, ips_mod, waf_mod) -> None:
    console.print(f"\n[bold]── Full Active Defense Deploy ──────────────────────────[/bold]\n")
    console.print("  This will configure UFW, nftables, Fail2ban, and ModSecurity")
    console.print("  with sensible defaults.  TLS requires a domain + admin e-mail.\n")

    # --- Firewall ---
    console.print(f"[cyan][1/4] Firewall[/cyan]")
    ufw = fw_mod.UFWManager()
    ufw.reset_and_apply_defaults(allow_ssh=True)
    #nft = fw_mod.NftablesManager()
    #nft.write_base_ruleset()

    # --- IPS ---
    console.print(f"\n[cyan][2/4] IPS – Fail2ban[/cyan]")
    ips_mod.deploy(bantime="1d", findtime="1d", maxretry=5)

    # --- WAF ---
    console.print(f"\n[cyan][3/4] WAF – ModSecurity (Detection-Only)[/cyan]")
    waf_mod._mgr.deploy(engine_mode="DetectionOnly", paranoia_level=1)

    # --- TLS (optional) ---
    console.print(f"\n[cyan][4/4] TLS – Let's Encrypt (optional)[/cyan]")
    domain = input("  Domain name (blank to skip TLS): ").strip()
    if domain:
        email = input("  Admin e-mail: ").strip()
        if tls_mod.obtain_certificate([domain, f"www.{domain}"], email):
            tls_mod.harden_nginx_ssl(domain)
        else:
            console.print("[bold red][!] TLS Deployment failed. Aborting Nginx SSL block generation to prevent crashes.[/bold red]")

    # TODO implement error counting (listing only succesfull deployments)
    console.print(f"\n[bold green]✔ Active Defense deployment complete![/bold green]")
    console.print("  Review /etc/nginx/modsec/modsecurity.conf and set")
    console.print("  SecRuleEngine On when you are ready to enforce WAF rules.\n")
    input("  Press Enter to continue...")


if __name__ == "__main__":
    run()