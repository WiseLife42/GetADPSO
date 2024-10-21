#!/usr/bin/env python3
import argparse
import logging
from ldap3 import Server, Connection, ALL, NTLM, KERBEROS, SUBTREE
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPBindError
from rich.table import Table
from rich.console import Console
from dateutil.relativedelta import relativedelta as rd

console = Console()

def base_creator(domain):
    return ','.join([f"DC={part}" for part in domain.split('.')])

def clock(nano):
    fmt = '{0.days} days {0.hours} hours {0.minutes} minutes {0.seconds} seconds'
    sec = int(abs(nano / 10000000))
    return fmt.format(rd(seconds=sec))

def setup_logging(debug=False):
    logging_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')

def create_connection(server_address, user, password, use_ssl=False, auth_method=NTLM, ccache_file=None, verbose=False):
    try:
        # Utiliser LDAPS (port 636) si use_ssl=True
        server = Server(server_address, get_info=ALL, use_ssl=use_ssl)
        if auth_method == KERBEROS and ccache_file:
            if verbose:
                console.log(f"[yellow][D][/yellow] Using Kerberos with ccache file: {ccache_file}")
            conn = Connection(server, authentication=KERBEROS, sasl_mechanism='GSSAPI')
        else:
            conn = Connection(server, user=user, password=password, authentication=auth_method, auto_bind=True)

        if verbose:
            console.log(f"[green][+][/green] Connected to {server_address} with {auth_method}")
        return conn
    except LDAPSocketOpenError:
        if verbose:
            console.log(f"[bold red][-][/bold red] Could not connect to {server_address}")
        return None
    except LDAPBindError as e:
        if verbose:
            console.log(f"[bold red][-][/bold red] Failed to bind to {server_address}: {str(e)}")
        return None

def get_user_attributes(username, password, domain, dc_host=None, kerberos=False, ccache_file=None, verbose=False):
    user = f'{domain}\\{username}' if not kerberos else None
    server_address = f'{dc_host}:389' if dc_host else f'{domain}:389'

    auth_method = KERBEROS if kerberos else NTLM

    conn = create_connection(server_address, user, password, auth_method=auth_method, ccache_file=ccache_file, verbose=verbose)
    if not conn:
        if verbose:
            console.log("[bold red][-][/bold red] LDAP on port 389 failed, trying LDAPS on port 636...")
        server_address = f'{dc_host}:636' if dc_host else f'{domain}:636'
        conn = create_connection(server_address, user, password, use_ssl=True, auth_method=auth_method, ccache_file=ccache_file, verbose=verbose)

    if not conn:
        if verbose:
            console.log("[bold red][-][/bold red] Both LDAP and LDAPS connection attempts failed.")
        return

    search_base = 'DC=' + ',DC='.join(domain.split('.'))
    search_filter = '(objectClass=user)'

    conn.search(search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'msDS-ResultantPSO'])

    table = Table(title="Users with PSO Applied")
    table.add_column("Users", justify="left", style="cyan", no_wrap=True)
    table.add_column("PSO", justify="left", style="green")

    for entry in conn.entries:
        if 'msDS-ResultantPSO' in entry and entry['msDS-ResultantPSO']:
            sam_account_name = entry.sAMAccountName.value if 'sAMAccountName' in entry else 'N/A'
            msds_resultant_pso = str(entry['msDS-ResultantPSO'])
            pso_name = msds_resultant_pso.split(',')[0].split('=')[1]

            table.add_row(sam_account_name, pso_name)

    console.print(table)
    if verbose:
        console.log("[green][+][/green] Successfully retrieved user PSO attributes.")
    conn.unbind()

def get_group_pso(username, password, domain, dc_host=None, kerberos=False, ccache_file=None, verbose=False):
    user = f'{domain}\\{username}' if not kerberos else None
    server_address = f'{dc_host}:389' if dc_host else f'{domain}:389'

    auth_method = KERBEROS if kerberos else NTLM

    conn = create_connection(server_address, user, password, auth_method=auth_method, ccache_file=ccache_file, verbose=verbose)
    if not conn:
        if verbose:
            console.log("[bold red][-][/bold red] LDAP on port 389 failed, trying LDAPS on port 636...")
        server_address = f'{dc_host}:636' if dc_host else f'{domain}:636'
        conn = create_connection(server_address, user, password, use_ssl=True, auth_method=auth_method, ccache_file=ccache_file, verbose=verbose)

    if not conn:
        if verbose:
            console.log("[bold red][-][/bold red] Both LDAP and LDAPS connection attempts failed.")
        return

    search_base = 'DC=' + ',DC='.join(domain.split('.'))
    search_filter = '(objectClass=group)'

    conn.search(search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['cn', 'msDS-PSOApplied'])

    table = Table(title="Groups with PSO Applied")
    table.add_column("Groups", justify="left", style="cyan", no_wrap=True)
    table.add_column("PSO", justify="left", style="green")

    for entry in conn.entries:
        if 'msDS-PSOApplied' in entry and entry['msDS-PSOApplied']:
            name = entry.cn.value
            msds_pso_applied = str(entry['msDS-PSOApplied'])
            pso_name = msds_pso_applied.split(',')[0].split('=')[1]

            table.add_row(name, pso_name)

    console.print(table)
    if verbose:
        console.log("[green][+][/green] Successfully retrieved group PSO attributes.")
    conn.unbind()

def get_pso_details(username, password, domain, dc_host=None, verbose=False):
    user = f'{domain}\\{username}'
    server_address = f'{dc_host}:389' if dc_host else f'{domain}:389'  # Essayer d'abord sur le port 389 (LDAP)

    auth_method = NTLM

    # Essayer la connexion sur le port LDAP (389)
    conn = create_connection(server_address, user, password, auth_method=auth_method, verbose=verbose)
    if not conn:
        if verbose:
            console.log("[bold red][-][/bold red] LDAP on port 389 failed, trying LDAPS on port 636...")
        # Si la connexion LDAP échoue, tenter avec LDAPS sur le port 636
        server_address = f'{dc_host}:636' if dc_host else f'{domain}:636'
        conn = create_connection(server_address, user, password, use_ssl=True, auth_method=auth_method, verbose=verbose)

    if not conn:
        if verbose:
            console.log("[bold red][-][/bold red] Both LDAP and LDAPS connection attempts failed.")
        return

    search_base = f'CN=Password Settings Container,CN=System,{base_creator(domain)}'
    search_filter = '(objectclass=msDS-PasswordSettings)'

    conn.search(search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    'name', 'msds-lockoutthreshold', 'msds-psoappliesto', 'msds-minimumpasswordlength',
                    'msds-passwordhistorylength', 'msds-lockoutobservationwindow', 'msds-lockoutduration',
                    'msds-passwordsettingsprecedence', 'msds-passwordcomplexityenabled', 'description',
                    'msds-passwordreversibleencryptionenabled', 'msds-minimumpasswordage', 'msds-maximumpasswordage'
                ])

    if len(conn.entries) > 0:
        for entry in conn.entries:
            # Créer un tableau distinct pour chaque PSO
            table = Table(title=f"PSO Details: {entry['name'].value}", show_header=True, header_style="bold magenta")
            table.add_column("Attribute", justify="left", style="cyan")
            table.add_column("Value", justify="left", style="green")

            table.add_row("Policy Name", entry['name'].value)
            if 'description' in entry:
                table.add_row("Description", entry['description'].value)

            table.add_row("Minimum Password Length", str(entry['msds-minimumpasswordlength'].value))
            table.add_row("Password History Length", str(entry['msds-passwordhistorylength'].value))
            table.add_row("Lockout Threshold", str(entry['msds-lockoutthreshold'].value))
            table.add_row("Observation Window", clock(int(entry['msds-lockoutobservationwindow'].value)) if 'msds-lockoutobservationwindow' in entry else 'N/A')
            table.add_row("Lockout Duration", clock(int(entry['msds-lockoutduration'].value)) if 'msds-lockoutduration' in entry else 'N/A')
            table.add_row("Password Complexity Enabled", str(entry['msds-passwordcomplexityenabled'].value))
            table.add_row("Minimum Password Age", clock(int(entry['msds-minimumpasswordage'].value)) if 'msds-minimumpasswordage' in entry else 'N/A')
            table.add_row("Maximum Password Age", clock(int(entry['msds-maximumpasswordage'].value)) if 'msds-maximumpasswordage' in entry else 'N/A')
            table.add_row("Reversible Encryption Enabled", str(entry['msds-passwordreversibleencryptionenabled'].value))
            table.add_row("Password Settings Precedence", str(entry['msds-passwordsettingsprecedence'].value))

            if 'msds-psoappliesto' in entry:
                for dn in entry['msds-psoappliesto']:
                    table.add_row("Policy Applies to", dn)

            # Afficher chaque tableau distinctement
            console.print(table)

        if verbose:
            console.log("[green][+][/green] Successfully retrieved PSO details.")
    else:
        if verbose:
            console.print("[bold red]Could not enumerate details, you likely do not have the privileges to do so![/bold red]")

    conn.unbind()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Script to retrieve the msDS-ResultantPSO attribute for all users and groups in Active Directory, and show the details of PSO policies.'
    )
    parser.add_argument('-u', '--username', help='Username for Active Directory', required=True)
    parser.add_argument('-p', '--password', help='Password for Active Directory', required=True)
    parser.add_argument('-d', '--domain', required=True, help='Domain for Active Directory')
    parser.add_argument('--dc-host', help='Domain Controller hostname or IP address')
    parser.add_argument('--kerberos', action='store_true', help='Use Kerberos authentication')
    parser.add_argument('--ccache', help='Path to Kerberos ccache file')
    parser.add_argument('-v', '--debug', action='store_true', help='Enable debug logging for more details')

    args = parser.parse_args()

    setup_logging(args.debug)

    # Display groups with PSO applied
    get_group_pso(args.username, args.password, args.domain, args.dc_host, kerberos=args.kerberos, ccache_file=args.ccache, verbose=args.debug)

    # Display users with PSO applied
    get_user_attributes(args.username, args.password, args.domain, args.dc_host, kerberos=args.kerberos, ccache_file=args.ccache, verbose=args.debug)

    # Display PSO details
    get_pso_details(args.username, args.password, args.domain, dc_host=args.dc_host, verbose=args.debug)
