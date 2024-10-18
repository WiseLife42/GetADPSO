#!/usr/bin/env python3
import argparse
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from dateutil.relativedelta import relativedelta as rd
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPBindError

def base_creator(domain):
    return ','.join([f"DC={part}" for part in domain.split('.')])

def clock(nano):
    fmt = '{0.days} days {0.hours} hours {0.minutes} minutes {0.seconds} seconds'
    sec = int(abs(nano / 10000000))
    return fmt.format(rd(seconds=sec))

def create_connection(server_address, user, password, use_ssl=False):
    try:
        # Attempt connection on port 389 for LDAP, or 636 for LDAPS if use_ssl=True
        server = Server(server_address, get_info=ALL, use_ssl=use_ssl)
        conn = Connection(server, user=user, password=password, authentication=NTLM, auto_bind=True)
        return conn
    except LDAPSocketOpenError:
        print(f"Could not connect to {server_address}")
        return None
    except LDAPBindError as e:
        print(f"Failed to bind to {server_address}: {str(e)}")
        return None

def get_user_attributes(username, password, domain, dc_ip=None):
    user = f'{domain}\\{username}'
    server_address_ldap = f'{dc_ip}:389' if dc_ip else f'{domain}:389'
    server_address_ldaps = f'{dc_ip}:636' if dc_ip else f'{domain}:636'

    # Try connecting first with LDAP, then with LDAPS
    conn = create_connection(server_address_ldap, user, password)
    if not conn:
        print("LDAP on port 389 failed, trying LDAPS on port 636...")
        conn = create_connection(server_address_ldaps, user, password, use_ssl=True)

    if not conn:
        print("Both LDAP and LDAPS connection attempts failed.")
        return

    search_base = 'DC=' + ',DC='.join(domain.split('.'))
    search_filter = '(objectClass=user)'

    conn.search(search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'msDS-ResultantPSO'])

    results = []
    max_user_length = len("Users")
    max_pso_length = len("PSO")

    for entry in conn.entries:
        if 'msDS-ResultantPSO' in entry and entry['msDS-ResultantPSO']:
            sam_account_name = entry.sAMAccountName.value if 'sAMAccountName' in entry else 'N/A'
            msds_resultant_pso = str(entry['msDS-ResultantPSO'])
            pso_name = msds_resultant_pso.split(',')[0].split('=')[1]

            results.append((sam_account_name, pso_name))

            max_user_length = max(max_user_length, len(sam_account_name))
            max_pso_length = max(max_pso_length, len(pso_name))

    # ANSI escape sequences for coloring
    GREEN = '\033[92m'
    RESET = '\033[0m'

    header = f"| {'Users':<{max_user_length}} | {'PSO':<{max_pso_length}} |"
    separator = f"| {'-'*max_user_length} | {'-'*max_pso_length} |"

    print(header)
    print(separator)

    for sam_account_name, pso_name in results:
        print(f"| {GREEN}{sam_account_name:<{max_user_length}}{RESET} | {pso_name:<{max_pso_length}} |")

    conn.unbind()

def get_group_pso(username, password, domain, dc_ip=None):
    user = f'{domain}\\{username}'
    server_address_ldap = f'{dc_ip}:389' if dc_ip else f'{domain}:389'
    server_address_ldaps = f'{dc_ip}:636' if dc_ip else f'{domain}:636'

    # Try connecting first with LDAP, then with LDAPS
    conn = create_connection(server_address_ldap, user, password)
    if not conn:
        print("LDAP on port 389 failed, trying LDAPS on port 636...")
        conn = create_connection(server_address_ldaps, user, password, use_ssl=True)

    if not conn:
        print("Both LDAP and LDAPS connection attempts failed.")
        return

    search_base = 'DC=' + ',DC='.join(domain.split('.'))
    search_filter = '(objectClass=group)'

    conn.search(search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['cn', 'msDS-PSOApplied'])

    results = []
    max_name_length = len("Groups")
    max_pso_length = len("PSO")

    for entry in conn.entries:
        if 'msDS-PSOApplied' in entry and entry['msDS-PSOApplied']:
            name = entry.cn.value
            msds_pso_applied = str(entry['msDS-PSOApplied'])
            pso_name = msds_pso_applied.split(',')[0].split('=')[1]

            results.append((name, pso_name))

            max_name_length = max(max_name_length, len(name))
            max_pso_length = max(max_pso_length, len(pso_name))

    # ANSI escape sequences for coloring
    GREEN = '\033[92m'
    RESET = '\033[0m'

    header = f"| {'Groups':<{max_name_length}} | {'PSO':<{max_pso_length}} |"
    separator = f"| {'-'*max_name_length} | {'-'*max_pso_length} |"

    print(header)
    print(separator)

    for name, pso_name in results:
        print(f"| {GREEN}{name:<{max_name_length}}{RESET} | {pso_name:<{max_pso_length}} |")

    conn.unbind()

def get_pso_details(username, password, domain, dc_ip=None):
    user = f'{domain}\\{username}'
    server_address_ldap = f'{dc_ip}:389' if dc_ip else f'{domain}:389'
    server_address_ldaps = f'{dc_ip}:636' if dc_ip else f'{domain}:636'

    # Try connecting first with LDAP, then with LDAPS
    conn = create_connection(server_address_ldap, user, password)
    if not conn:
        print("LDAP on port 389 failed, trying LDAPS on port 636...")
        conn = create_connection(server_address_ldaps, user, password, use_ssl=True)

    if not conn:
        print("Both LDAP and LDAPS connection attempts failed.")
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
        # ANSI escape sequences for coloring
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        RESET = '\033[0m'

        for entry in conn.entries:
            print(f"Policy Name: {BLUE}{entry['name'].value}{RESET}")
            if 'description' in entry:
                print(f"Description: {entry['description'].value}")
            print(f"Minimum Password Length: {CYAN}{entry['msds-minimumpasswordlength'].value}{RESET}")
            print(f"Password History Length: {CYAN}{entry['msds-passwordhistorylength'].value}{RESET}")
            print(f"Lockout Threshold: {CYAN}{entry['msds-lockoutthreshold'].value}{RESET}")
            print(f"Observation Window: {clock(int(entry['msds-lockoutobservationwindow'].value)) if 'msds-lockoutobservationwindow' in entry else 'N/A'}")
            print(f"Lockout Duration: {clock(int(entry['msds-lockoutduration'].value)) if 'msds-lockoutduration' in entry else 'N/A'}")
            print(f"Complexity Enabled: {entry['msds-passwordcomplexityenabled'].value}")
            print(f"Minimum Password Age: {clock(int(entry['msds-minimumpasswordage'].value)) if 'msds-minimumpasswordage' in entry else 'N/A'}")
            print(f"Maximum Password Age: {clock(int(entry['msds-maximumpasswordage'].value)) if 'msds-maximumpasswordage' in entry else 'N/A'}")
            print(f"Reversible Encryption: {entry['msds-passwordreversibleencryptionenabled'].value}")
            print(f"Precedence: {CYAN}{entry['msds-passwordsettingsprecedence'].value}{RESET}")
            if 'msds-psoappliesto' in entry:
                for dn in entry['msds-psoappliesto']:
                    print(f"Policy Applies to: {dn}")
            print("")
    else:
        print("Could not enumerate details, you likely do not have the privileges to do so!")

    conn.unbind()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Script to retrieve the msDS-ResultantPSO attribute for all users and groups in Active Directory who have this attribute defined, and show the details of the PSO policies.'
    )
    parser.add_argument('-u', '--username', required=True, help='Username for Active Directory')
    parser.add_argument('-p', '--password', required=True, help='Password for Active Directory')
    parser.add_argument('-d', '--domain', required=True, help='Domain for Active Directory')
    parser.add_argument('--dc-ip', required=True, help='Domain Controller IP address')

    args = parser.parse_args()

    print("Groups with PSO applied:")
    get_group_pso(args.username, args.password, args.domain, args.dc_ip)

    print("\nUsers with PSO applied:")
    get_user_attributes(args.username, args.password, args.domain, args.dc_ip)

    print("\nPSO Details:")
    try:
        get_pso_details(args.username, args.password, args.domain, args.dc_ip)
    except Exception as e:
        print(f"Could not enumerate details, you likely do not have the privileges to do so! Error: {e}")
