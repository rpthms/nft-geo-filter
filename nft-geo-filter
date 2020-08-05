#!/usr/bin/env python3

# Python script for updating the nftables blacklist sets

import os
import subprocess
import sys
import tempfile
import argparse
import textwrap
import urllib.request
import urllib.error

#Binaries
NFT = '/usr/sbin/nft'

#Temp File Header
FILE_HEADER = ('table {} {} {{\n'
               'set {} {{\n'
               'type {}\n'
               'flags interval\n'
               'auto-merge\n')

IPDENY_V4_URL= 'http://ipdeny.com/ipblocks/data/aggregated/{}-aggregated.zone'
IPDENY_V6_URL= 'http://ipdeny.com/ipv6/ipaddresses/aggregated/{}-aggregated.zone'

# Set all the required variables in the 'conf' dictionary
def set_variables(args):
    conf = dict()

    if args.inet_table:
        conf['IP_FAMILY'] = 'inet'
        conf['IP6_FAMILY'] = 'inet'
        conf['IP_TABLE_NAME'] = args.inet_table
        conf['IP6_TABLE_NAME'] = args.inet_table
    elif args.ip_table and args.ip6_table:
        conf['IP_FAMILY'] = 'ip'
        conf['IP6_FAMILY'] = 'ip6'
        conf['IP_TABLE_NAME'] = args.ip_table
        conf['IP6_TABLE_NAME'] = args.ip6_table
    elif args.ip_table:
        conf['IP_FAMILY'] = 'ip'
        conf['IP_TABLE_NAME'] = args.ip_table
    elif args.ip6_table:
        conf['IP6_FAMILY'] = 'ip6'
        conf['IP6_TABLE_NAME'] = args.ip6_table
    else:
        conf['IP_FAMILY'] = 'inet'
        conf['IP6_FAMILY'] = 'inet'
        conf['IP_TABLE_NAME'] = 'filter'
        conf['IP6_TABLE_NAME'] = 'filter'

    if args.blacklist_prefix:
        conf['BLACKLIST_PREFIX'] = args.blacklist_prefix
    else:
        conf['BLACKLIST_PREFIX'] = 'blacklist'

    if args.country:
        conf['COUNTRY_CODES'] = [c.lower() for c in args.country]

    return conf


def flush_blacklist(addr_family, nft_family, table, blacklist_prefix):
    if addr_family == 'AF_INET':
        set_name = "{}-v4".format(blacklist_prefix)
    elif addr_family == 'AF_INET6':
        set_name = "{}-v6".format(blacklist_prefix)
    else:
        print("addr_family is invalid!")
        return 1

    nft_command_tmpl = "{} flush set {} {} {}"

    # Flush the existing contents of the blacklist sets. The sets may or may
    # not exist, because of which the following subprocess.run call may
    # exit with a non zero code. I couldn't figure out a way to find if a
    # set exists without having to list the entire contents of a set.
    #
    # So, for now, I'm running the flush command anyways and checking the
    # output of the command. If the stderr contains 'No such file', that probably
    # means that the set doesn't exist, so print an appropriate message. If we
    # get anything else in the stdout or stderr of the flush command, print it
    # verbatim.
    print('Flushing {}..'.format(set_name))
    nft_command = nft_command_tmpl.format(NFT, nft_family, table, set_name).split()
    proc = subprocess.run(nft_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout = proc.stdout.decode('utf-8')
    if "No such file" in stdout:
        print('{} does not exist, skipping!'.format(set_name))
    elif stdout:
        print(stdout)

def update_blacklist(addr_family, nft_family, table, blacklist_prefix, country_codes):
    if addr_family == 'AF_INET':
        ipdeny_url = IPDENY_V4_URL
        set_type = "ipv4_addr"
        set_name = "{}-v4".format(blacklist_prefix)
        print_family = "IPv4"
    elif addr_family == 'AF_INET6':
        ipdeny_url = IPDENY_V6_URL
        set_type = "ipv6_addr"
        set_name = "{}-v6".format(blacklist_prefix)
        print_family = "IPv6"
    else:
        print("addr_family is invalid!")
        return 1

    for c in country_codes:
        print('Downloading "{}" {} blocks..'.format(c, print_family))
        try:
            ip_blocks = urllib.request.urlopen(ipdeny_url.format(c))
        except urllib.error.HTTPError as err:
            print("Couldn't GET {}: {} {}".format(ipdeny_url.format(c), err.code, err.reason))
            continue

        print('Building list of {} blocks..'.format(print_family))
        data = ip_blocks.read().decode('utf-8')
        blacklist_ips = ',\n'.join(data.splitlines())

        blacklist_ips = ''.join(('elements = {\n', blacklist_ips, '\n}\n}\n}'))

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write(FILE_HEADER.format(nft_family, table, set_name, set_type))
            tmp.write(blacklist_ips)

        print('Adding the "{}" {} blocks to {}..'.format(c, print_family, set_name))
        subprocess.run([NFT, '-f', tmp.name])

        # Delete the tmp file
        os.remove(tmp.name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add country based blacklist sets for nftables')

    # Version
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 2.0")

    # Optional arguments
    table_group = parser.add_argument_group(
        title="Table",
        description=textwrap.dedent("""Choose the family and table name to create the blacklist set in. If
                    --inet-table is chosen, then the blacklist set will be created in the inet family which
                    can be used by both v4 and v6 addresses. You cannot specify --inet-table along with
                    --ip-table and --ip6-table. An --inet-table called 'filter' will be used by default""")
    )
    table_group.add_argument("-4", "--ip-table",
        help="Name of the ip table which will contain the v4 blacklist set")
    table_group.add_argument("-6", "--ip6-table",
        help="Name of the ip6 table which will contain the v6 blacklist set")
    table_group.add_argument("-i", "--inet-table",
        help="Name of the inet table which will contain the v4 and v6 blacklist sets")

    blacklist_group = parser.add_argument_group(
        title="Blacklist",
        description=textwrap.dedent("""Provide the prefix to be used for the blacklist sets. The blacklist sets
                    will be called <prefix>-v4 or <prefix>-v6 depending on which address family is used by the
                    set. 'blacklist' will be used as the default blacklist prefix.""")
    )
    blacklist_group.add_argument("-b", "--blacklist-prefix", help="Name of the blacklist prefix")

    # Mandatory arguments
    parser.add_argument("country", nargs='+',
        help=textwrap.dedent("""2 letter ISO-3166-1 alpha-2 country codes to block. Check
            ipdeny.com/ipblocks/ to find the list of supported countries.""")
    )

    args = parser.parse_args()
    if args.inet_table and (args.ip6_table or args.ip_table):
        sys.exit("Can't use --inet-table with --ip-table or --ip6-table!")

    if not os.geteuid() == 0:
        sys.exit('Need root privileges to run this script!')

    # Set proper variables
    conf = set_variables(args)

    # Start updating the blacklists!
    if 'IP_FAMILY' in conf and 'IP_TABLE_NAME' in conf:
        flush_blacklist("AF_INET", conf['IP_FAMILY'],
            conf['IP_TABLE_NAME'], conf['BLACKLIST_PREFIX'])
        update_blacklist("AF_INET", conf['IP_FAMILY'], conf['IP_TABLE_NAME'],
            conf['BLACKLIST_PREFIX'], conf['COUNTRY_CODES'])
    if 'IP6_FAMILY' in conf and 'IP6_TABLE_NAME' in conf:
        flush_blacklist("AF_INET6", conf['IP6_FAMILY'],
            conf['IP6_TABLE_NAME'], conf['BLACKLIST_PREFIX'])
        update_blacklist("AF_INET6", conf['IP6_FAMILY'], conf['IP6_TABLE_NAME'],
            conf['BLACKLIST_PREFIX'], conf['COUNTRY_CODES'])

    print('Done!')
