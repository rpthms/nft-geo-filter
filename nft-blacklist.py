#!/usr/bin/env python3

# Python script for updating the nftables blacklist

import urllib.request
import subprocess
import tempfile

#Binaries
NFT = '/usr/sbin/nft'

#nftables Variables (Change accordingly)
FAMILY = 'ip'
TABLE = 'filter'
SET_NAME = 'blacklist'

#Temp File Header
FILE_HEADER = ('table {} {} {{\n'
               'set {} {{\n'
               'type ipv4_addr\n'
               'flags interval\n')

IPDENY_URL= 'http://www.ipdeny.com/ipblocks/data/countries/{}.zone'
COUNTRY_CODES = ('cn','ru')  #Check ipdeny.com for the country codes

def update_blacklist():
    for c in COUNTRY_CODES:
        print('Downloading "{}" IP blocks..'.format(c))
        ip_blocks = urllib.request.urlopen(IPDENY_URL.format(c))

        print('Building list of IP blocks..')
        data = ip_blocks.read().decode('utf-8')
        blacklist_ips = ',\n'.join(data.splitlines())
        blacklist_ips = ''.join(('elements = {', blacklist_ips, '}\n}\n}\n'))

        with tempfile.NamedTemporaryFile(mode='w') as tmp:
            tmp.write(FILE_HEADER.format(FAMILY, TABLE, SET_NAME))
            tmp.write(blacklist_ips)

            print('Adding the "{}" IP blocks to the blacklist..'.format(c))
            subprocess.run([NFT, '-f', tmp.name])

    print('Done!')

if __name__ == '__main__':
    update_blacklist()
