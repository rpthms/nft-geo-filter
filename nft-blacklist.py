#!/usr/bin/env python3

# Python script for updating the nftables blacklist

import urllib.request
import subprocess

#Binaries
NFT = '/usr/sbin/nft'
    
#nftables Variables (Change accordingly)
TABLE = 'filter'
SET_NAME = 'blacklist'

IPDENY_URL= 'http://www.ipdeny.com/ipblocks/data/countries/'
COUNTRY_CODES = ('cn','ru')  #Check ipdeny.com for the country codes

def main():
    for c in COUNTRY_CODES:
        print('Downloading "{}" IP blocks..'.format(c))
        ip_blocks = urllib.request.urlopen(''.join((IPDENY_URL,c,'.zone')))
        
        print('Building list of IP blocks..')
        data = ip_blocks.read().decode('utf-8')
        blacklist_ips = ','.join([i for i in data.splitlines()])
        blacklist_ips = ''.join(('{', blacklist_ips, '}'))
        
        print('Adding the "{}" IP blocks to the blacklist..'.format(c))
        subprocess.run([NFT, 'add element', TABLE, SET_NAME, blacklist_ips])
    
    print('Done!')

if __name__ == '__main__':
    main()
