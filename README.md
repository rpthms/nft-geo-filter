# nft-blacklist
Blacklist country specific IP blocks using nftables

NOTE : IPv6 addresses are not supported at the moment.

# Requirements
To use this script, you will need to create a 'set' in your nftables configuration with the `type ipv4_addr` and `flags interval` set properties. This set can belong to any table in your nftables configuration and is responsible for holding the blacklisted IP addresses. The syntax to create a set is :

`nft add set [table] [set-name] {set properties}`

Please refer the nftables wiki for more info on set operations: https://wiki.nftables.org/wiki-nftables/index.php/Sets

# Configuration

Edit the TABLE and SET\_NAME accordingly in the nft-blacklist.py. Then edit the COUNTRY\_CODES tuple and add the 2 letter codes for the countries you wish to restrict access to. Refer http://www.ipdeny.com/ipblocks/data/countries/ for the list of countries.

# Usage

After making the necessary configurations, run the script. The script will update your set with the blacklisted IP blocks, after which you can use the set to restrict access with a rule similar to the one below:

`nft add rule ip filter input ip saddr @blacklist drop`

# Example

A sample nftables configuration file is shown below for assistance:

```
#!/usr/sbin/nft -f

flush ruleset

table ip filter {
        set blacklist {
                type ipv4_addr
                flags interval
        }

        chain input {
                type filter hook input priority 0;

                iifname lo accept
                ct state established,related accept
                ip saddr @blacklist drop
                ip protocol icmp accept
                tcp dport {http, https, ssh} ct state new accept
                drop
        }
}
```
