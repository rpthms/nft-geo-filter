# nft-blacklist
Blacklist country specific IP blocks using nftables

# Requirements
To use this script, you will need to create a 'set' in your nftables configuration. This set can belong to any table in your nftables configuration. The syntax to create a set is :

`nft add set [table] [set-name] {set properties}`

Please refer the nftables wiki for more info on set operations: https://wiki.nftables.org/wiki-nftables/index.php/Sets

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

# Configuration

Edit the TABLE and SET\_NAME accordingly in the nft-blacklist.py. Then edit the COUNTRY\_CODES tuple and add the 2 letter codes for the countries you wish to restrict access to. Refer http://www.ipdeny.com/ipblocks/data/countries/ for the list of countries.
