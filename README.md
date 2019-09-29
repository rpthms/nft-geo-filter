# nft-blacklist
Blacklist country specific IP blocks using nftables

# Usage
This script will download IPv4 or/and IPv6 blocks for the specified countries
from ipdeny.com and add them to sets in the appropriate tables. You have to
specify 2 letter ISO-3166-1 alpha-2 country codes of the countries you want to
block as positional arguments to this script. Go to ipdeny.com/ipblocks to find
the list of countries that can be blocked.

You can specify which tables to add the sets into using `--ip-table`,
`--ip6-table` and `--inet-table`. Use `--ip-table` to specify the table for the
IPv4 blacklist set and `--ip6-table` for the IPv6 blacklist set.
`--inet-table` adds both the IPv4 and IPv6 blacklist set into the same table.
You cannot use `--inet-table` along with `--ip-table` or `--ip6-table`.

You can also modify the name of the blacklist sets that will be created in the
tables using the `--blacklist-prefix` flag. The sets will be named
`<prefix>-v4` and `<prefix>-v6` which will hold the IPv4 and IPv6 address
blocks respectively.

Running nft-blacklist.py without specifying any optional flags will end up
creating blacklist sets called **blacklist-v4** and **blacklist-v6** in a table
called **filter of type 'inet'**.

Run `nft-blacklist.py -h` to get the following help text:
```
usage: nft-blacklist.py [-h] [-v] [-4 IP_TABLE] [-6 IP6_TABLE] [-i INET_TABLE]
                        [-b BLACKLIST_PREFIX]
                        country [country ...]

Add country based blacklist sets for nftables

positional arguments:
  country               2 letter ISO-3166-1 alpha-2 country codes to block.
                        Check ipdeny.com/ipblocks/ to find the list of
                        supported countries.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit

Table:
  Choose the family and table name to create the blacklist set in. If
  --inet-table is chosen, then the blacklist set will be created in the inet
  family which can be used by both v4 and v6 addresses. You cannot specify
  --inet-table along with --ip-table and --ip6-table. An --inet-table called
  'filter' will be used by default

  -4 IP_TABLE, --ip-table IP_TABLE
                        Name of the ip table which will contain the v4
                        blacklist set
  -6 IP6_TABLE, --ip6-table IP6_TABLE
                        Name of the ip6 table which will contain the v6
                        blacklist set
  -i INET_TABLE, --inet-table INET_TABLE
                        Name of the inet table which will contain the v4 and
                        v6 blacklist sets

Blacklist:
  Provide the prefix to be used for the blacklist sets. The blacklist sets
  will be called <prefix>-v4 or <prefix>-v6 depending on which address
  family is used by the set. 'blacklist' will be used as the default
  blacklist prefix.

  -b BLACKLIST_PREFIX, --blacklist-prefix BLACKLIST_PREFIX
                        Name of the blacklist prefix

```

# Example

To use this script, you will need to create a 'set' in your nftables
configuration with the `type ipv4_addr`/`type ipv6_addr`, `flags interval` and
`auto-merge` set properties.  This set can belong to any table in your nftables
configuration and is responsible for holding the blacklisted IP addresses.
While nft-blacklist.py can create the set on it's own it would make more sense
for you to create the set in your nftables config file, because nftables would
complain when you're loading your ruleset initially if you try to use a named
set in one of your rules if that set doesn't exist. nft-blacklist.py will
update the set with the address blocks once your nftables ruleset has been
loaded and your rules would be able to use the addresses in the blacklist set.

Here's an example of an nftables configuration file containing the blacklist set.

```
#!/usr/sbin/nft -f

flush ruleset

table ip filter {
        set blacklist-v4 {
                type ipv4_addr
                flags interval
                auto-merge
        }

        chain input {
                type filter hook input priority 0;

                iifname lo accept
                ct state established,related accept
                ip saddr @blacklist-v4 drop
                ip protocol icmp accept
                tcp dport {http, https, ssh} ct state new accept
                drop
        }
}
```
As you can see, since the blacklist set has been defined, we can now use it in
the "input" chain. You can load this nftables config file (or something
similar) on boot. And then run the nft-blacklist.py command after the ruleset
has been loaded.

As an example, if I run nft-blacklist.py with the following arguments after
loading the nftables ruleset, to block all IP addresses from Monaco:
```
# nft-blacklist.py --ip-table filter MC
```
I would end up the following nftables ruleset that looks like this:
```
# nft list ruleset
table ip filter {
        set blacklist-v4 {
                type ipv4_addr
                flags interval
                auto-merge
                elements = { 37.44.224.0/22, 80.94.96.0/20,
                             82.113.0.0/19, 87.238.104.0/21,
                             87.254.224.0/19, 88.209.64.0/18,
                             91.199.109.0/24, 176.114.96.0/20,
                             185.47.116.0/22, 185.162.120.0/22,
                             185.250.4.0/22, 188.191.136.0/21,
                             194.9.12.0/23, 195.20.192.0/23,
                             195.78.0.0/19, 213.133.72.0/21,
                             213.137.128.0/19 }
        }

        chain input {
                type filter hook input priority 0; policy accept;
                iifname lo accept
                ct state { established, related } accept
                ip saddr @blacklist-v4 drop
                ip protocol icmp accept
                tcp dport {http, https, ssh} ct state new accept
                drop
        }
}
```

# Keep your blacklist sets updated

nft-blacklist.py can be run via a cronjob or a systemd timer to keep your
blacklists updated. When nft-blacklist.py is executed, it will first flush the
existing contents of the blacklist sets and then download the IP blocks from
ipdeny.com and add the updated IP blocks to the blacklist sets. This way you
don't need to reload your entire nftables ruleset. Your rules will stay the
same, only the contents of the blacklist sets will change.

Taking Monaco as an example again, to update the IPv4 blacklist set in an 'ip'
table called filter-4 and the IPv6 blacklist set in an 'ip6' table called
filter-6 at 3:00 a.m. every day, your cronjob would look like this:
```
0 3 * * * nft-blacklist.py --ip-table filter-4 --ip6-table filter-6 MC
```

# Whitelist?

Though the script is called nft-blacklist.py it isn't actually doing the acutal
blacklisting for you. The script only sets up nftables sets with IP address
blocks of various countries in the specified tables. It's up to you to figure
out what to do with the sets. Which is why it's pretty easy to whitelist the
IPs of specific countries by using a rule like:
```
nft add rule ip filter input ip saddr @whitelist-v4 allow
```
which allows connections from IP addresses in the whitelist-v4 set in the "ip"
filter table.
