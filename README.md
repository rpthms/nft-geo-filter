# nft-geo-filter
Filter traffic in nftables using country specific IP blocks

# Description
This script will download IPv4 or/and IPv6 blocks for the specified countries
from ipdeny.com and add them to sets in the specified table. You have to
provide 2 letter ISO-3166-1 alpha-2 country codes of the countries you want to
filter as positional arguments to this script. Go to
https://www.ipdeny.com/ipblocks/ to find the list of supported countries.

You can specify which table holds the sets and the filtering rules using the
`--table-family` and `--table-name` flags. `--table-name` specifies the name of
the table. nft-geo-filter requires its own private table, so make sure that the
table name that you provide is not being used by any other table in your
ruleset. `--table-family` specifies the family of the nftables table which will
store the filter sets and the filtering rule. The family must be one of the
following options:

* ip
* ip6
* inet
* netdev

By using a separate table, this script can create it's own chains and add its
own filtering rules without needing the admin to make any changes to their
nftables config, like you were required to do in the previous version of this
script. **Do not add any rules to the chains inside nft-geo-filter's private
table**, because they will be removed when you re-run the script to update the
filter sets.

**The default action of this script is to block traffic** from the IP blocks of
the provided countries and allow everything else. To invert this behaviour and
only allow traffic from the IP blocks of the specified countries, use the
`--allow` flag.

Running nft-geo-filter without specifying any optional flags will end up
creating IP sets and filtering rules to block traffic from those IPs, inside a
table called 'geo-filter' of the 'inet' family. But **it is recommended to use
a 'netdev' table to drop packets** much more effeciently than the other
families.  Refer to the 'netdev' section below.

# IPv4 or IPv6?

The filter sets that are added to the table is determined by the table's family
that you specify using `--table-family`:

Table Family | Filter Sets
-------------|------------
ip|Only the IPv4 set
ip6|Only the IPv6 set
inet|Both IPv4 and IPv6 sets
netdev|Both IPv4 and IPv6 sets by default. Use the --no-ipv6 flag to only use the IPv4 set or the --no-ipv4 flag to only use the IPv6 set.

# Netdev
Using the netdev table to drop packets is more efficient than dropping them in
the tables of other families (by a factor of 2x according to the nftables wiki:
https://wiki.nftables.org/wiki-nftables/index.php/Nftables_families#netdev).
This is because the netdev rules are applied very early in the packet path (as
soon as the NIC passes the packets to the networking stack).

To use a netdev table, you need to set the `--table-family` to `netdev` and
provide the name of the interface that's connected to the internet by using the
`--interface` flag. The interface is needed because netdev tables work on a
per-interface basis.

# What do I need to add to my nftables config?
**Nothing!** Since this script creates a separate nftables table to filter your
traffic, it will not cause your current nftables config to break. The
"filter-chain" chain created by this script has a priority of -200 to ensure
that the filtering rules of this script are applied before your own rules.

# Help Text
Run `nft-geo-filter -h` to get the following help text:
```
usage: nft-geo-filter [-h] [-v] [--version] [-l NFT_LOCATION] [-a]
                      [-f {ip,ip6,inet,netdev}] [-n TABLE_NAME]
                      [-i INTERFACE] [--no-ipv4 | --no-ipv6]
                      country [country ...]

Filter traffic in nftables using country IP blocks

positional arguments:
  country               2 letter ISO-3166-1 alpha-2 country codes to block.
                        Check https://www.ipdeny.com/ipblocks/ to find the
                        list of supported countries.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         show verbose output
  --version             show program's version number and exit

  -l NFT_LOCATION, --nft-location NFT_LOCATION
                        Location of the nft binary. Default is /usr/sbin/nft
  -a, --allow           By default, all the IPs in the filter sets will be
                        denied and every other IP will be allowed to pass the
                        filtering chain. Provide this argument to reverse this
                        behaviour.

Table:
  Provide the name and the family of the table in which the set of filtered
  addresses will be created. This script will create a new nftables table,
  so make sure the provided table name is unique and not being used by any
  other table in the ruleset. An 'inet' table called 'geo-filter' will be
  used by default

  -f {ip,ip6,inet,netdev}, --table-family {ip,ip6,inet,netdev}
                        Specify the table's family. Default is inet
  -n TABLE_NAME, --table-name TABLE_NAME
                        Specify the table's name. Default is geo-filter

Netdev arguments:
  If you're using a netdev table, you need to provide the name of the
  interface which is connected to the internet because netdev tables work on
  a per-interface basis. You can also choose to only store v4 or only store
  v6 addresses inside the netdev table sets by providing the '-4' or '-6'
  arguments. Both v4 and v6 addresses are stored by default

  -i INTERFACE, --interface INTERFACE
                        Specify the ingress interface for the netdev table
  --no-ipv4             Don't create a set for v4 addresses in the netdev
                        table
  --no-ipv6             Don't create a set for v6 addresses in the netdev
                        table
```

# Usage examples
All you have to do is run this script with the appropriate flags. There's no
need to create a table or set manually in your nftables config for the
filtering operation to work.  Take a look at the following examples to
understand how the script works. I'm using the IP address blocks from Monaco in
the following examples:

* Use a netdev table to block packets from Monaco (on the enp1s0 interface)\
  Command to run: `nft-geo-filter --table-family netdev --interface enp1s0 MC`\
  Resulting rulset:
  ```
  table netdev geo-filter {
        set filter-v4 {
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

        set filter-v6 {
                type ipv6_addr
                flags interval
                auto-merge
                elements = { 2a01:8fe0::/32,
                             2a07:9080::/29,
                             2a0b:8000::/29 }
        }

        chain filter-chain {
                type filter hook ingress device "enp1s0" priority -200; policy accept;
                ip saddr @filter-v4 drop
                ip6 saddr @filter-v6 drop
        }
  }
  ```

* Use a netdev table to only block IPv4 packets from Monaco (on the enp1s0 interface)\
  Command to run: `nft-geo-filter --table-family netdev --interface enp1s0 --no-ipv6 MC`\
  Resulting ruleset:
  ```
  table netdev geo-filter {
        set filter-v4 {
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

        chain filter-chain {
                type filter hook ingress device "enp1s0" priority -200; policy accept;
                ip saddr @filter-v4 drop
        }
  }
  ```

* Only allow packets from Monaco using a netdev table (on the enp1s0 interface)\
  Command to run: `nft-geo-filter --table-family netdev --interface enp1s0 --allow MC`\
  Resulting ruleset:
  ```
  table netdev geo-filter {
        set filter-v4 {
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

        set filter-v6 {
                type ipv6_addr
                flags interval
                auto-merge
                elements = { 2a01:8fe0::/32,
                             2a07:9080::/29,
                             2a0b:8000::/29 }
        }

        chain filter-chain {
                type filter hook ingress device "wlp2s0" priority -200; policy drop;
                ip saddr @filter-v4 accept
                ip6 saddr @filter-v6 accept
        }
  }
  ```

* Use an ip table named 'monaco-filter' to block IPv4 packets from Monaco\
  Command to run: `nft-geo-filter --table-family ip --table-name monaco-filter MC`\
  Resulting ruleset:
  ```
  table ip monaco-filter {
        set filter-v4 {
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

        chain filter-chain {
                type filter hook prerouting priority -200; policy accept;
                ip saddr @filter-v4 drop
        }
  }
  ```

* Use an ip6 table named 'monaco-filter-v6' to block IPv6 packets from Monaco\
  Command to run: `nft-geo-filter --table-family ip6 --table-name monaco-filter-v6 MC`\
  Resulting ruleset:
  ```
  table ip6 monaco-filter-v6 {
        set filter-v6 {
                type ipv6_addr
                flags interval
                auto-merge
                elements = { 2a01:8fe0::/32,
                             2a07:9080::/29,
                             2a0b:8000::/29 }
        }

        chain filter-chain {
                type filter hook prerouting priority -200; policy accept;
                ip6 saddr @filter-v6 drop
        }
  }
  ```

* Only allow packets from Monaco using an inet table\
  Command to run: `nft-geo-filter --allow MC`\
  Resulting ruleset:
  ```
  table inet geo-filter {
        set filter-v4 {
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

        set filter-v6 {
                type ipv6_addr
                flags interval
                auto-merge
                elements = { 2a01:8fe0::/32,
                             2a07:9080::/29,
                             2a0b:8000::/29 }
        }

        chain filter-chain {
                type filter hook prerouting priority -200; policy drop;
                ip saddr @filter-v4 accept
                ip6 saddr @filter-v6 accept
        }
  }
  ```

* Block all packets from Monaco using an inet table (default operation)\
  Command to run: `nft-geo-filter MC`\
  Resulting ruleset:
  ```
  table inet geo-filter {
        set filter-v4 {
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

        set filter-v6 {
                type ipv6_addr
                flags interval
                auto-merge
                elements = { 2a01:8fe0::/32,
                             2a07:9080::/29,
                             2a0b:8000::/29 }
        }

        chain filter-chain {
                type filter hook prerouting priority -200; policy accept;
                ip saddr @filter-v4 drop
                ip6 saddr @filter-v6 drop
        }
  }
  ```

* Block all packets from Monaco using an inet table named 'monaco-filter'\
  Command to run: `nft-geo-filter --table-name monaco-filter MC`\
  Resulting ruleset:
  ```
  table inet monaco-filter {
        set filter-v4 {
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

        set filter-v6 {
                type ipv6_addr
                flags interval
                auto-merge
                elements = { 2a01:8fe0::/32,
                             2a07:9080::/29,
                             2a0b:8000::/29 }
        }

        chain filter-chain {
                type filter hook prerouting priority -200; policy accept;
                ip saddr @filter-v4 drop
                ip6 saddr @filter-v6 drop
        }
  }
  ```

# Adding exceptions to the filter sets
If there are certain IP addresses which you want to prevent from being filtered
by the IP sets generated by the scripts, then you'll need to create a chain
with a priority higher than the script generated chain and accept the packets
from those IP addresses. The priority used by the script generated chain is
'-200'.

For example, if you're blocking all IPv4 packets from Monaco using an 'ip'
table and you want to add an exception for the addresses: `37.44.224.1` and
`37.44.224.2`. Then your ruleset should look something like this:

```
table ip geo-filter {
        set filter-v4 {
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

        chain filter-chain {
                type filter hook prerouting priority -200; policy accept;       <--- Lower priority
                ip saddr @filter-v4 drop
        }
}
table ip my-local-table {
        chain my-local-chain {
                type filter hook prerouting priority -250; policy accept;       <--- Higher priority
                ip saddr { 27.44.224.2, 37.44.224.1 } accept
        }
}
```

# Run nft-geo-filter as a service
nft-geo-filter can also be run via a cronjob or a systemd timer to keep your
filtering sets updated. When nft-geo-filter is executed, it will check if the
target sets already exist. It they do, the script will flush the existing
contents of the filtering sets after downloading the IP blocks from ipdeny.com
and then add the updated IP blocks to the sets. If any changes need to be made
to the filtering rules, the script will make them as well.

Taking Monaco as an example again, to update the filtering sets in an 'ip'
table called 'monaco-filter' at 3:00 a.m. every day, your cronjob would look
like this:
```
0 3 * * * nft-geo-filter --table-family ip --table-name monaco-filter MC
```
