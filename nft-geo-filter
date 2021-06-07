#!/usr/bin/env python3

# Python script for filtering traffic in nftables using country IP blocks

import argparse
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import urllib.request
import urllib.error

#Temp File Header
FILE_HEADER = ('table {} {} {{\n'
               'set {} {{\n'
               'type {}\n'
               'flags interval\n'
               'auto-merge\n')

SUPPORTED_PROVIDERS = ('ipdeny.com', 'ipverse.net')

class GeoFilter:
    def __init__(self, args):
        self.nft = args.nft_location
        self.allow = args.allow
        self.table_family = args.table_family
        self.table_name = args.table_name
        self.interface = args.interface
        self.country_codes = [c.lower() for c in args.country]
        self.no_ipv4 = args.no_ipv4
        self.no_ipv6 = args.no_ipv6
        self.counter = args.counter
        self.log_accept = args.log_accept
        self.log_accept_prefix = args.log_accept_prefix
        self.log_accept_level = args.log_accept_level
        self.log_drop = args.log_drop
        self.log_drop_prefix = args.log_drop_prefix
        self.log_drop_level = args.log_drop_level
        self.verbosity = args.verbose
        self.provider = args.provider

        self.reset_dormancy = True
        self.working_dir = tempfile.mkdtemp()
        self.logger = self.configure_logging()

        self.policy = "drop" if self.allow else "accept"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.delete_working_dir()

    def configure_logging(self):
        """Configure the logger object for this class"""
        logger = logging.getLogger('GeoFilter')

        if self.verbosity > 1:
            log_level = logging.DEBUG
        elif self.verbosity == 1:
            log_level = logging.INFO
        else:
            log_level = logging.WARNING

        logger.setLevel(log_level)

        # Create a StreamHandler to log messages to the console
        sh = logging.StreamHandler()
        sh.setLevel(logging.DEBUG)

        # Log format
        formatter = logging.Formatter('%(levelname)s - %(funcName)s - %(message)s')

        sh.setFormatter(formatter)
        logger.addHandler(sh)
        return logger

    def delete_working_dir(self):
        self.logger.info("Deleting the working directory")
        shutil.rmtree(self.working_dir)

    def show_subprocess_run_error(self, err):
        self.logger.error("Failed to run: {}".format(err.args))
        self.logger.error("Command exit status: {}\n".format(err.returncode))
        self.logger.error("Command stdout: \n{}".format(err.stdout.decode("utf-8")))
        self.logger.error("Command stderr: \n{}".format(err.stderr.decode("utf-8")))

    def add_table(self):
        nft_command_tmpl = "{} add table {} {}"
        nft_command = nft_command_tmpl.format(self.nft, self.table_family, self.table_name)

        self.logger.info("Adding a {} table: {}".format(self.table_family, self.table_name))
        self.logger.debug("Running command: {}".format(nft_command))
        try:
            subprocess.run(nft_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            self.logger.error("Failed to add the {} table: {}".format(self.table_family, self.table_name))
            self.show_subprocess_run_error(err)
            raise

    def set_table_as_dormant(self, is_dormant):
        if is_dormant:
            nft_dormant_command_tmpl = "{} add table {} {} {{ flags dormant; }}"
        else:
            nft_dormant_command_tmpl = "{} add table {} {}"
        nft_dormant_command = nft_dormant_command_tmpl.format(self.nft, self.table_family, self.table_name)

        self.logger.info("{} is dormant: {}".format(self.table_name, is_dormant))
        self.logger.debug("Running command: {}".format(nft_dormant_command))
        try:
            subprocess.run(nft_dormant_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            if is_dormant:
                self.logger.error("Failed to add the dormant flag to the {} table".format(self.table_name))
            else:
                self.logger.error("Failed to remove the dormant flag from the {} table".format(self.table_name))
            self.show_subprocess_run_error(err)
            raise

    def add_chain(self):
        if self.table_family == "netdev":
            nft_command_tmpl = "{} -- add chain {} {} filter-chain {{ type filter hook ingress device {} priority -190; policy {}; }}"
            nft_command = nft_command_tmpl.format(self.nft, self.table_family, self.table_name, self.interface, self.policy)
        else:
            nft_command_tmpl = "{} -- add chain {} {} filter-chain {{ type filter hook prerouting priority -190; policy {}; }}"
            nft_command = nft_command_tmpl.format(self.nft, self.table_family, self.table_name, self.policy)

        self.logger.info("Adding the filter-chain in the {} table".format(self.table_name))
        self.logger.debug("Running command: {}".format(nft_command))
        try:
            subprocess.run(nft_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            self.logger.error("Failed to add the filter-chain to the {} table".format(self.table_name))
            self.show_subprocess_run_error(err)
            raise

    def find_old_rules(self):
        """Get a list of all the old rules in the filter-chain and store them
        for deletion."""
        nft_list_command = "{} -j list chain {} {} filter-chain".format(self.nft, self.table_family, self.table_name)

        self.logger.info("Finding old filtering rules in the filter-chain of the {} table".format(self.table_name))
        self.logger.debug("Running command: {}".format(nft_list_command))
        try:
            result = subprocess.run(nft_list_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            self.logger.error("Failed to find the handles of the old filtering rules")
            self.show_subprocess_run_error(err)
            raise

        json_result = json.loads(result.stdout.decode("utf-8"))
        self.old_rule_handles = []

        # Get the handles of all the rules in the filter-chain
        for rule in [r for r in json_result["nftables"] if "rule" in r]:
            self.old_rule_handles.append(rule["rule"]["handle"])

        self.logger.debug("Old filtering rule handles: {}".format(self.old_rule_handles))

    def delete_old_rules(self):
        """Delete the old rules in the filter-chain. This should be done after the
        new filtering rules are added so that the filtering chain doesn't remain
        without rules at any point"""
        if self.old_rule_handles:
            nft_delete_tmpl = "{} delete rule {} {} filter-chain handle {}"
            self.logger.info("Deleting old filtering rules from {}'s filter-chain".format(self.table_name))

            for handle in self.old_rule_handles:
                nft_delete_command = nft_delete_tmpl.format(self.nft, self.table_family, self.table_name, handle)
                self.logger.debug("Running command: {}".format(nft_delete_command))
                try:
                    subprocess.run(nft_delete_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                except subprocess.CalledProcessError as err:
                    self.logger.error("Failed to delete the old filtering rules")
                    self.show_subprocess_run_error(err)
                    raise

    def create_log_statement(self, action):
        """ Construct the logging as specified by command line args.
        for a rule with the specified action"""
        is_accept = action == "accept"
        if (self.log_accept and is_accept) or (self.log_drop and not is_accept):

            # Extract the log parameters for this type of action
            log_prefix = self.log_accept_prefix if is_accept else self.log_drop_prefix
            log_level = self.log_accept_level if is_accept else self.log_drop_level

            return "log {} {}".format(
                "prefix \"{}\"".format(log_prefix) if log_prefix else "",
                "level {}".format(log_level) if log_level else ""
            )
        else:
            return ""

    def add_filtering_rule(self, addr_family):
        action = "accept" if self.allow else "drop"
        filter_set_name = "filter-v4" if addr_family == "ip" else "filter-v6"
        log_addr_family = "IPv4" if addr_family == "ip" else "IPv6"

        nft_command_tmpl = "{} add rule {} {} filter-chain {} saddr @{} {} {} {}"
        nft_command = nft_command_tmpl.format(self.nft, self.table_family, self.table_name, addr_family,
            filter_set_name, self.counter, self.create_log_statement(action), action).split()

        self.logger.info("Adding a new filtering rule for {} addresses in {}'s filter-chain".format(log_addr_family, self.table_name))
        self.logger.debug("Running command: {}".format(nft_command))
        try:
            subprocess.run(nft_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            self.logger.error("Failed to add the new filtering rule for the {} addresses".format(log_addr_family))
            self.show_subprocess_run_error(err)
            raise

    def add_exceptions(self):
        ip_list = args.exceptions.split(',')

        try:
            v4_list = [addr for addr in ip_list if ipaddress.ip_network(addr, strict=False).version == 4]
            v6_list = [addr for addr in ip_list if ipaddress.ip_network(addr, strict=False).version == 6]
        except ValueError as err:
            self.logger.error("ValueError raised: {}".format(err))
            raise

        if v6_list:
            nft_allow_v6_exceptions = "{} insert rule {} {} filter-chain ip6 saddr {{ {} }} accept".format(
                self.nft, self.table_family, self.table_name, ",".join(v6_list))
            self.logger.info("Adding IPv6 exceptions in {}'s filter-chain".format(self.table_name))
            self.logger.debug("Running command: {}".format(nft_allow_v6_exceptions))
            try:
                subprocess.run(nft_allow_v6_exceptions.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Failed to add IPv6 exceptions in {}'s filter-chain".format(self.table_name))
                self.show_subprocess_run_error(err)
                raise

        if v4_list:
            nft_allow_v4_exceptions = "{} insert rule {} {} filter-chain ip saddr {{ {} }} accept".format(
                self.nft, self.table_family, self.table_name, ",".join(v4_list))
            self.logger.info("Adding IPv4 exceptions in {}'s filter-chain".format(self.table_name))
            self.logger.debug("Running command: {}".format(nft_allow_v4_exceptions))
            try:
                subprocess.run(nft_allow_v4_exceptions.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Failed to add IPv4 exceptions in {}'s filter-chain".format(self.table_name))
                self.show_subprocess_run_error(err)
                raise

    def allow_established(self):
        nft_command = "{} insert rule {} {} filter-chain ct state established,related accept".format(self.nft,
            self.table_family, self.table_name)

        self.logger.info("Adding a rule to allow packets from established connections in {}'s filter-chain".format(
            self.table_name))
        self.logger.debug("Running command: {}".format(nft_command))
        try:
            subprocess.run(nft_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            self.logger.error("Failed to add the rule to allow packets from established connections")
            self.show_subprocess_run_error(err)
            raise

    def add_allow_rules(self):
        """Certain rules need to be added to the filter-chain when using --allow, otherwise
           LAN traffic and protocols such as ARP won't work"""
        if self.table_family == "netdev":
            nft_allow_non_ip = "{} insert rule {} {} filter-chain meta protocol ne {{ ip, ip6 }} accept".format(
                self.nft, self.table_family, self.table_name)
            self.logger.info("Allow non-IP traffic in {}'s filter-chain".format(self.table_name))
            self.logger.debug("Running command: {}".format(nft_allow_non_ip))
            try:
                subprocess.run(nft_allow_non_ip.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Failed to add the rule to allow non-IP traffic in {}'s filter-chain".format(self.table_name))
                self.show_subprocess_run_error(err)
                raise

        if self.table_family in ("ip","inet") or (self.table_family == "netdev" and not self.no_ipv4):
            if self.table_family == "netdev":
                nft_allow_private_ip = "{} insert rule {} {} filter-chain ip saddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }}\
                    accept".format(self.nft, self.table_family, self.table_name)
            else:
                nft_allow_private_ip = "{} insert rule {} {} filter-chain ip saddr {{ 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12,\
                    192.168.0.0/16 }} accept".format(self.nft, self.table_family, self.table_name)
            self.logger.info("Allow private IPv4 address ranges in {}'s filter-chain".format(self.table_name))
            self.logger.debug("Running command: {}".format(nft_allow_private_ip))
            try:
                subprocess.run(nft_allow_private_ip.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Failed to add the rule to allow private IPv4 address ranges in {}'s filter-chain".format(self.table_name))
                self.show_subprocess_run_error(err)
                raise

        if self.table_family in ("ip6","inet") or (self.table_family == "netdev" and not self.no_ipv6):
            if self.table_family == "netdev":
                nft_allow_link_local_ip6 = "{} insert rule {} {} filter-chain ip6 saddr fe80::/10 accept".format(
                    self.nft, self.table_family, self.table_name)
            else:
                nft_allow_link_local_ip6 = "{} insert rule {} {} filter-chain ip6 saddr {{ ::1, fe80::/10 }} accept".format(
                    self.nft, self.table_family, self.table_name)
            self.logger.info("Allow link local IPv6 traffic in {}'s filter-chain".format(self.table_name))
            self.logger.debug("Running command: {}".format(nft_allow_link_local_ip6))
            try:
                subprocess.run(nft_allow_link_local_ip6.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Failed to add the rule to allow link local IPv6 traffic in {}'s filter-chain".format(self.table_name))
                self.show_subprocess_run_error(err)
                raise

    def add_policy_logging_rule(self):
        """Append a final rule with same action of the policy if
        counter or logging with match to policy if required"""
        log_statement = self.create_log_statement(self.policy)
        if log_statement != "" or self.counter == "counter":
            nft_unmatched_logging = "{} add rule {} {} filter-chain {} {} {}".format(
                self.nft, self.table_family, self.table_name, self.counter, log_statement, self.policy)
            self.logger.info("Appending {} to {}'s filter-chain to attach logging/counter".format(self.policy, self.table_name))
            self.logger.debug("Running command: {}".format(nft_unmatched_logging))
            try:
                subprocess.run(nft_unmatched_logging.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Failed to append a {} rule to attach logging/counter in {}'s filter-chain".format(self.policy, self.table_name))
                self.show_subprocess_run_error(err)
                raise

    def does_set_exist(self, filter_set_name):
        nft_list_command = "{} -j list sets {}".format(self.nft, self.table_family)

        self.logger.info("Checking if the {} set exists in the {} table".format(filter_set_name, self.table_name))
        self.logger.debug("Running command: {}".format(nft_list_command))
        try:
            result = subprocess.run(nft_list_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            self.logger.error("Could not list the existing sets in the {} family".format(self.table_family))
            self.show_subprocess_run_error(err)
            raise

        json_result = json.loads(result.stdout.decode("utf-8"))

        if json_result["nftables"] is not None:
            for nft_set in [s for s in json_result["nftables"] if "set" in s]:
                if (nft_set["set"]["name"] == filter_set_name and
                    nft_set["set"]["family"] == self.table_family and
                    nft_set["set"]["table"] == self.table_name):

                    self.logger.info("Found set {} in {}!".format(filter_set_name, self.table_name))
                    return True

        self.logger.info("Could not find set {} in {}!".format(filter_set_name, self.table_name))
        return False

    def flush_filter_set(self, filter_set_name):
        """Flush the contents of the specified set. But before that, we want to save the
           contents of the old set, so that we can restore it if an error occurs."""
        if self.does_set_exist(filter_set_name):
            nft_list_command = "{} list set {} {} {}".format(self.nft, self.table_family, self.table_name, filter_set_name)
            try:
                list_result = subprocess.run(nft_list_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Could not list the {} set in the {} table".format(filter_set_name, self.table_name))
                self.show_subprocess_run_error(err)
                raise

            with open("{}/old_sets".format(self.working_dir), mode="ab") as f:
                f.write(list_result.stdout)

            nft_flush_command = "{} flush set {} {} {}".format(self.nft, self.table_family, self.table_name, filter_set_name)

            self.logger.info('Flushing the {} set in the {} table'.format(filter_set_name, self.table_name))
            self.logger.debug("Running command: {}".format(nft_flush_command))
            try:
                subprocess.run(nft_flush_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error("Could not flush the {} set in the {} table".format(filter_set_name, self.table_name))
                self.show_subprocess_run_error(err)
                raise

    def restore_old_sets(self):
        """Restore the old sets if we failed to update the existing sets of the filter table. If
           we were creating new sets and failed to do so, then set the filter table to dormant
           because we don't want to accidentally lock ourselves out of the server"""
        if not os.path.exists("{}/old_sets".format(self.working_dir)):
            self.logger.warning('No old sets detected. Setting the {} table as dormant!'.format(self.table_name))
            self.reset_dormancy = False
            self.set_table_as_dormant(True)
            return

        nft_restore_command = "{} -f {}".format(self.nft, "{}/old_sets".format(self.working_dir))

        self.logger.info('Restoring the old sets in the {} table'.format(self.table_name))
        self.logger.debug("Running command: {}".format(nft_restore_command))
        try:
            subprocess.run(nft_restore_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as err:
            self.logger.error('Could not restore the old sets in the {} table'.format(self.table_name))
            self.show_subprocess_run_error(err)
            raise

    def get_ip_blocks(self, country_code, addr_family):
        # We need to set the table as dormant before we try to download the IP blocks, because
        # there is a possibility that the IP blocks provider's address might be blocked by the
        # filtering rule that was added when this script was previously executed. The dormant
        # flag is removed as soon as the download is finished. By doing this, we are disabling
        # the geo-filtering as little as possible.
        self.set_table_as_dormant(True)

        log_addr_family = "IPv4" if addr_family == 'ip' else "IPv6"
        self.logger.info('Downloading "{}" {} blocks from {}'.format(country_code, log_addr_family, self.provider))

        try:
            if self.provider == 'ipdeny.com':
                if addr_family == 'ip':
                    provider_url = 'https://www.ipdeny.com/ipblocks/data/aggregated/{}-aggregated.zone'
                else:
                    provider_url = 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{}-aggregated.zone'

                http_resp = urllib.request.urlopen(provider_url.format(country_code))
                data = http_resp.read().decode('utf-8')

                self.logger.info('Building list of {} blocks for {}..'.format(log_addr_family, country_code))
                ip_blocks = ',\n'.join(data.splitlines())
                self.logger.debug("IP block list for {}: {}".format(country_code, ip_blocks))
            elif self.provider == 'ipverse.net':
                if addr_family == 'ip':
                    provider_url = 'http://ipverse.net/ipblocks/data/countries/{}.zone'
                else:
                    provider_url = 'http://ipverse.net/ipblocks/data/countries/{}-ipv6.zone'

                http_resp = urllib.request.urlopen(provider_url.format(country_code))
                data = http_resp.read().decode('utf-8')

                self.logger.info('Building list of {} blocks for {}..'.format(log_addr_family, country_code))

                # Delete the comments on top of the IPverse IP blocks
                data_list = data.splitlines()
                data_without_comments = [d for d in data_list if d[0] != '#']

                ip_blocks = ',\n'.join(data_without_comments)
                self.logger.debug("IP block list for {}: {}".format(country_code, ip_blocks))

            return ip_blocks
        except urllib.error.HTTPError as err:
            self.logger.error("Couldn't GET {}: {} {}".format(provider_url.format(country_code), err.code, err.reason))
            self.restore_old_sets()
            raise
        except urllib.error.URLError as err:
            self.logger.error("Couldn't GET {}: {}".format(provider_url.format(country_code), err.reason))
            self.restore_old_sets()
            raise
        finally:
            if self.reset_dormancy:
                self.set_table_as_dormant(False)

    def update_filter_set(self, addr_family):
        if addr_family == 'ip':
            filter_set_type = "ipv4_addr"
            filter_set_name = "filter-v4"
            log_addr_family = "IPv4"
        elif addr_family == 'ip6':
            filter_set_type = "ipv6_addr"
            filter_set_name = "filter-v6"
            log_addr_family = "IPv6"

        # Flush the existing filter set (if it exists)
        self.flush_filter_set(filter_set_name)

        for c in self.country_codes:
            ip_blocks = self.get_ip_blocks(c, addr_family)
            filter_set_ips = ''.join(('elements = {\n', ip_blocks, '\n}\n}\n}'))

            with tempfile.NamedTemporaryFile(mode='w', dir=self.working_dir, delete=False) as tmp:
                tmp.write(FILE_HEADER.format(self.table_family, self.table_name, filter_set_name, filter_set_type))
                tmp.write(filter_set_ips)

            nft_command = "{} -f {}".format(self.nft, tmp.name)

            self.logger.info('Adding the "{}" {} blocks to the {} set in {}'.format(c, log_addr_family, filter_set_name, self.table_name))
            self.logger.debug("Running command: {}".format(nft_command))
            try:
                subprocess.run(nft_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as err:
                self.logger.error('Could not add the "{}" {} blocks to the {} set in {}'.format(c, log_addr_family, filter_set_name, self.table_name))
                self.restore_old_sets()
                self.show_subprocess_run_error(err)
                raise

        # Add the new filtering rule
        self.add_filtering_rule(addr_family)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Filter traffic in nftables using country IP blocks')

    # Version
    parser.add_argument("-v", "--verbose", help="show verbose output", action="count", default=0)
    parser.add_argument("--version", action="version", version="%(prog)s 3.0")

    nft_gfilter_group = parser.add_argument_group()
    nft_gfilter_group.add_argument("-l", "--nft-location", default="/usr/sbin/nft", metavar="LOCATION",
        help="Location of the nft binary. Default is /usr/sbin/nft")
    nft_gfilter_group.add_argument("-a", "--allow", action="store_true",
        help=textwrap.dedent("""By default, all the IPs in the filter sets will be denied and every other
                IP will be allowed to pass the filtering chain. Provide this argument to reverse this
                behaviour.""")
    )
    nft_gfilter_group.add_argument("--allow-established", action="store_true",
        help=textwrap.dedent("""Allow packets from denied IPs, but only if they are a part of an established
                connection i.e the initial packet originated from your host. Initial packets from the denied IPs
                will still be dropped. This flag can be useful when using the allow mode, so that outgoing connections
                to addresses outside the filter set can still be made.""")
    )
    nft_gfilter_group.add_argument("-c", "--counter", action="store_const", const="counter", default="",
        help="Add the counter statement to the filtering rules")
    nft_gfilter_group.add_argument("--provider", action="store", default="ipverse.net", choices=SUPPORTED_PROVIDERS,
        help="Specify the country IP blocks provider. Default is ipverse.net")

    # Table info
    table_group = parser.add_argument_group(
        title="Table",
        description=textwrap.dedent("""Provide the name and the family of the table in which the set of
                    filtered addresses will be created. This script will create a new nftables table, so
                    make sure the provided table name is unique and not being used by any other table in
                    the ruleset. An 'inet' table called 'geo-filter' will be used by default""")
    )
    table_group.add_argument("-f", "--table-family", choices=["ip","ip6","inet","netdev"], default="inet",
        help="Specify the table's family. Default is inet")
    table_group.add_argument("-n", "--table-name", default="geo-filter", metavar="NAME",
        help="Specify the table's name. Default is geo-filter")

    # Netdev info
    netdev_group = parser.add_argument_group(
        title="Netdev arguments",
        description=textwrap.dedent("""If you're using a netdev table, you need to provide the name of the
                    interface which is connected to the internet because netdev tables work on a per-interface
                    basis. You can also choose to only store v4 or only store v6 addresses inside the
                    netdev table sets by providing the '--no-ipv6' or '--no-ipv4' arguments. Both v4 and v6
                    addresses are stored by default""")
    )
    netdev_group.add_argument("-i", "--interface",
        help="Specify the ingress interface for the netdev table")
    netdev_addr_family_group = netdev_group.add_mutually_exclusive_group()
    netdev_addr_family_group.add_argument("--no-ipv4", action="store_true", help="Don't create a set for v4 addresses in the netdev table")
    netdev_addr_family_group.add_argument("--no-ipv6", action="store_true", help="Don't create a set for v6 addresses in the netdev table")

    # Logging statement options
    log_group = parser.add_argument_group(
        title="Logging statement",
        description=textwrap.dedent("""You can optionally add the logging statement to the filtering rules added
                by this script. That way, you'll be able to see the IP addresses of the packets that are accepted
                or dropped by the filtering rules in the kernel log (which can be read via the systemd journal or
                syslog). You can also add an optional prefix to the log messages and change the log message
                severity level.""")
    )
    log_group.add_argument("-p", "--log-accept", action="store_true", help="Add the log statement to the accept filtering rules")
    log_group.add_argument("--log-accept-prefix", metavar="PREFIX", help=textwrap.dedent("""Add a prefix to the accept log messages
        for easier identification. No prefix is used by default."""))
    log_group.add_argument("--log-accept-level", choices=["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"],
        help="Set the acceptlog message severity level. Default is 'warn'.")
    log_group.add_argument("-o", "--log-drop", action="store_true", help="Add the log statement to the drop filtering rules")
    log_group.add_argument("--log-drop-prefix", metavar="PREFIX", help=textwrap.dedent("""Add a prefix to the drop log messages
        for easier identification. No prefix is used by default."""))
    log_group.add_argument("--log-drop-level", choices=["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"],
        help="Set the drop log message severity level. Default is 'warn'.")

    exception_group = parser.add_argument_group(
        title="IP Exceptions",
        description=textwrap.dedent("""You can add exceptions for certain IPs by passing a comma separated list
            of IPs or subnets/prefixes to the '--exceptions' option. The IP addresses passed to this option will
            be explicitly allowed in the filtering chain created by this script. Both IPv4 and IPv6 addresses
            can be passed. Use this option to allow a few IP addresses that would otherwise be denied by your
            filtering sets.""")
    )
    exception_group.add_argument("-e", "--exceptions", metavar="ADDRESSES")

    # Mandatory arguments
    parser.add_argument("country", nargs='+',
        help=textwrap.dedent("""2 letter ISO-3166-1 alpha-2 country codes to allow/block. Check
            your IP blocks provider to find the list of supported countries.""")
    )

    args = parser.parse_args()

    if not os.geteuid() == 0:
        sys.exit('Need root privileges to run this script!')

    # Check the arguments
    if args.table_family == "netdev" and not args.interface:
        sys.exit("'netdev' family requires an 'interface'. Please provide an interface with --interface")
    if args.table_family == "netdev" and args.allow_established:
        sys.exit("Can't use '--allow-established' with the 'netdev' family. Please choose a different table family.")
    if (args.log_accept_prefix or args.log_accept_level) and not args.log_accept:
        sys.exit("Can't use '--log-accept-prefix', '--log-accept-level' without the '--log-accept' argument.")
    if (args.log_drop_prefix or args.log_drop_level) and not args.log_drop:
        sys.exit("Can't use '--log-drop-prefix', '--log-drop-level' without the '--log-drop' argument.")

    with GeoFilter(args) as gFilter:
        try:
            # Ensure that the target nft table and chain exists
            gFilter.add_table()
            gFilter.add_chain()

            # Store the handles of the old filtering rules
            gFilter.find_old_rules()

            # Start updating the filter sets!
            if args.table_family in ("ip","inet") or (args.table_family == "netdev" and not args.no_ipv4):
                gFilter.update_filter_set('ip')
            if args.table_family in ("ip6","inet") or (args.table_family == "netdev" and not args.no_ipv6):
                gFilter.update_filter_set('ip6')

            # If we're using --allow, need to add some extra rules
            if args.allow:
                gFilter.add_allow_rules()

            # If exceptions have been provided, add rules for them
            if args.exceptions:
                gFilter.add_exceptions()

            # If we're allowing established connections from denied IPs, add a rule for that
            if args.allow_established:
                gFilter.allow_established()

            # Add a final rule matching the policy if logging/counters are required
            gFilter.add_policy_logging_rule()

            # Delete the old rules
            gFilter.delete_old_rules()
        except (ValueError, subprocess.CalledProcessError, urllib.error.HTTPError, urllib.error.URLError):
            sys.exit(1)
