# infratrack.py
#
# infratrack is a Python program to query GreyNoise, VirusTotal, Shodan, Censys
# for information on suspicious domains, IP addresses and TLS certificates.data on domains, file hashes, and IP addresses.  
# Future versions of infratrack will allow the user to graph and group identified infrastructure for tracking/hunting.
#
# github.com/mrippey
# twitter.com/@nahamike01
# 03 SEP 2022
from argparse import ArgumentParser
import sys
from shodan_censys_scan import ShodanCensysScan
import new_reg_domains
import ipaddr_summary
from domain_summary import DomainSummary
from core.args import ARGS_BASIC
from core.logs import LOG


def main():
    """Main function"""
    LOG.debug("Main program starting...")
    banner = """
██╗███╗   ██╗███████╗██████╗  █████╗ ████████╗██████╗  █████╗  ██████╗██╗  ██╗
██║████╗  ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██║██╔██╗ ██║█████╗  ██████╔╝███████║   ██║   ██████╔╝███████║██║     █████╔╝ 
██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║   ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║██║ ╚████║██║     ██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
Adversary Infrastructure Tracker [Infratrack]                                                                          
    """
    # idea extracted from: https://www.youtube.com/watch?v=Zf38qncahiU
    parser = ArgumentParser(
        description="Adversary Infrastructure Tracker [Infratrack]",
        parents=[ARGS_BASIC],
    )

    parser.add_argument("-hu", "--hunt", nargs="+", help="Targets to scan")
    parser.add_argument("-n", "--new", help="File containing queries to match")
    parser.add_argument("-i", "--ip", help="IP address to scan")
    parser.add_argument("-d", "--domain", help="Domain to scan")
 
    args = parser.parse_args()

    if args.hunt:
        LOG.info("Starting hunt...")
        print(banner)
        hunt = args.hunt
        processor = InfraTrackr(hunt)
        processor.run()

    elif args.new:
        LOG.info("Starting newly registered domain scan...")
        print(banner)
        new_reg_domains.rapidfuzz_multi_query(args.new)

    elif args.ip:
        LOG.info("Starting IP address scan...")
        print(banner)
        ipaddr_summary.validate_ip_addr(args.ip)
        

    elif args.domain:
        LOG.info("Starting domain scan...")
        print(banner)
        domain = args.domain 
        domain_summary = DomainSummary(domain)
        domain_summary.run()

    else:
        parser.print_help()
        LOG.error("Incorrect options/ no targets provided")
        exit(1)


if __name__ == "__main__":
    main()

