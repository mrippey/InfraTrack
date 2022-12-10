#!/usr/bin/env python3
from argparse import ArgumentParser
import sys
from shodan_censys_scan import ShodanCensysScan
from ip_lkup_summary import IPSummary
from domain_lkup_summary import DomainSummary
from core.args import ARGS_BASIC
from core.logs import LOG


def main():
    """Main function"""
    LOG.debug("Main program starting...")
    print("""
██╗███╗   ██╗███████╗██████╗  █████╗ ████████╗██████╗  █████╗  ██████╗██╗  ██╗
██║████╗  ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██║██╔██╗ ██║█████╗  ██████╔╝███████║   ██║   ██████╔╝███████║██║     █████╔╝ 
██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║   ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║██║ ╚████║██║     ██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                         
    """)
    parser = ArgumentParser(
        description="Adversary Infrastructure Tracker [Infratrack]",
        parents=[ARGS_BASIC],
    )

    parser.add_argument("-hu", "--hunt", nargs="+", help="Targets to scan")
    parser.add_argument("-i", "--ip", help="IP address to scan")
    parser.add_argument("-d", "--domain", help="Domain to scan")

    args = parser.parse_args()

    if args.hunt:
        LOG.info("Starting hunt...")
        hunt = args.hunt
        processor = ShodanCensysScan(hunt)
        processor.run()

    elif args.ip:
        LOG.info("Starting IP address scan...")
        ip = args.ip
        processor = IPSummary(ip)
        processor.run()
      
    elif args.domain:
        LOG.info("Starting domain scan...")
        domain = args.domain 
        domain_summary = DomainSummary(domain)
        domain_summary.run()

    else:
        parser.print_help()
        LOG.error("Be sure you provided an argument using '--xxx' and the target.")
        sys.exit(1)
 

if __name__ == "__main__":
    main()
