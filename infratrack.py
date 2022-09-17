#!/usr/bin/env python
from argparse import ArgumentParser
import sys
from shodan_censys_scan import ShodanCensysScan
import new_reg_domains
from ip_domain_info import DomainSummary, IPSummary
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
Adversary Infrastructure Tracker [Infratrack]                                                                          
    """)
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
        hunt = args.hunt
        processor = ShodanCensysScan(hunt)
        processor.run()

    elif args.new:
        LOG.info("Starting new domain scan...")
        new_reg_domains.rapidfuzz_multi_query(args.new)

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
        LOG.error("Incorrect options/ no targets provided")
        sys.exit(1)
 

if __name__ == "__main__":
    main()
