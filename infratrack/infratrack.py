from argparse import ArgumentParser
from core.args import ARGS_BASIC
from core.logs import LOG
from shodan_censys_scan import InfraTrackr
import new_reg_domains
import ipaddr_summary
import domain_summary


def main():
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
    # parser.add_argument('-a', '--all', action='store_true', help='Scan all targets')
    args = parser.parse_args()

    if args.hunt:
        LOG.info("Starting hunt...")
        print(banner)
        hunt = args.hunt
        processor = InfraTrackr(hunt)
        processor.run()

    elif args.new:
        LOG.info("Starting new domain scan...")
        print(banner)
        new_reg_domains.rapidfuzz_multi_query(args.new)

    elif args.ip:
        LOG.info("Starting IP address scan...")
        print(banner)
        ipaddr_summary.validate_ip_addr(args.ip)
        # ipaddr_summary.get_greynoise_data(args.ip)
        # ipaddr_summary.virustotal_api_req(args.ip)
        # ipaddr_summary.riskiq_api_pdns_req(args.ip)

    elif args.domain:
        LOG.info("Starting domain scan...")
        print(banner)
        domain_summary.validate_domain_input(args.domain)

    else:
        parser.print_help()
        LOG.error("Incorrect options/ no targets provided")
        exit(1)


if __name__ == "__main__":
    main()

