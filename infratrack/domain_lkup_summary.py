"""Domain Lookup Summary"""
import os
import sys
from dotenv import load_dotenv
import whois
from httpx import get
import httpx
from rich.console import Console
from rich import table
from core.logs import LOG


load_dotenv()
console = Console()

LOG.info("Starting domain_lkup_summary.py...")


class DomainSummary:
    """_summary_ - DomainSummary class"""

    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.vt_api = os.getenv("VT_API_KEY")
        self.api_key_header = {"x-apikey": self.vt_api}
        # VirusTotal API requests
        self.vt_api_basic_domain = (
            f"https://www.virustotal.com/api/v3/domains/{target_domain}"
        )
        self.vt_domain_commfiles = f"https://www.virustotal.com/api/v3/domains/{target_domain}/communicating_files"
        self.pdns_resolutions = []

    def get_vt_api_domain_info(self, target_domain):
        """_summary_ - VirusTotal API request for domain info"""
        print()
        LOG.debug("VT API GET request for %s", self.vt_api_basic_domain)
        try:
            response = get(self.vt_api_basic_domain, headers=self.api_key_header)

        except (httpx.HTTPError, httpx.ConnectTimeout):
            self.api_error_logging_crit("Could not connect. Check the URL for your API")
            

        results = response.json()
        LOG.debug("Received a response: %s", results)

        if results.get("error") and results.get("data") is None:
            print("There may be an issue with your search term. Try again.")
            sys.exit(1)
        data = results["data"]
        attrs = data["attributes"]
        last_analysis = attrs["last_analysis_stats"]
        mal = last_analysis["malicious"]

        if mal == 0:
            return f"{target_domain} is clean"
        return f"{target_domain} was identified as malicious by {str(mal)} vendors"

    def get_vt_api_comm_files(self, target_domain):
        """_summary_ - VirusTotal API request for communicating files"""

        LOG.debug("VT API GET request for %s", self.vt_domain_commfiles)
        try:
            response = get(self.vt_domain_commfiles, headers=self.api_key_header)

        except (httpx.HTTPError, httpx.ConnectTimeout):
            self.api_error_logging_crit("Could not connect. Check the URL for your API")

        results = response.json()

        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print(
                "N/A"
            )

        else:
            metadata = results["meta"]
            file_count = metadata["count"]

            if file_count == 0:

                return f"No communicating files with {target_domain}"

            return (
                f"{file_count} file(s) communicating with [bold white] {target_domain}"
            )

    def run(self):
        """_summary_ - Run the main code"""
        try:
            console.print(
                f"Querying WhoIs, VirusTotal, and RiskIQ for {self.target_domain}..."
            )
            self.combine_api_output_to_table()

        except whois.parser.PywhoisError as err:
            LOG.critical(
                "Error in WhoIs, a domain name not aligning with the RFCs may have been submitted."
            )
            print(err)

        except (httpx.HTTPError, httpx.ConnectTimeout):
            self.api_error_logging_crit(
                "Could not connect. Check the URL for your API."
            )

    def api_error_logging_crit(self, arg0):
        "Standard logging message for errors/exceptions in API use."
        LOG.critical("Error in API URL, check it again.")
        print(arg0)
        sys.exit(1)

    def combine_api_output_to_table(self):
        """_summary_ -- Combine all API output and build a table"""
        riskiq_user = os.getenv("RISKIQ_USER")
        riskiq_apikey = os.getenv("RISKIQ_KEY")
        auth = (riskiq_user, riskiq_apikey)
        data = {"query": self.target_domain}
        LOG.debug("RiskIQ API GET request for %s", self.target_domain)

        response = get(
            "https://api.riskiq.net/pt/v2/dns/passive", auth=auth, params=data
        )
        riq_api_results = response.json()

        LOG.debug("Received a response: %s", riq_api_results)
        for items in riq_api_results["results"]:
            pdns_resolutions = items["resolve"]
            first_seen = riq_api_results["firstSeen"]
            last_seen = riq_api_results["lastSeen"]

        domain_info = whois.whois(self.target_domain)

        infratrack_table = table.Table(
            title="Domain Summary",
            show_header=True,
            header_style="white",
            show_footer=False,
        )

        infratrack_table.add_column("IP", style="cyan")
        infratrack_table.add_column("Domain Name", style="green")
        infratrack_table.add_column("Name Server(s)", style="magenta")
        infratrack_table.add_column("Registrar", style="magenta")
        infratrack_table.add_column("First Seen", style="green")
        infratrack_table.add_column("Last Seen", style="green")
        infratrack_table.add_column("VirusTotal Report", style="red")
        infratrack_table.add_column("VirusTotal Communicating Files", justify="right", style="red")

        infratrack_table.add_row(
            str(pdns_resolutions),
            self.target_domain,
            str(domain_info.name_servers),
            domain_info.registrar,
            str(first_seen),
            str(last_seen),
            self.get_vt_api_domain_info(self.target_domain),
            self.get_vt_api_comm_files(self.target_domain),
        )

        console.print(infratrack_table)
