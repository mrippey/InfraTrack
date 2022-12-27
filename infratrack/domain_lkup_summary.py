"""Domain Lookup Summary"""
import os
from dotenv import load_dotenv
import whois
from httpx import get
import dns.resolver
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
        self.vt_domain_report = (
            f"https://www.virustotal.com/api/v3/domains/{target_domain}"
        )
        self.vt_domain_commfiles = f"https://www.virustotal.com/api/v3/domains/{target_domain}/communicating_files"
        self.pdns_resolutions = []

    def virustotal_api_req_domaininfo(self, target_domain):
        """_summary_ - VirusTotal API request for domain info"""
        print()
        LOG.debug("VT API GET request for %s", self.vt_domain_report)
        response = get(self.vt_domain_report, headers=self.api_key_header)
        results = response.json()
        LOG.debug("Received a response: %s", results)

        if results.get("error") and results.get("data") is None:
            return "[X] Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing..."
        data = results["data"]
        attrs = data["attributes"]
        last_analysis = attrs["last_analysis_stats"]
        mal = last_analysis["malicious"]

        if mal == 0:
            return f"{target_domain} is clean"
        return f"{target_domain} was identified as malicious by {str(mal)} vendors"
        


    def virustotal_api_req_commfiles(self, target_domain):
        """_summary_ - VirusTotal API request for communicating files"""

        LOG.debug("VT API GET request for %s", self.vt_domain_commfiles)
        response = get(self.vt_domain_commfiles, headers=self.api_key_header)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print(
                "Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing...",
                style="bold red",
            )

        else:
            metadata = results["meta"]
            file_count = metadata["count"]

            if file_count == 0:
               
                return f"No communicating files with {target_domain}"
               
            return f"{file_count} file(s) communicating with [bold white] {target_domain}"
    

    def run(self):
        """_summary_ - Run the main code"""
        try:
            self.combine_data_to_table()
        except dns.resolver.NXDOMAIN as err:
            console.print(err, style="bold red")

        except dns.resolver.NoAnswer as err:
            console.print(err, style="bold red")
            return "There was an issue with the domain name. Please check your input and try again."

    def combine_data_to_table(self):
        """_summary_ - Combine all relevant API data and create a table for output"""        
        console.print(
            f"[!] Grabbing results for {self.target_domain}: ", style="bold white"
            )
 
        try:
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

            infratrack_table.add_column("IP", style="dim")
            infratrack_table.add_column("Domain Name", style="dim")
            infratrack_table.add_column("Name Server(s)", style="dim")
            infratrack_table.add_column("Registrar", style="dim")
            infratrack_table.add_column("First Seen", style="dim")
            infratrack_table.add_column("Last Seen", style="dim")
            infratrack_table.add_column("VirusTotal Report", style="dim")
            infratrack_table.add_column("VirusTotal Communicating Files", style='dim')

            infratrack_table.add_row(
            str(pdns_resolutions),
            self.target_domain,
            str(domain_info.name_servers),
            domain_info.registrar,
            str(first_seen),
            str(last_seen),
            self.virustotal_api_req_domaininfo(self.target_domain),
            self.virustotal_api_req_commfiles(self.target_domain)
            )

            console.print(infratrack_table)

        except whois.parser.PywhoisError as err:
            print(err)
