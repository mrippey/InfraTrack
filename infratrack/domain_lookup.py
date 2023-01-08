"""domain_lookup.py"""
import os
import sys
import time

from dotenv import load_dotenv
import whois
from httpx import get
import httpx
from rich.console import Console
from rich import table
from rich.box import MINIMAL
from core.logs import LOG
from error import StandardApiErrorMessage


load_dotenv()
console = Console()


class DomainLookup:
    """_summary_ - DomainSummary class"""

    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.vt_api_key = os.getenv("VT_API_KEY")
        self.vt_api_key_header = {"x-apikey": self.vt_api_key}
        # VirusTotal API requests
        self.vt_api_basic_domain = (
            f"https://www.virustotal.com/api/v3/domains/{target_domain}"
        )
        self.vt_domain_commfiles = f"https://www.virustotal.com/api/v3/domains/{target_domain}/communicating_files"
        self.pdns_resolutions = []

    def get_vt_api_domain_info(self, target_domain: str) -> int:
        """_summary_ - VirusTotal API request for domain info"""
        print()
        LOG.debug("VT API GET request for %s", self.vt_api_basic_domain)
        try:
            response = get(self.vt_api_basic_domain, headers=self.vt_api_key_header)
            time.sleep(1)
        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
            LOG.critical("Error in API URL")
            raise StandardApiErrorMessage("There may be an error in your API URL") from exc
            
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
        return f"{target_domain} [white]was identified as malicious by [red]{str(mal)} vendors"

    def get_vt_api_comm_files(self, target_domain: str) -> int:
        """_summary_ - VirusTotal API request for communicating files"""

        LOG.debug("VT API GET request for %s", self.vt_domain_commfiles)
        try:
            response = get(self.vt_domain_commfiles, headers=self.vt_api_key_header)
            time.sleep(1)

        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
            LOG.critical("Error in API URL")
            raise StandardApiErrorMessage("There may be an error in your API URL") from exc

        results = response.json()

        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print("N/A")

        else:
            metadata = results["meta"]
            file_count = metadata["count"]

            if file_count == 0:

                return f"[white]No communicating files with {target_domain}"

            return (
                f"{file_count} [white]file(s) communicating with {target_domain}"
            )

    def run(self):
        """_summary_ - Run the main code"""
        try:
            LOG.info("Starting domain_lkup_summary.py...")
            console.print(f"Querying API services for {self.target_domain}...")
            console.print(self.combine_api_output_to_table())

        except whois.parser.PywhoisError as err:
            LOG.critical(
                "Error in WhoIs, a domain name not aligning with the RFCs may have been submitted."
            )
            print(f"WhoIs -- {err}")

        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
            LOG.critical("Error in API URL")
            raise StandardApiErrorMessage("There may be an error in your API URL") from exc

    def combine_api_output_to_table(self) -> table:

        """_summary_ -- Combine all API output and build a table"""
        riskiq_user = os.getenv("RISKIQ_USER")
        riskiq_apikey = os.getenv("RISKIQ_KEY")
        auth = (riskiq_user, riskiq_apikey)
        data = {"query": self.target_domain}
        LOG.debug("RiskIQ API GET request for %s", self.target_domain)
        try:
            response = get(
                "https://api.riskiq.net/pt/v2/dns/passive", auth=auth, params=data
             )
            time.sleep(1)

        except (httpx.HTTPError, httpx.ConnectTimeout) as exc:
            LOG.critical("Error in API URL")
            raise StandardApiErrorMessage("There may be an error in your API URL") from exc

        riq_api_results = response.json()

        LOG.debug("Received a response: %s", riq_api_results)
        for items in riq_api_results["results"]:
            pdns_resolutions = items["resolve"]
            first_seen = riq_api_results["firstSeen"]
            last_seen = riq_api_results["lastSeen"]
              
        domain_info = whois.whois(self.target_domain)

        if domain_info.registrar is None:
            domain_info.registrar = "Not found"

        # Idea for vertical output: https://github.com/3c7/bazaar/blob/main/malwarebazaar/output.py
        domain_summ_table = table.Table(
            show_header=False, show_footer=False, box=MINIMAL
        )

        domain_summ_table.add_column()
        domain_summ_table.add_column(overflow="fold")

        try:
            domain_summ_table.add_row(
                "[white]Domain Summary",
                f"[white]IP:          {str(pdns_resolutions)}\n"
                f"[white]First Seen:  {str(first_seen)}\n"
                f"[white]Last Seen:   {str(last_seen)}\n",
            )

            domain_summ_table.add_row(
                "[white]Domain Info",
                f"[white]Domain Name:     {self.target_domain}\n"
                f"[white]Name Server(s):  {str(domain_info.name_servers) or 'Not Found'}\n"
                f"[white]Registrar:       {domain_info.registrar or 'Not Found'}\n",
            )

            domain_summ_table.add_row(
                "[white]VirusTotal",
                f"[white]Virus Total Report:  {self.get_vt_api_domain_info(self.target_domain)}\n"
                f"[white]Communicating Files:  {self.get_vt_api_comm_files(self.target_domain)}\n",
            )

        except Exception:
            console.print_exception(show_locals=True)
            sys.exit(1)
        print()
        return domain_summ_table