"""_summary_ -- ip_lkup_summary.py"""
import os
import sys
import ipaddress
from rich import table
from rich.console import Console
from dotenv import load_dotenv
import whois
from httpx import get
import httpx
from core.logs import LOG


load_dotenv()
console = Console()

VIRUSTOTAL_API= os.getenv("VT_API_KEY")
GREYNOISE_API = os.getenv("GREYNOISE_API")

class IPSummary:
    """_summary_ - IP address summary"""

    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.greynoise_api_url = f"https://api.greynoise.io/v3/community/{target_ip}"
        self.vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}"
        self.vt_comm_files = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}/communicating_files"
        self.vt_ip_resolutions = (
            f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}/resolutions"
        )
        self.gn_result = {}

    def get_greynoise_api(self, target_ip: str):
        """_summary_ - GreyNoise API request
        Args:
        target_ip (str): The IP address you want to investigate.
        """
        LOG.debug("GreyNoise GET request for %s", target_ip)
        headers = {"key": GREYNOISE_API}
        try:
            response = get(self.greynoise_api_url, headers=headers)
        except (httpx.HTTPError, httpx.ConnectTimeout):
            self.api_error_logging_crit(
                "Could not connect. Check the URL for your API."
            )

        self.gn_result = response.json()
        LOG.debug("Received a response: %s", self.gn_result)

    def get_vt_api_ip_info(self, target_ip: str):
        """_summary_
        Args:
        target_ip (str): The IP address you want to investigate.
        """
        headers = {"x-apikey": VIRUSTOTAL_API}

        LOG.debug("VT API GET request for %s", self.vt_url)

        try:

            response = get(self.vt_url, headers=headers)

        except (httpx.HTTPError, httpx.ConnectTimeout):
            self.api_error_logging_crit(
                "Could not connect. Check the URL for your API."
            )

        results = response.json()

        LOG.debug("Received a response: %s", results)
        data = results["data"]
        attrs = data["attributes"]
        last_analysis = attrs["last_analysis_stats"]
        mal = last_analysis["malicious"]

        if mal == 0:
            return f"{target_ip} is clean"

        return (
            f"{target_ip} [white]was identified as malicious by [red]{str(mal)} vendors"
        )

    def get_vt_api_ip_resolutions(self, target_ip: str):
        """_summary_
        Args:
        target_ip (str): The IP address you want to investigate.
        """
        LOG.debug("VT API GET request for %s", self.vt_ip_resolutions)
        headers = {"x-apikey": VIRUSTOTAL_API}

        LOG.debug("VT API GET request for %s", self.vt_ip_resolutions)

        try:
            response = get(self.vt_ip_resolutions, headers=headers)

        except (httpx.HTTPError, httpx.ConnectTimeout):
            self.api_error_logging_crit(
                "Could not connect. Check the URL for your API."
            )

        vt_results = response.json()
        LOG.debug("Received a response: %s", vt_results)
        vt_data = vt_results["data"]

        hist_resolutions = [
            x["attributes"]["host_name"]
            for x in vt_data
            if x["attributes"]["host_name"] is not None
        ]

        return (
            hist_resolutions
            if isinstance(hist_resolutions, list)
            else f"No historical domain resolutions for {target_ip} found."
        )

    def run(self):
        """_summary_ -- Run the program."""
        LOG.info("Starting ip_lkup_summary.py")
        try:
            self.build_table_from_output()
        except ipaddress.AddressValueError as err:
            console.print(err, style="bold red")
            console.print("Invalid IP address", style="bold red")
            sys.exit(1)

    def api_error_logging_crit(self, arg0):
        """Standard logging message for errors/exceptions in API use."""
        LOG.critical("Error in API URL, check it again.")
        print(arg0)
        sys.exit(1)

    def build_table_from_output(self):
        """_summary_ -- Combine all API output and build a table"""

        riskiq_user = os.getenv("RISKIQ_USER")
        riskiq_apikey = os.getenv("RISKIQ_KEY")
        auth = (riskiq_user, riskiq_apikey)
        data = {"query": self.target_ip}

        LOG.debug("RiskIQ API GET request for %s", self.target_ip)
        response = get(
            "https://api.riskiq.net/pt/v2/dns/passive", auth=auth, params=data
        )
        riq_api_results = response.json()

        LOG.debug("Received a response: %s", riq_api_results)
        for _ in riq_api_results["results"]:
            #pdns_resolutions = items["resolve"]
            first_seen = riq_api_results["firstSeen"]
            last_seen = riq_api_results["lastSeen"]

        ip_whois_info = whois.whois(self.target_ip)

        ip_summ_table = table.Table(
            title="IP Summary",
            show_header=True,
            header_style="white",
            show_footer=False,
        )

        ip_summ_table.add_column("IP", style="cyan")
        ip_summ_table.add_column("Registrar", style="magenta")
        ip_summ_table.add_column("Greynoise Report", style="red")
        ip_summ_table.add_column("VirusTotal Classification", justify="center", style="red")
        ip_summ_table.add_column(
            "VirusTotal Historical Resolutions", justify="center", style="red"
        )
        ip_summ_table.add_column("First Seen", justify="right", style="green")
        ip_summ_table.add_column("Last Seen", justify="right", style="green")
        
        try:
            ip_summ_table.add_row(
                self.target_ip,
                ip_whois_info.registrar,
                str(self.gn_result.get("classification")),
                self.get_vt_api_ip_info(self.target_ip),
                str(self.get_vt_api_ip_resolutions(self.target_ip)),
                str(first_seen),
                str(last_seen),
            )
        except Exception:
            console.print_exception(show_locals=True)

        console.print(ip_summ_table)
        print()
