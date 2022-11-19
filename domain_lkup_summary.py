import os
import time
from dotenv import load_dotenv
import whois
from httpx import get
import dns.resolver
from rich.console import Console
from core.logs import LOG
from riskiq_api_lookup import riskiq_ip_resolutions

load_dotenv()
console = Console()

LOG.info("Starting Domain Lookup...")


class DomainSummary:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.vt_api = os.getenv("VT_API_KEY")
        self.api_key_header = {"x-apikey": self.vt_api}
        # VirusTotal API requests
        self.vt_domain_report = (
            f"https://www.virustotal.com/api/v3/domains/{target_domain}"
        )
        self.vt_domain_commfiles = f"https://www.virustotal.com/api/v3/domains/{target_domain}/communicating_files"
        self.vt_domain_certinfo = f"https://www.virustotal.com/api/v3/domains/{target_domain}/historical_ssl_certificates"

    def virustotal_api_req_domaininfo(self, target_domain):
        """_summary_ - VirusTotal API request for domain info"""
        print()
        console.print(
            f"[!] VirusTotal results for {target_domain}: ",
            style="bold white",
        )

        LOG.debug("VT API GET request for %s", self.vt_domain_report)
        response = get(self.vt_domain_report, headers=self.api_key_header)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print(
                "[X] Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing...",
                style="bold red",
            )

        else:
            data = results["data"]
            attrs = data["attributes"]
            last_analysis = attrs["last_analysis_stats"]
            mal = last_analysis["malicious"]

        if mal == 0:
            console.print(f"[X] {target_domain} is clean", style="bold red")
        else:
            console.print(
                f"[!] {target_domain} was identified as malicious by {str(mal)} vendors",
                style="bold green",
            )

    def virustotal_api_req_commfiles(self, target_domain):
        """_summary_ - VirusTotal API request for communicating files"""

        LOG.debug("VT API GET request for %s", self.vt_domain_commfiles)
        response = get(self.vt_domain_commfiles, headers=self.api_key_header)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print(
                "[X] Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing...",
                style="bold red",
            )

        else:
            metadata = results["meta"]
            file_count = metadata["count"]
           
            if file_count == 0:
                console.print(
                    f"[X] No communicating files with {target_domain}", style="bold red"
                )

            else:
                console.print(
                    f'[!] {file_count} file(s) communicating with [bold white] {target_domain}: [bold red]{",".join(self.file_names)}',
                    style="bold green",
                )

    def virustotal_api_req_certinfo(self, target_domain):
        """_summary_ - VirusTotal API request for historical SSL certificates"""
        LOG.debug("VT API GET request for %s", self.vt_domain_certinfo)
        response = get(self.vt_domain_certinfo, headers=self.api_key_header)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print(
                "[X] Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing...",
                style="bold red",
            )

        else:

            vt_cert_data = list(results["data"])
            metadata = results["meta"]
            cert_count = metadata["count"]
            self.ca_issuer = [
            x["attributes"]["issuer"]["O"]
            for x in vt_cert_data
            if x["attributes"]["issuer"]["O"] is not None
        ]
          
            if cert_count == 0:
                console.print(
                    f"[X] No historical SSL certificates for {target_domain}",
                    style="bold red",
                )
            else:
                console.print(
                    f"[!] {cert_count} historical SSL certificates for {target_domain}",
                    style="bold green",
                )
     
                console.print(f'Certificate Issuer: {",".join(self.ca_issuer)}', style="bold green")

    def run(self):
        """_summary_ - Run the VirusTotal API requests"""
        try:
            if _ := whois.whois(self.target_domain):
                self.api_output()
        except dns.resolver.NXDOMAIN as err:
            console.print(err, style="bold red")

        except dns.resolver.NoAnswer as err:
            console.print(err, style="bold red")
            return "There was an issue with the domain name. Please check your input and try again."

    def api_output(self):
        """_summary_ - Output VirusTotal API results"""
        console.print(
            f"[!] Displaying results for {self.target_domain}: ", style="bold white"
        )
        host_to_ip = dns.resolver.query(self.target_domain, "A")
        for ipval in host_to_ip:
            console.print(f"[!] IP address: {ipval.to_text()}", style="bold green")
        domain_info = whois.whois(self.target_domain)
        console.print(
            f"[!] Registrar: {domain_info.registrar} \n[!] Name Servers; {domain_info.name_servers}",
            style="bold green",
        )
      
        time.sleep(1)
        self.virustotal_api_req_domaininfo(self.target_domain)
        time.sleep(1)
        self.virustotal_api_req_commfiles(self.target_domain)
        time.sleep(1)
        self.virustotal_api_req_certinfo(self.target_domain)
        print()
        time.sleep(1)
        riskiq_ip_resolutions(self.target_domain)
