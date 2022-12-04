import os
import time
from dotenv import load_dotenv
import whois
import sys
import ipaddress
from httpx import get
from rich.console import Console
from core.logs import LOG
from riskiq_api_lookup import riskiq_ip_resolutions

load_dotenv()
console = Console()

LOG.info("Starting...")

class IPSummary:
    """_summary_ - IP address summary"""
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.greynoiseapi = "https://api.greynoise.io/v3/community/{target_ip}"
        self.greynoise_api_key = os.getenv("GREYNOISE_API")
        self.vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}"
        self.vt_comm_files = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}/communicating_files"
        self.vt_certs = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}/historical_ssl_certificates"
        self.vt_headers = os.getenv("VT_API_KEY")
       

    def get_greynoise_data(self, target_ip: str) :
        """_summary_ - GreyNoise API request"""
        LOG.debug("GreyNoise GET request for %s", target_ip)
        headers = {"key": self.greynoise_api_key}
        response = get(self.greynoiseapi, headers=headers)
        #console.print(f"[*] GreyNoise results for {target_ip}: ", style="bold white")
        self.result = response.json()
        LOG.debug("Received a response: %s", self.result)
        console.print(f'GreyNoise classification: [bold red]{self.result.get("classification")} ', style=" white")

    def virustotal_api_req(self, target_ip: str):
        #console.print(f"[*] VirusTotal results for {target_ip}: ", style="bold white")
        headers = {"x-apikey": self.vt_headers}

        LOG.debug("VT API GET request for %s", self.vt_url)
        response = get(self.vt_url, headers=headers)
        results = response.json()

        LOG.debug("Received a response: %s", results)
        data = results["data"]
        attrs = data["attributes"]
        last_analysis = attrs["last_analysis_stats"]
        mal = last_analysis["malicious"]

        if mal == 0:
            console.print(f"{target_ip} is clean", style="bold red")
        else:
            console.print(
                f"[blue]{target_ip} [white]was identified as malicious by [red]{str(mal)} vendors",
                style="bold green",
            )

    def virustotal_api_comm_files(self, target_ip: str):
        LOG.debug("VT API GET request for %s", self.vt_comm_files)
        headers = {"x-apikey": self.vt_headers}
        response = get(self.vt_comm_files, headers=headers)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        vt_data = results["data"]
        metadata = results["meta"]
        file_count = metadata["count"]

        self.file_names = [
            x["attributes"]["magic"]
            for x in vt_data
            if x["attributes"]["magic"] is not None
        ]

        if file_count == 0:
            console.print(
                f"No communicating files", style="bold red"
            )
        else:
            console.print(
                f"[blue]{file_count} communicating files identified", style=" white"
            )

    def virustotal_api_cert_info(self, target_ip: str):
        LOG.debug("VT API GET request for %s", self.vt_certs)
        headers = {"x-apikey": self.vt_headers}

        LOG.debug("VT API GET request for %s", self.vt_certs)
        response = get(self.vt_certs, headers=headers)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        vt_cert_data = list(results["data"])
        metadata = results["meta"]
        cert_count = metadata["count"]
        
        self.ca_issuer = [
            x["attributes"]["issuer"]["O"]
            for x in vt_cert_data
            if x["attributes"]["issuer"]["O"] is not None
        ]
    
        if cert_count == 0:
            console.print("No historical SSL certificates found", style="bold white")
        else:
            console.print(
                f"[white]{cert_count} historical SSL certificates for [green]{target_ip}",
                style="green",
            )
            console.print(f'Certificate Issuer: {self.ca_issuer}', style="bold white")

 
       
    def run(self):
       
        try:
           
            self._process_info()
        except ValueError as err:
            console.print(err, style="bold red")
            console.print("Invalid IP address", style="bold red")
            sys.exit(1)

   
    def _process_info(self):
        ipaddress.ip_address(self.target_ip)
        ip_info = whois.whois(self.target_ip)
        console.print("         IP Address Summary", style="bold white")
        console.print("         ---------------------", style="bold white")
        console.print(f"IP: {self.target_ip} ", style="bold white")
        console.print(
            f"Registrar: [green] {ip_info.registrar}\n[white]Country: [green] {ip_info.country}",
        )
        time.sleep(1)

        self.get_greynoise_data(self.target_ip)
        time.sleep(1)
        self.virustotal_api_req(self.target_ip)
        time.sleep(1)
        self.virustotal_api_comm_files(self.target_ip)
        time.sleep(1)
        self.virustotal_api_cert_info(self.target_ip)
        time.sleep(1)
        riskiq_ip_resolutions(self.target_ip)

