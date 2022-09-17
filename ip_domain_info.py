import os
import time
from dotenv import load_dotenv
import whois
import json
import sys
import ipaddress
from httpx import get
import dns.resolver
from rich.console import Console
from core.logs import LOG

load_dotenv()
console = Console()

LOG.info("Starting...")


def riskiq_api_pdns_req( target_ip: str):
   """_summary_ - RiskIQ Passive DNS API request"""
    try:
        riskiq_ip_resolutions(target_ip)
    except Exception as err:
        console.print(err, style="bold red")

def riskiq_ip_resolutions( target_ip):
    riskiq_user = os.getenv("RISKIQ_USER")
    riskiq_apikey = os.getenv("RISKIQ_API")
    auth = (riskiq_user, riskiq_apikey)
    data = {"query": target_ip}
    LOG.debug("RiskIQ API GET request for %s", target_ip)
    pdns_resolutions = []
    response = get(
            "https://api.riskiq.net/pt/v2/dns/passive", auth=auth, params=data
        )
    riq_api_results = response.json()
    console.print(f"[*] RiskIQ results for {target_ip}: ", style="bold white")
    LOG.debug("Received a response: %s", riq_api_results)
    for items in riq_api_results["results"]:
        pdns_resolutions = items["resolve"]
    if not pdns_resolutions:
        console.print("[X] No resolutions identified", style="bold red")
    else:
        console.print(
                f"[!] Resolution(s) identified: {pdns_resolutions}", style="bold green"
            )

        console.print(
            f'[!] First_Seen: {riq_api_results["firstSeen"]}', style="bold green"
        )
        console.print(
            f'[!] Last_Seen: {riq_api_results["lastSeen"]}', style="bold green"
        )

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
        console.print(f"[*] GreyNoise results for {target_ip}: ", style="bold white")
        self.result = response.json()
        LOG.debug("Received a response: %s", self.result)
        console.print(f'[!] GreyNoise Noise tag: [bold red]{self.result.get("noise")} ', style="bold white")

    def virustotal_api_req(self, target_ip: str):
       """_summary_ - VirusTotal API request"""
        console.print(f"[*] VirusTotal results for {target_ip}: ", style="bold white")
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
            console.print(f"[X] {target_ip} is clean", style="bold red")
        else:
            console.print(
                f"[!] {target_ip} was identified as malicious by {str(mal)} vendors",
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
                f"[X] No communicating files with {target_ip}", style="bold red"
            )
        else:
            console.print(
                f"[!] {file_count} communicating files identified", style="bold green"
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
        cert_serial_num = [
            x["attributes"]["serial_number"]
            for x in vt_cert_data
            if x["attributes"]["serial_number"] is not None
        ]
        self.ca_cn = [
            x["attributes"]["issuer"]["CN"]
            for x in vt_cert_data
            if x["attributes"]["issuer"]["CN"] is not None
        ]
        self.ca_issuer = [
            x["attributes"]["issuer"]["O"]
            for x in vt_cert_data
            if x["attributes"]["issuer"]["O"] is not None
        ]
        self.cert_san = [
            x["attributes"]["extensions"]["subject_alternative_name"]
            for x in vt_cert_data
            if x["attributes"]["extensions"]["subject_alternative_name"] is not None
        ]
        #flattened_cert_san = [val for san in cert_san for val in san]
        self.subj_cn = [
            x["attributes"]["subject"]["CN"]
            for x in vt_cert_data
            if x["attributes"]["subject"]["CN"] is not None
        ]
    
        if cert_count == 0:
            console.print("[X] No historical SSL certificates found", style="bold red")
        else:
            console.print(
                f"[!] {cert_count} historical SSL certificates for {target_ip}",
                style="bold green",
            )
    
        api_obj = {
                "target_domain": target_ip,
                "GreyNoise_RIOT": self.result.get("riot"),
                "GreyNoise_INFO": self.result.get("message"),
                "GreyNoise_Classification": self.result.get("classification")  if "classification" in self.result else None,
                "GreyNoise_Name": self.result.get("name") if "name" in self.result else None,
                "GreyNoise_Last_Seen": self.result.get("last_seen") if "last_seen" in self.result else None,
                "file_magic": self.file_names,
                "communicating_files": self.file_names[0] if self.file_names else None,
                "ssl_cert_serial": cert_serial_num,
                "ssl_cert_ca_cn": self.ca_cn,
                "ssl_cert_ca_issuer": self.ca_issuer,
                "ssl_cert_san": self.cert_san,
                "ssl_cert_subj_cn": self.subj_cn,
                }
        with open(f"{target_ip}_api_output.json", "w") as outfile:
            json.dump(api_obj, outfile, indent=4)

    
    def run(self):
       
        try:
       
            ipaddress.ip_address(self.target_ip)
            ip_info = whois.whois(self.target_ip)
            console.print(f"[*] Whois info for {self.target_ip}: ", style="bold white")
            console.print(
                f"[!] Registrar: {ip_info.registrar}\n[!] Country: {ip_info.country}\n[!] Whois Server: {ip_info.whois_server}",
            style="bold green",
            )
            time.sleep(1)
            print()
            
            #console.print(Columns(self.get_content(), expand=True))
           
            self.get_greynoise_data(self.target_ip)
            print()
            time.sleep(1)
            self.virustotal_api_req(self.target_ip)
            time.sleep(1)
            self.virustotal_api_comm_files(self.target_ip)
            time.sleep(1)
            self.virustotal_api_cert_info(self.target_ip)
            time.sleep(1)
            print()
            riskiq_api_pdns_req(self.target_ip)
            print()
      
       
            console.print(f"[*] Full API output saved to: {self.target_ip}_api_output.json")

        except ValueError as err:
            console.print(err, style="bold red")
            console.print("[X] Invalid IP address", style="bold red")
            sys.exit(1)


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
            f"[!] Returning VirusTotal results for {target_domain}: ",
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

            vt_data = results["data"]
            metadata = results["meta"]
            file_count = metadata["count"]
            self.file_names = [
                x["attributes"]["meaningful_name"]
                for x in vt_data
                if x["attributes"]["meaningful_name"] is not None
            ]
            self.file_magic = [
                x["attributes"]["magic"]
                for x in vt_data
                if x["attributes"]["magic"] is not None
            ]

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
            cert_serial_num = [
                x["attributes"]["serial_number"]
                for x in vt_cert_data
                if x["attributes"]["serial_number"] is not None
            ]
            self.ca_cn = [
                x["attributes"]["issuer"]["CN"]
                for x in vt_cert_data
                if x["attributes"]["issuer"]["CN"] is not None
            ]
            self.ca_issuer = [
                x["attributes"]["issuer"]["O"]
                for x in vt_cert_data
                if x["attributes"]["issuer"]["O"] is not None
            ]
            self.cert_san = [
                x["attributes"]["extensions"]["subject_alternative_name"]
                for x in vt_cert_data
                if x["attributes"]["extensions"]["subject_alternative_name"] is not None
            ]
            flattened_cert_san = [val for san in self.cert_san for val in san]
            self.subj_cn = [
                x["attributes"]["subject"]["CN"]
                for x in vt_cert_data
                if x["attributes"]["subject"]["CN"] is not None
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
             
            api_obj = {
                "target_domain": target_domain,
                "file_names": self.file_names,
                "file_magic": self.file_magic,
                "ssl_cert_serial": cert_serial_num,
                "ssl_cert_ca_cn": self.ca_cn,
                "ssl_cert_ca_issuer": self.ca_issuer,
                "ssl_cert_san": self.cert_san,
                "ssl_cert_subj_cn": self.subj_cn,
                }
            with open(f"{target_domain}_api_output.json", "w") as outfile:
                json.dump(api_obj, outfile, indent=4)

            console.print('[*] Full API output saved to: ' + f"{target_domain}_api_output.json")



    def run(self):
        """_summary_ - Run the VirusTotal API requests"""
        try:
            if _ := whois.whois(self.target_domain):
                self.api_output()
        except dns.resolver.NXDOMAIN as err:
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
