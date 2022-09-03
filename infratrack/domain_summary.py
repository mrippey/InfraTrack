import os
from core.logs import LOG
import time
from dotenv import load_dotenv
import whois
from httpx import get
from ipaddr_summary import riskiq_ip_resolutions
import dns.resolver
from rich.console import Console


console = Console()

LOG.info("Starting...")

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
headers = {"x-apikey": VT_API_KEY}

class DomainSummary:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        # VirusTotal API requests
        self.vt_domain_report = f"https://www.virustotal.com/api/v3/domains/{target_domain}"
        self.vt_domain_commfiles = f"https://www.virustotal.com/api/v3/domains/{target_domain}/communicating_files"
        self.vt_domain_certinfo = f"https://www.virustotal.com/api/v3/domains/{target_domain}/historical_ssl_certificates"

    def virustotal_api_req_domaininfo(self, target_domain): 
        print()
        console.print(f"[*] Returning VirusTotal results for {target_domain}: ", style='bold white')
        headers = {"x-apikey": VT_API_KEY}
        LOG.debug("VT API GET request for %s", self.vt_domain_report)
        response = get(self.vt_domain_report, headers=headers)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print('[X] Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing...', style='bold red')

        else: 
            data = results["data"]
            attrs = data["attributes"]
            last_analysis = attrs["last_analysis_stats"]
            mal = last_analysis["malicious"]


        if mal == 0:
            console.print(f"[X] {target_domain} is clean", style='bold red')
        else:
            console.print(f"[!] {target_domain} was identified as malicious by {str(mal)} vendors", style='bold green')


    def virustotal_api_req_commfiles(self, target_domain):
        LOG.debug("VT API GET request for %s", self.vt_domain_commfiles)
        response = get(self.vt_domain_commfiles, headers=headers)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print('[X] Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing...', style='bold red')

        else:

            vt_data = results['data']
            metadata = results['meta']
            file_count = metadata['count']
            file_names = [x['attributes']['meaningful_name'] for x in vt_data if x['attributes']['meaningful_name'] is not None]
            file_magic = [x['attributes']['magic'] for x in vt_data if x['attributes']['magic'] is not None]


            if file_count == 0:
                console.print(f'[X] No communicating files with {target_domain}', style='bold red')

            else:
                console.print(f'[!] {file_count} file(s) communicating with [bold white] {target_domain}: [bold red]{",".join(file_names)}', style='bold green')

                console.print(f'[!] File type: [bold yellow] {",".join(file_magic)}', style='bold green')

    def virustotal_api_req_certinfo(self, target_domain):
        LOG.debug("VT API GET request for %s", self.vt_domain_certinfo)
        response = get(self.vt_domain_certinfo, headers=headers)
        results = response.json()
        LOG.debug("Received a response: %s", results)
        if results.get("error") and results.get("data") is None:
            console.print('[X] Either VirusTotal returned 0 results, or there was an error in your domain pattern. Continuing...', style='bold red')
    
        else:

            vt_cert_data = list(results['data'])
            metadata = results['meta']
            cert_count = metadata['count']
            cert_serial_num = [x['attributes']['serial_number'] for x in vt_cert_data if x['attributes']['serial_number'] is not None]
            ca_cn = [x['attributes']['issuer']['CN'] for x in vt_cert_data if x['attributes']['issuer']['CN'] is not None]
            ca_issuer = [x['attributes']['issuer']['O'] for x in vt_cert_data if x['attributes']['issuer']['O'] is not None]
            cert_san = [x['attributes']['extensions']['subject_alternative_name'] for x in vt_cert_data if x['attributes']['extensions']['subject_alternative_name'] is not None]
            flattened_cert_san = [val for san in cert_san for val in san]
            subj_cn = [x['attributes']['subject']['CN'] for x in vt_cert_data if x['attributes']['subject']['CN'] is not None]



            if cert_count == 0:
                console.print(f'[X] No historical SSL certificates for {target_domain}', style='bold red')
            else:
                console.print(f'[!] {cert_count} historical SSL certificates for {target_domain}', style='bold green')
                console.print(f'[!] Serial #: [bold yellow] {",".join(cert_serial_num)}', style='bold green')
                console.print(f'[!] Issuer CN: [bold yellow] {",".join(ca_cn)}', style='bold green')
                console.print(f'[!] Issuer Org: [bold yellow] {",".join(ca_issuer)}', style='bold green')
                console.print(f'[!] Subject Alternative Name: [bold yellow] {"".join(flattened_cert_san)}', style='bold green')
                console.print(f'[!] Subject CN: [bold yellow] {"".join(subj_cn)}', style='bold green')



    def run(self):
        try:
            if _ := whois.whois(self.target_domain):
                self.api_output()
        except dns.resolver.NXDOMAIN as e:
            console.print(e, style='bold red')
            return False

    
    def api_output(self):
        console.print(f'[!] Displaying results for {self.target_domain}: ', style='bold white')
        host_to_ip = dns.resolver.query(self.target_domain, 'A')
        for ipval in host_to_ip:
            console.print(f'[!] IP address: {ipval.to_text()}', style='bold green')
        domain_info = whois.whois(self.target_domain)
        console.print(f'[!] Registrar: {domain_info.registrar} \n[!] Name Servers; {domain_info.name_servers}', style='bold green')
        print()
        time.sleep(1)
        self.virustotal_api_req_domaininfo(self.target_domain)
        time.sleep(1)
        self.virustotal_api_req_commfiles(self.target_domain)
        time.sleep(1)
        self.virustotal_api_req_certinfo(self.target_domain)
        print()
        time.sleep(1)
        riskiq_ip_resolutions(self.target_domain)

