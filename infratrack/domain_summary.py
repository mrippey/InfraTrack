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

global target_domain 
VT_API_KEY = os.getenv("VT_API_KEY")


def validate_domain_input(target_domain):
    try:
        if _ := whois.whois(target_domain):
            display_domain_info(target_domain)
        else:
            console.print(f'[X] {target_domain} is not a valid domain name', style='bold red')
    except Exception as e:
        console.print(f'[X] {e}', style='bold red')


# TODO Rename this here and in `validate_domain_name`
def display_domain_info(target_domain):
    console.print(f'[!] Displaying results for {target_domain}', style='bold white')
    get_domain_info(target_domain)
    time.sleep(1)
    virustotal_api_req(target_domain)
    #vt_api_tls_cert_info(target_domain)
    time.sleep(1)
    print()
    riskiq_ip_resolutions(target_domain)
        

def get_domain_info(target_domain):
    try:
        host_to_ip = dns.resolver.query(target_domain, 'A')
        for host in host_to_ip:
            console.print(f'[!] IP Address: {host}', style='bold green')
        domain_info = whois.whois(target_domain)
        console.print(f'[!] Registrar: {domain_info.registrar} \n[!] Name Servers; {domain_info.name_servers}', style='bold green')

    except dns.resolver.NXDOMAIN as e:
        console.print(f'[X] No WhoIs DNS query names found for {target_domain}', style='bold red')

    except dns.resolver.NoAnswer as err:
        console.print(f'[X] {err}', style='bold red')

    except dns.exception.Timeout as err:
        console.print(f'[X] DNS query timed out for {target_domain}', style='bold red')
        
    except dns.exception.DNSException as err:
        console.print(f'[X] Exception: {err}', style='bold red')
            

def virustotal_api_req(target_domain):
    print()
    console.print(f"[*] Returning VirusTotal results for {target_domain}: ", style='bold white')

    headers = {"x-apikey": VT_API_KEY}
    vt_api_url = f"https://www.virustotal.com/api/v3/domains/{target_domain}"
    LOG.debug("VT API GET request for %s", vt_api_url)
    response = get(vt_api_url, headers=headers)
    results = response.json()
    LOG.debug("Received a response: %s", results)
    data = results["data"]
    attrs = data["attributes"]
    last_analysis = attrs["last_analysis_stats"]
    mal = last_analysis["malicious"]
    if mal == 0:
        console.print(f"[X] {target_domain} is clean", style='bold red')
    else:
        console.print(f"[!] {target_domain} was identified as malicious by {str(mal)} vendors", style='bold green')

    vt_api_comm_files = f"https://www.virustotal.com/api/v3/domains/{target_domain}/communicating_files"

    LOG.debug("VT API GET request for %s", vt_api_comm_files)
    response = get(vt_api_comm_files, headers=headers)
    results = response.json()
    LOG.debug("Received a response: %s", results)
    
    vt_data = list(results['data'])
    metadata = results['meta']
    file_count = metadata['count']
    file_names = [x['attributes']['meaningful_name'] for x in vt_data if x['attributes']['meaningful_name'] is not None]
    file_magic = [x['attributes']['magic'] for x in vt_data if x['attributes']['magic'] is not None]
    

    if file_count == 0:
        console.print(f'[X] No communicating files with {target_domain}', style='bold red')

    else:
        console.print(f'[!] {file_count} file(s) communicating with [bold white] {target_domain}: [bold red]{",".join(file_names)}', style='bold green')

        console.print(f'[!] File type: [bold yellow] {",".join(file_magic)}', style='bold green')
        

    vt_api_cert_info = f"https://www.virustotal.com/api/v3/domains/{target_domain}/historical_ssl_certificates"
    LOG.debug("VT API GET request for %s", vt_api_comm_files)
    response = get(vt_api_cert_info, headers=headers)
    results = response.json()
    LOG.debug("Received a response: %s", results)
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
        



      

    