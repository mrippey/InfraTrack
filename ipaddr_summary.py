import os
from core.logs import LOG
import time
from dotenv import load_dotenv
from rich.console import Console
from httpx import get, Response
import ipaddress
import whois

LOG.info("Starting...")

console = Console()

load_dotenv()

global target_ip
# target_ip = prompt("Enter IP address: ")
# print(f'Info for {target_ip}')

GN_API = os.getenv("GREYNOISE_API")
VT_API_KEY = os.getenv("VT_API_KEY")

greynoise_url = "https://api.greynoise.io/v3/community/"


def validate_ip_addr(target_ip):
    # target_ip = prompt("Enter IP address: ")
    # global target_ip
    #target_ip = prompt("Enter IP address: ")
    #target_ip = ipaddress.ip_address(target_ip)
    try:
        ipaddress.ip_address(target_ip)
        ip_info = whois.whois(target_ip)
        console.print(f"[*] IP info for {target_ip}: ", style='bold white')
        console.print(f'[!] Registrar: {ip_info.registrar}\n[!] Country: {ip_info.country}\n[!] Whois Server: {ip_info.whois_server}', style='bold green')
        time.sleep(1)
        print()
        get_greynoise_data(target_ip)
        time.sleep(1)
        virustotal_api_req(target_ip)
        time.sleep(1)
        print()
        riskiq_api_pdns_req(target_ip)
    except ValueError as err:
        console.print(err, style='bold red')
        return False
   
# TODO Rename this here and in `get_greynoise_data`
def get_greynoise_data(target_ip: str) -> Response:
    headers = {"Accept": "application/json", "key": GN_API}
    target_url = f"{greynoise_url}{target_ip}"
    LOG.debug("GreyNoise GET request for %s", target_url)
    response = get(target_url, headers=headers)
    console.print(f"[*] GreyNoise results for {target_ip}: ", style='bold white')
    result = response.json()
    LOG.debug("Received a response: %s", result)
    console.print(
        f"""[!] GreyNoise Noise tag: [bold red]{result["noise"]} \n[!] GreyNoise RIOT: [bold red] {result["riot"]} \n[!] GreyNoise Info: [bold red]{result["message"]} \n[!] Classification: [bold red]{result["classification"] if "classification" in result else None} \n[!] Name: [bold red]{result["name"] if "name" in result else None} \n[!] Last seen: {result["last_seen"] if "last_seen" in result else None} 
        """, style='bold green'
    )


def virustotal_api_req(target_ip):
    console.print(f"[*] VirusTotal results for {target_ip}: ", style='bold white')
    headers = {
        "x-apikey": VT_API_KEY,
    }
    vt_api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}"
    
    LOG.debug("VT API GET request for %s", vt_api_url)
    response = get(vt_api_url, headers=headers)
    results = response.json()

    LOG.debug("Received a response: %s", results)
    data = results["data"]
    attrs = data["attributes"]
    last_analysis = attrs["last_analysis_stats"]
    mal = last_analysis["malicious"]

    if mal == 0:
        console.print(f"[X] {target_ip} is clean", style='bold red')
    else:
        console.print(f"[!] {target_ip} was identified as malicious by {str(mal)} vendors", style='bold green')

    vt_api_comm_files = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}/communicating_files"

    LOG.debug("VT API GET request for %s", vt_api_comm_files)
    response = get(vt_api_comm_files, headers=headers)
    results = response.json()
    LOG.debug("Received a response: %s", results)
    vt_data = results['data']
    metadata = results['meta']
    file_count = metadata['count']


    file_names = [x['attributes']['magic'] for x in vt_data if x['attributes']['magic'] is not None]
      
    if file_count == 0:
        console.print(f'[X] No communicating files with {target_ip}', style='bold red')
    else:
        console.print(f'[!] {file_count} communicating files identified', style='bold green')
        console.print(f'[!] File Magic: [yellow]{file_names[0]}', style='bold green')
    
   
   
    vt_api_cert_info = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}/historical_ssl_certificates"
    LOG.debug("VT API GET request for %s", vt_api_cert_info)
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
        console.print('[X] No historical SSL certificates found', style='bold red')
    else:
        console.print(f'[!] {cert_count} historical SSL certificates for {target_ip}', style='bold green')
        console.print(f'[!] Serial #: {",".join(cert_serial_num)}', style='bold green')
        console.print(f'[!] Issuer CN: [bold yellow] {",".join(ca_cn)}', style='bold green')
        console.print(f'[!] Issuer Org: [bold yellow] {",".join(ca_issuer)}', style='bold green')
        console.print(f'[!] Subject Alternative Name: [bold yellow] {"".join(flattened_cert_san)}', style='bold green')
        console.print(f'[!] Subject CN: [bold yellow] {"".join(subj_cn)}', style='bold green')


def riskiq_api_pdns_req(target_ip: str) -> Response:
    try:
        riskiq_ip_resolutions(target_ip)
    except Exception as err:
        console.print(err, style='bold red')


# TODO Rename this here and in `riskiq_api_pdns_req`
def riskiq_ip_resolutions(target_ip):
    riskiq_user = os.getenv("RISKIQ_USER")
    riskiq_apikey = os.getenv("RISKIQ_API")
    auth = (riskiq_user, riskiq_apikey)
    data = {'query': target_ip}
    LOG.debug('RiskIQ API GET request for %s', target_ip)
    pdns_resolutions = []
    response = get('https://api.riskiq.net/pt/v2/dns/passive', auth=auth, params=data)
    riq_api_results = response.json()
    console.print(f'[*] RiskIQ results for {target_ip}: ', style='bold white')
    LOG.debug("Received a response: %s", riq_api_results)
    for items in riq_api_results['results']:
        pdns_resolutions = items['resolve']
        #pdns_resolutions = ('\n'.join(pdns_resolutions))

    if not pdns_resolutions:
        console.print('[X] No resolutions identified', style='bold red')
    else:
        console.print(f'[!] Resolution(s) identified: {pdns_resolutions}', style='bold green')

    console.print(f'[!] First_Seen: {riq_api_results["firstSeen"]}', style='bold green')
    console.print(f'[!] Last_Seen: {riq_api_results["lastSeen"]}', style='bold green')

