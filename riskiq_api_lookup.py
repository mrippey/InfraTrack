from dotenv import load_dotenv
import os
from httpx import get
from rich.console import Console
from core.logs import LOG

load_dotenv()
console = Console()

LOG.info("Starting...")

def riskiq_ip_resolutions(target_ip):
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
