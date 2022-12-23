"""RiskIQ API Lookup"""


from dotenv import load_dotenv
import os
from httpx import get
from rich.console import Console
from core.logs import LOG

load_dotenv()
console = Console()

LOG.info("Starting...")

def riskiq_ip_resolutions(target_ip):
"""Contact RiskIQ API endpoint & get first_seen
	last_seen, and DNS resolution information"""
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
  
    LOG.debug("Received a response: %s", riq_api_results)
    for items in riq_api_results["results"]:
        pdns_resolutions = items["resolve"]
    if not pdns_resolutions:
        console.print("[white]No resolutions identified")
    else:
        console.print(
                f"[white]Resolution(s): [green]{pdns_resolutions}"
            )

        console.print(
            f'[white]First_Seen: [magenta]{riq_api_results["firstSeen"]}'
        )
        console.print(
            f'[white]Last_Seen: [magenta]{riq_api_results["lastSeen"]}'
        )
        print()
