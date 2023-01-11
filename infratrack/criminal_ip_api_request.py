# criminal_ip_api_request.py 

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()


class GetCriminalIpApi:
    """Make GET request to CriminalIP API"""

    def __init__(self):
        self.crimip_api = os.getenv("CRIMIP_API")
       
        

    def get_criminalip_api_ip(self, target_ip: str):
        """get whether the IP address is malicious or not"""
        crimip_api_url = f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={target_ip}"
        params = {}
        headers = {"x-api-key": self.crimip_api}

        response = requests.get(crimip_api_url, params, headers=headers, timeout=5)

        api_results = response.json()

        is_malicious = api_results['is_malicious']

        time.sleep(1)
    
        return is_malicious

