"""_summary_
"""
import json
import os
import datetime
import time
from dotenv import load_dotenv
from censys.search import CensysHosts
from censys.common.exceptions import CensysAPIException
import shodan
from typing import List



load_dotenv()  # Loads contents of the .env file into the environment
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")


class InfraTrackr:
    """_summary_"""

    def __init__(self, sig) -> None:
        self.sig = sig
        self.process_all = True
        self.shodan_query = None
        self.censys_query = None
        self.shodan_data = None
        self.censys_data = None
        self.first_seen = datetime.datetime.now().strftime('%Y-%m-%d')

    def create_results_folders(self) -> None:
        """_summary_"""
        root_path = "/home/ubuntu-lab/Documents/infratrackr"
        api_output_folders = ["shodan", "censys"]
        for folder in api_output_folders:
            path = os.path.join(root_path, folder)
            if not os.path.exists(path):
                os.makedirs(path)

    def write_query_output(self):
        """_summary_

        Args:
            data (_type_): _description_
        """
        self.shodan_results = f"/home/ubuntu-lab/Documents/infratrackr/shodan/{self.query}_{self.first_seen}.json"
        self.censys_results = f"/home/ubuntu-lab/Documents/infratrackr/censys/{self.query}_{self.first_seen}.json"
        if self.shodan_data is not None:
            with open(self.shodan_results, "a", encoding="utf-8") as outfile:
                outfile.write(json.dumps(self.shodan_data, indent=4))
                time.sleep(1)
        
        if self.censys_data is not None:
            with open(self.censys_results, "w", encoding="utf-8") as outfile:
                outfile.write(json.dumps(self.censys_data, indent=4))
                time.sleep(2)


    def process_hunt_rule(self, sig):
        """_summary_

        Args:
            target (_type_): _description_
        """
        print(f"[+] Processing rule: {sig}")

        with open(sig, "r", encoding="utf-8") as query_file:
            query_data = json.load(query_file)
            

        for _, data_holder in query_data.items():
            for data in data_holder:
                self.query = data["signature"]
                self.shodan_query = data["query_shodan"]
                self.censys_query = data["query_censys"]
                if self.censys_query is None:
                    print("[-] No query found")
                    continue
                
                print(self.query)
               
    def query_shodan_api(self) -> None:
        """_summary_"""
        print('[+] Submitting Shodan query')
        api = shodan.Shodan(SHODAN_API_KEY)
        try:
            results = api.search(self.shodan_query)
            print(f'Results found: {results["total"]}')
            for result in results["matches"]:
                self.render_shodan_output(result)
        except shodan.APIError as err:
            print(f"Error: {err}")

    def render_shodan_output(self, result) -> List[dict]:
        """_summary_

        Args:
            result (_type_): _description_
        """
        data_source = 'Shodan'
        first_seen = self.first_seen
        target_ip = result["ip_str"]
        port =  [services['port'] for services in result.get('data')]
        hostnames = result["hostnames"] or "N/A"
        country = result["location"]["country_code"]
        isp = result["isp"]
        org = result["org"]
        
        self.shodan_data = dict(data_source=data_source, first_seen=first_seen, target_ip=target_ip, port=port, hostnames=hostnames, country=country, isp=isp, org=org)
            
        self.write_query_output()

    def query_censys_api(self) -> None:
        """_summary_"""
        print('[+] Submitting Censys query')
        censys = CensysHosts()
        if self.censys_query == 'None':
            print("[-] No query found")
            return
        else:
            try:
                
                for censys_results in censys.search(self.censys_query):
                    self.censys_data = censys_results
                            
                    self.write_query_output()
                    
            except CensysAPIException as err:
                print(f'Error: {err}')
        

    def run(self) -> None:
        """_summary_"""
        for signature in self.sig:
            if self.process_all:
                self.process_hunt_rule(signature)
                self.create_results_folders()
                self.query_censys_api()
                #self.query_shodan_api()

                continue
            # self.prompt(target)
