"""Shodan Censys Scan"""
import json
import os
import datetime
import csv
from rich.console import Console
from typing import List
from dotenv import load_dotenv
from censys.search import CensysHosts
from censys.common.exceptions import CensysAPIException
import shodan

console = Console()

load_dotenv()  # Loads contents of the .env file into the environment
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")


class ShodanCensysScan:
    """ShodanCensysScan class"""

    def __init__(self, sig: str) -> None:
        self.sig = sig
        self.process_all = True
        self.shodan_query = None
        self.censys_query = None
        self.shodan_data = None
        self.censys_data = None
        self.todays_date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    @classmethod
    def create_folders_for_output(cls) -> None:
        """Create results folders"""
        root_path = "/Users/m_a_t/Documents/Python_Projects/infratrackr"
        api_output_folders = ["shodan", "censys"]
        for folder in api_output_folders:
            path = os.path.join(root_path, folder)
            if not os.path.exists(path):
                os.makedirs(path)

    def write_query_output(self):
        """Write query output to file"""
        self.shodan_results = f"/Users/m_a_t/Documents/Python_Projects/infratrackr/shodan/{self.query}_{self.todays_date}.csv"
        self.censys_results = f"/Users/m_a_t/Documents/Python_Projects/infratrackr/censys/{self.query}_{self.todays_date}.csv"
        
        if self.shodan_data is not None:
            file_exists = os.path.isfile(self.shodan_results)
            fieldnames=['ip', 'todays_date', 'last_seen', 'port', 'hostnames', 'org']
            with open(self.shodan_results, "a", encoding='utf-8') as output_file:
                writer = csv.DictWriter(output_file, fieldnames=fieldnames)
                if not file_exists:
                    writer.writeheader()
                writer.writerows(self.shodan_data)

        if self.censys_data is not None:
            file_exists = os.path.isfile(self.censys_results)
            headers=['data_source', 'todays_date', 'ip', 'port', 'hostnames', 'org', 'country']
            with open(self.censys_results, "a", encoding="utf-8") as outfile:
                writer = csv.DictWriter(outfile, fieldnames=headers)
                if not file_exists:
                    writer.writeheader()
                writer.writerows(self.censys_data)

    def read_api_queries(self, sig: str):
        """Read & process hunting rules from file"""
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
        """Query Shodan API"""
        print("[+] Executing Shodan query")
        print()
        api = shodan.Shodan(SHODAN_API_KEY)
        try:
            results = api.search(self.shodan_query)
            console.print(f'[*] Results found: [bold gree]{results["total"]}')
            for result in results["matches"]:
                self.prep_shodan_output(result)
        except shodan.APIError as err:
            print(f"Error: {err}")

    def prep_shodan_output(self, result: list) -> List[dict]:
        """Display Shodan output"""
        
        self.shodan_data = [{
            "ip": result["ip_str"],
            "todays_date": self.todays_date,
            "last_seen" : result["timestamp"],
            "port": result["port"],
            "hostnames": result["hostnames"] or "N/A",
            "org": result["org"] or "N/A",
        }]
        self.write_query_output()
        

    def query_censys_api(self) -> None:
        """Run Censys query"""
        print("[+] Executing Censys query")
        print()
        censys = CensysHosts()
        if self.censys_query == "None":
            print("[-] No query found")
            print()
          
        else:
            try:

                for censys_results in censys.search(self.censys_query):
                    censys_data = censys_results
                    for i in censys_data:
                        self.censys_data = [{
                            "data_source": "censys",
                            "todays_date": self.todays_date,
                            "ip": i.get("ip", "N/A"),
                            "port": [service["port"] for service in i.get("services", "N/A")],
                            "hostnames": i["dns"]["reverse_dns"]["names"] if "dns" in i else "N/A",
                            "org": i.get("autonomous_system", "N/A").get("description", "N/A"),
                            "country": i.get("location", "N/A").get("country", "N/A"),
                        }]
                    
                        self.write_query_output()

            except CensysAPIException as err:
                print(f"Error: {err}")

    def run(self) -> None:
        """Run the program"""
        for signature in self.sig:
            if self.process_all:
                self.read_api_queries(signature)
                self.create_folders_for_output()
                self.query_censys_api()
                self.query_shodan_api()

                continue
           
