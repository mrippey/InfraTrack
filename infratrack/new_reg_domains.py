AUTHOR = "Michael Rippey, Twitter: @nahamike01"
LAST_SEEN = "2022 07 05"
DESCRIPTION = """Download/search for suspicious domains from the WHOISDS database. 

usage: python3 newdomainspotter.py -rfuzz <<str(keyword)>>  || -a <<str(keyword)>>"""

from core.logs import LOG
import sys
import base64
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
import requests
from typing import List, Tuple
from zipfile import ZipFile
import re
from rich.console import Console

console = Console()

try:
    from rapidfuzz import process

except ImportError:
    print("rapidfuzz not installed, use:")
    print("\t\tpip3 install rapidfuzz")
    sys.exit(1)

file_name_date = datetime.now().strftime("%Y-%m-%d")

WHOISDS_URL = "https://whoisds.com//whois-database/newly-registered-domains/"

regex_for_domain_names = (
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"
)

def format_date_url() -> str:
    """
    Set date to yesterday"s date in
    Args: None
    Returns:
    str -> Yesterday"s date Base64 encoded with additional information for URL
    """
    yesterday = datetime.now() - timedelta(days=2)
    format_date = datetime.strftime(yesterday, "%Y-%m-%d")
    url_add_ext = f"{format_date}.zip"
    finished_url_date = base64.b64encode(url_add_ext.encode("utf-8")).decode("utf-8")
    return finished_url_date


def get_newreg_domains() -> requests.Response:
    """
    Fetch content from WHOISDS website for new domains file
    Args: None
    Returns:
    requests.Response -> Content of server response
    (zip file of newly registered domains)
    """
    add_date_url = format_date_url()

    try:
        LOG.debug("[+] Fetching new domains from WHOISDS...")
        console.print("[+] Connecting to WHOISDS...\n", style='bold white')
        headers = {"User-Agent": "NewDomainSpotter v0.2 (github: @mrippey"}
        whoisds_new_domains = requests.get(
            WHOISDS_URL + add_date_url + "/nrd", headers=headers
        )
        whoisds_new_domains.raise_for_status()

    except requests.exceptions.Timeout as err:
        console.print(f"[!] Exception: {err}", style='bold red')
        console.print(
            "[!] Connection timed out. Today's domains may not have been posted yet. Please try again later.", style='bold red'
        )
        LOG.error(f"[!] Exception: {err}")
    except requests.RequestException as err:
        console.print(f"[!] Requests Module Exception: {err}", style='bold red')
        LOG.error(f"[!] Exception: {err}")

    return whoisds_new_domains.content


def process_domain_file() -> List[str]:
    """
    Open and read returned zip file from request
    Args: None
    Returns:
    List[str] -> The zip file is read and returns each newly
    identified domain as a list of strings.
    """
    domain_file = get_newreg_domains()
    domains = []

    try:
        LOG.debug("[+] Extracting domains from zip file...")
        console.print("[+] Processing list of newly registered domains...\n", style='bold white')
        with ZipFile(BytesIO(domain_file)) as data:

            for info in data.infolist():
                with data.open(info) as lines:
                    for line in lines:

                        file = line.decode("ascii")
                        domains.append(str(file).rstrip("\r\n"))

    except ZipFile.error as err:
        console.print(f"[!] Exception: {err}", style='bold red')

    return domains


def rapidfuzz_multi_query(wordlist) -> List[Tuple]:
    """
    Return RapidFuzz string match of search query
    Args: query_str
    Returns:
    List[Tuple] -> Best matches based on similarity
    """
    paths = []
    
   
    LOG.debug("[+] Searching for matches using RapidFuzz...")
    with open(wordlist, "r") as data:
        query_str = data.readlines()

    paths = [uri_path.strip() for uri_path in query_str]

    # print(paths)

    new_domains_list = process_domain_file()
    results_file = Path.cwd() / f"{wordlist}_matches.txt"
    #path = Path.cwd() / f'{query_str}_matches.txt'
    for query in paths:
        results = process.extract(query, new_domains_list, limit=10, score_cutoff=70)
        domain_matches = ", '".join(map(str, results))
        domain_matches.replace("'", "")

        # print(domain_matches)
        with open(results_file, "a") as f:
            LOG.info("[+] Writing results to file...")
            extracted = re.findall(regex_for_domain_names, domain_matches)
            domain_names = str(extracted)
            domain_names.replace("]", "").replace("[", "").split(",")

            f.writelines(domain_names + "\n")

    console.print(f"[!] Complete. File written to: {results_file}", style='bold green')


def scan_all_occurrences(query_str: str) -> str:
    """
    Return all instances of the queried search term
    Args: query_str
    Returns:
    str -> All instances where the query appears in the file
    """

    path = Path.cwd() / f"{query_str}_matches.txt"
    list_of_domains = process_domain_file()

    for search_all in list_of_domains:

        if query_str in search_all:

            print(f"[*] {search_all}")

            with open(path, "a") as f:
                LOG.info("[+] Writing results to file...")
                f.write(search_all + "\n")

    # ADD CHECK IF NONE, DONT PRINT
    print()
    print(f"[+] Results written to: {path}\n")
