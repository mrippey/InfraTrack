"""_new_reg_domains.py_ = Search for new domains using RapidFuzz"""
import sys
import os
import base64
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import List, Tuple
from zipfile import ZipFile
import httpx
from httpx import get
from rich.console import Console
from core.logs import LOG
from detect_mal_url import detect_domains

console = Console()

try:
    from rapidfuzz import process

except ImportError:
    print("rapidfuzz not installed, use:")
    print("\t\tpip3 install rapidfuzz")
    sys.exit(1)

file_name_date = datetime.now().strftime("%Y-%m-%d")

WHOISDS_URL = "https://whoisds.com//whois-database/newly-registered-domains/"
LOG.debug("[+] Starting new_reg_domains.py...")


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


def get_newreg_domains() -> bytes:
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
        console.print("[+] Connecting to WHOISDS...\n", style="bold white")
        headers = {"User-Agent": "InfraTrack v0.1 (github: @mrippey"}
        whoisds_new_domains = get(WHOISDS_URL + add_date_url + "/nrd", headers=headers)
        whoisds_new_domains.raise_for_status()

    except httpx.TimeoutException as err:
        console.print(f"[!] Exception: {err}", style="bold red")
        console.print(
            "[!] Connection timed out. Today's domains list may not have been posted yet. Please try again later.",
            style="bold red",
        )
        LOG.error(f"[!] Exception: {err}")
        sys.exit(1)
    except httpx.RequestError as err:
        console.print(f"[!] Requests Module Exception: {err}", style="bold red")
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
        console.print(
            "[+] Processing list of newly registered domains...\n", style="bold white"
        )
        with ZipFile(BytesIO(domain_file)) as data:

            for info in data.infolist():
                with data.open(info) as lines:
                    for line in lines:

                        file = line.decode("ascii")
                        domains.append(str(file).rstrip("\r\n"))

    except Exception as err:
        console.print("[!] Exception Triggered: New domains list may not have been uploaded yet.", style="bold red")
        LOG.error(f"[!] Exception: {err}")
        sys.exit(1)

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
    split_wordlist_name = os.path.splitext(wordlist)[0]
    results_file = Path.cwd() / f"{split_wordlist_name}_{file_name_date}_matches.txt"
    # path = Path.cwd() / f'{query_str}_matches.txt'
    for query in paths:
        results = process.extract(query, new_domains_list, limit=10, score_cutoff=70)

        for result in results:
            # print(f"[*] {result[0]}")

            with open(results_file, "a") as output_file:
                LOG.info("[+] Writing results to file...")
                output_file.write(result[0] + "\n")

    #console.print("[*] Scored results below: \n")
    detect_domains(results_file)
    print()
    console.print(
        f"[!] Job complete. File written to: {results_file}", style="bold green"
    )
