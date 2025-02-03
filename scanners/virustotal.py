import json

from .scanner import Scanner
from ..logs.logger import log

import requests

class VirusTotal(Scanner):
    _name = "VirusTotal"
    __api_key = ""

    def __init__(self, api_key):
        self.__api_key = api_key

    def scan(self, samples: list) -> None:
        headers = {"X-Apikey": self.__api_key}

        for sample in samples:
            sample["related_ips"] = []
            sample["related_domains"] = []

            r = requests.get(f"https://www.virustotal.com/api/v3/files/{sample["sha256_hash"]}/behaviours", headers=headers)
            json_response = json.loads(r.text)

            if("error" in json_response):
                continue
            
            json_data = json_response["data"]

            for obj in json_data:
                if("ip_traffic" in obj["attributes"]):
                    for connection in obj["attributes"]["ip_traffic"]:
                        sample["related_ips"].append(connection["destination_ip"])

                if("dns_lookups" in obj["attributes"]):
                    for connection in obj["attributes"]["dns_lookups"]:
                        sample["related_domains"].append(connection["hostname"])


        self._data = samples