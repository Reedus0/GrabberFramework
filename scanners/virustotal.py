import json

from .scanner import Scanner

import requests


class VirusTotalScanner(Scanner):
    _name: str = "VirusTotal"
    __api_key: str

    def __init__(self, api_key) -> None:
        self.__api_key = api_key
        self._data = []

    def scan(self, sample: dict) -> dict:
        headers = {"X-Apikey": self.__api_key}

        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sample["sha256_hash"]}/behaviours", headers=headers)
        json_response = json.loads(r.text)

        if ("error" in json_response):
            return sample

        json_data = json_response["data"]

        for obj in json_data:
            if ("ip_traffic" in obj["attributes"]):
                for connection in obj["attributes"]["ip_traffic"]:
                    sample["related_ips"].append(connection["destination_ip"])

            if ("dns_lookups" in obj["attributes"]):
                for connection in obj["attributes"]["dns_lookups"]:
                    sample["related_domains"].append(connection["hostname"])

        return sample
