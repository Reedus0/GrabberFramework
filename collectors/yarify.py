import json
from datetime import datetime

from .collector import Collector
from ..logs.logger import log

import requests


class YarifyCollector(Collector):
    _name: str = "Yarify"
    __api_key: str

    def __init__(self, api_key) -> None:
        self.__api_key = api_key
        self._data = []

    def collect(self) -> None:
        headers = {"Auth-Key": self.__api_key}

        rules_data = {
            "query": "show_deployed_yara_rules"
        }

        r = requests.post("https://yaraify-api.abuse.ch/api/v1/", headers=headers, json=rules_data)
        json_response = json.loads(r.text)

        if (json_response["query_status"] != "ok"):
            log(10, "Failed to fetch data from yarify")
            return

        json_data = json_response["data"]

        for rule in json_data:
            data: dict = {
                "query": "get_yara",
                "search_term": rule["rule_name"],
                "result_max": 100
            }

            r = requests.post("https://yaraify-api.abuse.ch/api/v1/", headers=headers, json=data)
            json_response = json.loads(r.text)

            if (json_response["query_status"] != "ok"):
                log(10, "Failed to fetch data from yarify")
                return

            sample_data = json_response["data"]

            for sample in sample_data:
                new_sample = {}
                new_sample["sha256_hash"] = sample["sha256_hash"]
                new_sample["md5_hash"] = sample["md5_hash"]
                new_sample["malware_family"] = rule["rule_name"]
                new_sample["mime"] = sample["mime_type"]
                new_sample["first_seen"] = datetime.strptime(sample["first_seen"], "%Y-%m-%d %H:%M:%S %Z")
                new_sample["last_seen"] = datetime.strptime(
                    sample["first_seen"], "%Y-%m-%d %H:%M:%S %Z") if sample["last_seen"] else None
                new_sample["file_name"] = sample["sha256_hash"]
                new_sample["file_size"] = sample["file_size"]

                self._data.append(new_sample)
