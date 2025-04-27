import json
from datetime import datetime

from .collector import Collector
from ..logs.logger import log

import requests


class AbuseCollector(Collector):
    _name: str = "Abuse"
    __api_key: str

    def __init__(self, api_key) -> None:
        self.__api_key = api_key
        self._data = []

    def collect(self) -> None:
        headers = {"Auth-Key": self.__api_key}

        data = {
            "query": "get_recent",
            "selector": "time",
        }

        r = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
        json_response = json.loads(r.text)

        if (json_response["query_status"] != "ok"):
            log(20, "Failed to fetch data from Abuse")
            return

        json_data = json_response["data"]

        for sample in json_data:
            new_sample = {}
            new_sample["sha256_hash"] = sample["sha256_hash"]
            new_sample["md5_hash"] = sample["md5_hash"]
            new_sample["malware_family"] = sample["signature"]
            new_sample["mime"] = sample["file_type_mime"]
            new_sample["first_seen"] = datetime.fromisoformat(sample["first_seen"])
            new_sample["last_seen"] = datetime.fromisoformat(sample["last_seen"]) if sample["last_seen"] else None
            new_sample["file_name"] = sample["file_name"]
            new_sample["file_size"] = sample["file_size"]
            new_sample["tags"] = sample["tags"]

            self._data.append(new_sample)
