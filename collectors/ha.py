import json
from datetime import datetime

from .collector import Collector
from ..logs.logger import log

import requests


class HybridAnalysisCollector(Collector):
    _name: str = "HybridAnalysis"
    __api_key: str

    def __init__(self, api_key) -> None:
        self.__api_key = api_key
        self._data = []

    def collect(self) -> None:
        headers = {"api-key": self.__api_key}

        r = requests.get("https://www.hybrid-analysis.com/api/v2/feed/latest", headers=headers)
        try:
            json_response = json.loads(r.text)
        except json.decoder.JSONDecodeError:
            log(20, "Failed to fetch data from HybridAnalysis")
            return

        if (json_response["status"] != "ok"):
            log(20, "Failed to fetch data from HybridAnalysis")
            return

        json_data = json_response["data"]

        for sample in json_data:

            if ("sha256" not in sample):
                continue
            if (sample["submit_name"][:4] == "http"):
                continue
            if (sample["threat_score"] < 50):
                continue

            new_sample = {}
            new_sample["sha256_hash"] = sample["sha256"]
            new_sample["md5_hash"] = sample["md5"] if "md5" in sample else None
            new_sample["malware_family"] = sample["vx_family"] if "vx_family" in sample else None
            new_sample["first_seen"] = datetime.fromisoformat(sample["analysis_start_time"])
            new_sample["last_seen"] = None
            new_sample["file_name"] = sample["submit_name"] if "submit_name" in sample else None
            new_sample["file_size"] = sample["size"] if "size" in sample else None

            if ("hosts" in sample):
                new_sample["related_ips"] = sample["hosts"]
            if ("domains" in sample):
                new_sample["related_domains"] = sample["domains"]

            self._data.append(new_sample)
