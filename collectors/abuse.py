import os
import json
from datetime import datetime

from collectors.collector import Collector
from logs.logger import log

import requests

class Abuse(Collector):
    def collect(self) -> None:
        headers = {"Auth-Key": os.environ["ABUSE_API_KEY"]}

        data = {
            "query": "get_recent",
            "selector": "time",
        }

        r = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
        json_response = json.loads(r.text)
        
        if(json_response["query_status"] != "ok"):
            log("Failed to fetch data from abuse")
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