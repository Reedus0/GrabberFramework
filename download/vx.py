import json

import requests

from .downloader import Downloader

class VX(Downloader):
    _name = "VX"
    __api_key = ""

    def __init__(self, api_key):
        self.__api_key = api_key

    def download(self, hash):
        headers = {"Authorization": "Bearer " + self.__api_key}

        r = requests.get("https://virus.exchange/api/samples/" + hash, headers=headers)
        try:
            json_response = json.loads(r.text)
            link = json_response["download_link"]
            if(link):
                sample = requests.get(link).content
                self._result = sample
        except:
            pass