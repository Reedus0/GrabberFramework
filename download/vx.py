import json

import requests

from .downloader import Downloader


class VXDownloader(Downloader):
    _name: str = "VX"
    __api_key: str

    def __init__(self, api_key) -> None:
        self.__api_key = api_key
        self._result = bytearray()

    def download(self, hash) -> None:
        headers = {"Authorization": "Bearer " + self.__api_key}

        r = requests.get("https://virus.exchange/api/samples/" + hash, headers=headers)
        try:
            json_response = json.loads(r.text)

            if ("errors" in json_response):
                return

            link = json_response["download_link"]

            if (link):
                sample = requests.get(link).content
                self._result = sample
        except ValueError:
            pass
