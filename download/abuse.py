import os
import json

import requests
import pyzipper

from .downloader import Downloader


class AbuseDownloader(Downloader):
    _name: str = "Abuse"
    __api_key: str

    def __init__(self, api_key) -> None:
        self.__api_key = api_key
        self._result = bytearray()

    def download(self, hash) -> None:
        headers = {"Auth-Key": self.__api_key}

        data = {
            "query": "get_file",
            "sha256_hash": hash,
        }

        r = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
        try:
            json.loads(r.text)
        except ValueError:
            with open(hash + ".zip", "wb") as file:
                file.write(r.content)

            file_name = ""

            with pyzipper.AESZipFile(hash + ".zip", "r", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_ref:
                try:
                    zip_ref.extractall(".", pwd="infected".encode())
                except EOFError:
                    zip_ref.close()
                    os.remove(hash + ".zip")
                    return

                file_name = zip_ref.namelist()[0]
            os.remove(hash + ".zip")

            with open(file_name, "rb") as file:
                self._result = file.read()
            os.remove(file_name)
