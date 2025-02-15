import json
import time
import requests

from typing import Any

from .sandbox import Sandbox
from ..logs.logger import log


class sandboxVX(Sandbox):
    _name: str = "VX"
    __api_key: str

    def __init__(self, api_key) -> None:
        self.__api_key = api_key

    def sendToSendbox(self, file) -> Any:
        headers = {"api-key": self.__api_key}

        data = {
            "file": file,
            "environment_id": (None, 160)
        }

        r = requests.post("https://www.hybrid-analysis.com/api/v2/submit/file", headers=headers, files=data)
        json_response = json.loads(r.text)

        if ("job_id" not in json_response):
            log(0, "Failed to send sample to VX")
            return

        log(0, f"Sended sample, id: {json_response["job_id"]}")
        return json_response["job_id"]

    def waitForAnalysis(self, file_id) -> None:

        headers = {"api-key": self.__api_key}

        while (1):

            r = requests.get(f"https://www.hybrid-analysis.com/api/v2/report/{file_id}/summary", headers=headers)
            json_response = json.loads(r.text)

            if (json_response["state"] != "IN_PROGRESS"):
                break

            log(0, "Waiting for sandbox...")
            time.sleep(30)

        self._result = json_response
