import json
import time
import requests

from .sandbox import Sandbox
from ..logs.logger import log

class sandboxVX(Sandbox):
    _name = "VX"
    __api_key = ""

    def __init__(self, api_key):
        self.__api_key = api_key

    def sendToSendbox(self, file):
        headers = {"api-key": self.__api_key}

        data = {
            "file": file,
            "environment_id": (None, 160)
        }

        r = requests.post("https://www.hybrid-analysis.com/api/v2/submit/file", headers=headers, files=data)
        json_response = json.loads(r.text)
        
        if("job_id" not in json_response):
            log("Failed to send sample to VX")
            return
        
        log(f"Sended sample, id: {json_response["job_id"]}")
        return json_response["job_id"]
        
    def waitForAnalysis(self, file_id):

        headers = {"api-key": self.__api_key}
        
        while(1):

            r = requests.get(f"https://www.hybrid-analysis.com/api/v2/report/{file_id}/summary", headers=headers)
            json_response = json.loads(r.text)

            if("job_id" in json_response):
                break

            log("Waiting for sandbox...")
            time.sleep(10)

        self._result = json_response