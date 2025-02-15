from typing import Any
from ..logs.logger import log


class Sandbox():
    _name: str
    _result: dict

    def getResult(self) -> dict:
        log(0, f"Sending to sandbox using {self._name} sandbox...")
        return self._result

    def sendToSendbox(self, file) -> Any:
        return

    def waitForAnalysis(self, file_id) -> None:
        return
