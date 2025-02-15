from ..logs.logger import log


class Downloader():
    _name: str
    _result: bytes

    def getResult(self) -> bytes:
        log(10, f"Downloading sample using {self._name} downloader...")
        return self._result

    def download(self, hash) -> None:
        return
