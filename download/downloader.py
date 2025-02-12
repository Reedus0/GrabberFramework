from ..logs.logger import log

class Downloader():
    _name = ""
    _result = None

    def getResult(self):
        log(f"Downloading sample using {self._name} downloader...")
        return self._result
    
    def download(self, hash):
        return