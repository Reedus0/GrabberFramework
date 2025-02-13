from ..logs.logger import log

class Sandbox():
    _name = ""
    _result = None

    def getResult(self):
        log(f"Sending to sandbox using {self._name} sandbox...")
        return self._result
    
    def sendToSendbox(self, file):
        return
    
    def waitForAnalysis(self, file_id):
        return