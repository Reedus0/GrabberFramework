from logs.logger import log

default_fields = {
    "related_ips": [],
    "related_domains": []
}

class Scanner():
    _name = ""
    _data = []

    def __init__(self, name: str) -> None:
        self._name = name

    def getResult(self) -> list:
        log(f"Scanning data with {self._name} scanner...")
        for sample in self._data:
            for field in default_fields.keys():
                if(field not in sample or sample[field] == None):
                    sample[field] = default_fields[field]
        return self._data
    
    def scan(self, samples: list) -> None:
        pass