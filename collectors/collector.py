from ..logs.logger import log

default_fields: dict = {
    "sha256_hash": None,
    "md5_hash": None,
    "malware_family": None,
    "mime": None,
    "first_seen": None,
    "last_seen": None,
    "file_name": None,
    "file_size": -1,
    "tags": []
}


class Collector():
    _name: str
    _data: list

    def getResult(self) -> list:
        log(10, f"Retrieving data from {self._name} collector...")
        for sample in self._data:
            for field in default_fields.keys():
                if (field not in sample or sample[field] is None):
                    sample[field] = default_fields[field]
        return self._data

    def collect(self) -> None:
        return
