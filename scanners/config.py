import re

from .scanner import Scanner

from ..config.processor import Processor
from ..config.extractor import Extractor

from ..config.sample import Sample


class ConfigScanner(Scanner):
    _name: str = "Config"
    __samples_path: str
    __extractors: dict

    def __init__(self, samples_path, extractors) -> None:
        self._data = []
        self.__samples_path = samples_path
        self.__extractors = extractors

    def scan(self, sample: dict) -> dict:
        for malware_family in self.__extractors.keys():
            if (malware_family == sample["malware_family"]):
                result = {}

                sample_file = Sample(self.__samples_path + "/" + sample["sha256_hash"])

                for worker in self.__extractors[malware_family]:
                    if (isinstance(worker, Processor)):
                        worker.processSample(sample_file)
                        sample_file = worker.getResult()
                    if (isinstance(worker, Extractor)):
                        worker.extract(sample_file)
                        result = {**result, **worker.getResult()}

                address_regex = r"([\w-]+\.){1,}[\w-]+"
                ip_regex = r"(\d{1,3}\.){3}\d{1,3}"

                for field in result.keys():
                    current_field = [result[field]]

                    if (type(result[field]) is type([])):
                        current_field = result[field]

                    for array_field in current_field:
                        address_regex_result = re.search(address_regex, array_field)
                        if (address_regex_result):
                            ip_regex_result = re.search(ip_regex, array_field)
                            if (ip_regex_result):
                                sample["related_ips"].append(ip_regex_result[0])
                            else:
                                sample["related_domains"].append(address_regex_result[0])

        return sample
