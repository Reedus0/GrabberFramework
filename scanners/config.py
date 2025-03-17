import re

from .scanner import Scanner

from ..config.sample import Sample


class ConfigScanner(Scanner):
    _name = "Config"
    __samples_path = ""
    __extractors = {}

    def __init__(self, samples_path, extractors) -> None:
        self._data = []
        self.__samples_path = samples_path
        self.__extractors = extractors

    def scan(self, sample: dict) -> dict:
        for malware_family in self.__extractors.keys():
            if (malware_family == sample["malware_family"]):
                extractor = self.__extractors[malware_family]["extractor"]()

                sample_file = Sample(self.__samples_path + "/" + sample["sha256_hash"])

                extractor.extract(sample_file)
                result = extractor.getResult()

                address_regex = "([\w-]+\.){1,}[\w-]+"
                ip_regex = "\d{1,3}\.{3}\d{1,3}"

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
