import re

from .scanner import Scanner

from ..config.extractor import Extractor

from ..config.sample import Sample


class UrlsScanner(Scanner):
    _name: str = "Urls"
    __samples_path: str
    __extractor: Extractor

    def __init__(self, samples_path, extractor) -> None:
        self._data = []
        self.__samples_path = samples_path
        self.__extractor = extractor

    def scan(self, sample: dict) -> dict:

        sample_file = Sample(self.__samples_path + "/" + sample["sha256_hash"])
        self.__extractor.extract(sample_file)
        result = self.__extractor.getResult()

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
