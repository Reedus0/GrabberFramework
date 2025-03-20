import os

import yara

from .scanner import Scanner

from ..logs.logger import log


class YaraScanner(Scanner):
    _name = "Yara"
    __rules_path = ""
    __samples_path = ""

    def __init__(self, rules_path, samples_path) -> None:
        self._data = []
        self.__rules_path = rules_path
        self.__samples_path = samples_path

        self.compileRules("result.yar", self.__rules_path)

    def compileRules(self, name: str, path: str):
        rules = []

        files = os.listdir(path)
        result = ""

        for filename in files:
            if (filename != name and filename.endswith(".yar")):
                rules.append(filename)

        for rule in rules:
            with open(path + "/" + rule, "r") as file:
                result += file.read()

        with open(path + "/" + name, "w") as file:
            file.write(result)

    def scan(self, sample: dict) -> dict:
        rules = yara.compile(self.__rules_path + "/" + "result.yar")
        try:
            match = rules.match(self.__samples_path + "/" + sample["sha256_hash"])
        except yara.Error:
            return sample

        if (match):
            family = match[0].rule
            log(10, "Found sample family: " + family)
            sample["malware_family"] = family

        return sample
