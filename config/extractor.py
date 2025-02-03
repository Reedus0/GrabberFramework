import re

from sample import Sample
from .regex import Regex
from logs.logger import log

types = {
    "int32": 0,
    "int32_ptr": 0,
    "ascii_ptr": "",
    "unicode_ptr": "",
    "cli_offset": "",
    "custom": None
}

class Extractor():
    __name: str = ""
    __expressions: list[Regex] = []
    __result: object = {}

    def __init__(self, name: str, expressions: list[Regex]):
        self.__name = name
        self.__expressions = expressions

    def getName(self):
        return self.__name
    
    def getExpressions(self):
        return self.__expressions
    
    def getResult(self):
        return self.__result
    
    def extract(self, sample: Sample):
        log("Extracting, with " + self.__name + " extractor...")

        sample_data = sample.readSample()

        for config_param in self.__expressions:

            param_name = config_param.getName()
            param_type = config_param.getType()

            regex_result = re.search(re.compile(config_param.getRegex()), sample_data)

            if(regex_result):
                extract_result = regex_result[1]
                log("Found " + param_name + " with " + self.__name + " extractor!")
                match(param_type):
                    case "int32": 
                        self.__result[param_name] = int.from_bytes(extract_result, "little")
                    case "int32_ptr": 
                        offset = sample.getPhysicalAddress(int.from_bytes(extract_result, "little"))
                        self.__result[param_name] = sample.readInt32(offset)
                    case "ascii_ptr":
                        offset = sample.getPhysicalAddress(int.from_bytes(extract_result, "little"))
                        self.__result[param_name] = sample.readASCIIString(offset)
                    case "unicode_ptr":
                        offset = sample.getPhysicalAddress(int.from_bytes(extract_result, "little"))
                        self.__result[param_name] = sample.readUnicodeString(offset)
                    case "cli_offset":
                        offset = int.from_bytes(extract_result, "little")
                        self.__result[param_name] = sample.readCLIString(offset)
                    case "custom":
                        self.__result[param_name] = config_param.getCustom()(sample, regex_result)
            else:
                log("Didn't find " + param_name + " with " + self.__name + " extractor!")
                self.__result[param_name] = types[param_type]