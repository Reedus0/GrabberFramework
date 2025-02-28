import re

from .sample import Sample
from .regex import Regex
from ..logs.logger import log

types = {
    "raw": "",
    "int16": 0,
    "int16_ptr": 0,
    "int32": 0,
    "int32_ptr": 0,
    "ascii_ptr": "",
    "unicode_ptr": "",
    "bytes_ptr": "",
    "cli_offset": "",
    "custom": ""
}


class Extractor():
    __name: str
    __expressions: list[Regex]
    __result: dict

    def __init__(self, name: str, expressions: list[Regex]) -> None:
        self.__name = name
        self.__expressions = expressions
        self.__result = {}

    def getName(self) -> str:
        return self.__name

    def getExpressions(self) -> list[Regex]:
        return self.__expressions

    def getResult(self) -> dict:
        return self.__result

    def extract(self, sample: Sample) -> None:
        log(0, f"Extracting with {self.__name} extractor...")

        sample_data = sample.getData()

        for config_param in self.__expressions:

            param_name = config_param.getName()
            param_type = config_param.getType()
            param_regex = config_param.getRegex()

            regex_result = re.search(re.compile(param_regex), sample_data)

            if (regex_result):
                extract_result = regex_result[1]
                
                virtual_address = hex(sample.getVirtualAddress(regex_result.start()))
                physical_address = hex(regex_result.start())

                log(10, f"Found {param_name} at {virtual_address}({physical_address}) with {self.__name} extractor!")
                match(param_type):
                    case "raw":
                        self.__result[param_name] = extract_result
                    case "int32" | "int16":
                        self.__result[param_name] = int.from_bytes(extract_result, "little")
                    case "int32_ptr" | "int16_ptr":
                        offset = sample.getPhysicalAddress(int.from_bytes(extract_result, "little"))
                        self.__result[param_name] = sample.readInt32(offset)
                    case "ascii_ptr":
                        offset = sample.getPhysicalAddress(int.from_bytes(extract_result, "little"))
                        self.__result[param_name] = sample.readASCIIString(offset)
                    case "unicode_ptr":
                        offset = sample.getPhysicalAddress(int.from_bytes(extract_result, "little"))
                        self.__result[param_name] = sample.readUnicodeString(offset)
                    case "bytes_ptr":
                        offset = sample.getPhysicalAddress(int.from_bytes(extract_result, "little"))
                        self.__result[param_name] = sample.readBytesString(offset)
                    case "cli_offset":
                        offset = int.from_bytes(extract_result, "little")
                        self.__result[param_name] = sample.readCLIString(offset)
                    case "custom":
                        self.__result[param_name] = config_param.getCustom()(sample, regex_result)
            else:
                log(0, f"Didn't find {param_name} with {self.__name} extractor...")
                self.__result[param_name] = types[param_type]
