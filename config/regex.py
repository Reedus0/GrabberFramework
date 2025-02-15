import typing

types = {
    "int": 0,
    "ascii_ptr": "",
    "unicode_ptr": "",
    "custom": None
}


class Regex():
    __name: str
    __type: str
    __regex: bytes
    __custom: typing.Callable

    def __init__(self, name, type, regex: bytes, custom: typing.Callable = lambda x: x) -> None:
        self.__name = name
        self.__type = type
        self.__regex = regex
        self.__custom = custom

    def getName(self) -> str:
        return self.__name

    def getType(self) -> str:
        return self.__type

    def getRegex(self) -> bytes:
        return self.__regex

    def getCustom(self) -> typing.Callable:
        return self.__custom
