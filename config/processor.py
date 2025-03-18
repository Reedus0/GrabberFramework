import typing

from .sample import Sample


class Processor():
    __name: str
    __function: typing.Callable
    __result: Sample

    def __init__(self, name: str, function: typing.Callable) -> None:
        self.__name = name
        self.__function = function

    def processSample(self, sample: Sample) -> None:
        self.__result = self.__function(sample)

    def getName(self) -> str:
        return self.__name

    def getResult(self) -> Sample:
        if (isinstance(self.__result, Sample)):
            return self.__result
        else:
            raise TypeError("result is not Sample")
