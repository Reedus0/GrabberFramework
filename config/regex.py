types = {
    "int": 0,
    "ascii_ptr": "",
    "unicode_ptr": "",
    "custom": None
}

class Regex():
    __name = None
    __type = None
    __regex: tuple = ()
    __custom: callable = None

    def __init__(self, name, type, regex: tuple, custom: callable = None):
        self.__name = name
        self.__type = type
        self.__regex = regex
        self.__custom = custom

    def getName(self):
        return self.__name
    
    def getType(self):
        return self.__type
    
    def getRegex(self):
        return self.__regex
    
    def getCustom(self):
        return self.__custom