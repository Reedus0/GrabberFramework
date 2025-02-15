import pefile
import re


class Sample():
    __path: str
    __data: bytes

    def __init__(self, path: str) -> None:
        self.__path = path

    def getData(self) -> bytes | None:
        return self.__data

    def readSample(self) -> bytes:
        with open(self.__path, "rb") as file:
            self.__data = file.read()

        return self.__data

    def getString(self, address) -> str:
        offset = self.getPhysicalAddress(address)

        if (self.__data[offset + 1]):
            return self.readASCIIString(offset)
        else:
            return self.readUnicodeString(offset)

    def getPhysicalAddress(self, virutal_address):
        pe = pefile.PE(self.__path)

        for section in pe.sections:
            section_address = section.VirtualAddress
            section_size = section.Misc_VirtualSize

            if (section_address <= virutal_address < section_address + section_size + pe.OPTIONAL_HEADER.ImageBase):
                return section.PointerToRawData + (virutal_address - section_address - pe.OPTIONAL_HEADER.ImageBase)

    def getVirtualAddress(self, physical_address):
        pe = pefile.PE(self.__path)

        for section in pe.sections:
            if section.PointerToRawData <= physical_address < (section.PointerToRawData + section.SizeOfRawData):
                offset_in_section = physical_address - section.PointerToRawData
                virtual_address = section.VirtualAddress + offset_in_section + pe.OPTIONAL_HEADER.ImageBase
                return virtual_address

    def readASCIIString(self, offset):
        result = []

        while (self.__data[offset]):
            result.append(chr(self.__data[offset]))
            offset += 1

        return "".join(result)

    def readUnicodeString(self, offset):
        result = []

        while (self.__data[offset] or self.__data[offset + 1]):
            result.append(chr(self.__data[offset]))
            offset += 2

        return "".join(result)

    def readBytesString(self, offset):
        result = []

        while (self.__data[offset]):
            result.append(self.__data[offset])
            offset += 1

        return result

    def readCLIString(self, offset):
        # Reference: https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf
        result = []

        metadata_regex = b"\x42\x53\x4A\x42"
        metadata = re.search(re.compile(metadata_regex), self.__data)

        if (not metadata):
            return ""

        us_section_regex = b"(.{4}).{4}#US\x00"
        us_section = re.search(re.compile(us_section_regex), self.__data)

        if (not us_section):
            return ""

        us_section_offset = us_section[1]

        physical_address = metadata.start() + int.from_bytes(us_section_offset, "little") + offset

        for i in range(0, self.__data[physical_address], 2):
            result.append(chr(self.__data[physical_address + i + 1]))

        return "".join(result)

    def readInt32(self, offset):
        result = []
        for i in range(4):
            result.append(self.__data[offset + i])
        return int.from_bytes(bytes(result), "little")
