import re

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex

def ValleyRAT64():

    def parse_config(sample: Sample, regex_result: re.Match):
        virutal_address = sample.getVirtualAddress(regex_result.start(1))
        virutal_address += int.from_bytes(regex_result[1], "little") + 4
        offset = sample.getPhysicalAddress(int.from_bytes(virutal_address, "little"))
        return sample.readASCIIString(offset)[::-1]
    
    config_regex = Regex(
        "config",
        "custom",
        (
                b"\\x48\\x89\\x58\\xF8"
                b"\\x48\\x89\\x68\\xF0"
                b"\\x48\\x89\\x70\\xE8"
                b"\\x48\\x89\\x78\\xE0"
                b"\\x4C\\x89\\x60\\xD8"
                b"\\x4C\\x89\\x70\\xD0"
                b"\\x48\\x8D\\x2D(.{4})"
        ),
        parse_config)

    
    return Extractor("ValleyRAT64", [config_regex])