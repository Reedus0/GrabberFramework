import re

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex

def njrat():
    def extract(sample: Sample, regex_result: re.Match):
        data = sample.getData()
        nullmatch = re.search(b'\x00\x00', data[regex_result.start():])

        unicode_offset = nullmatch.start() + regex_result.start()
        unicode_data = data[unicode_offset:300+unicode_offset]

        config = []
        for data in unicode_data :
            data = data.to_bytes(1, byteorder="little")
            
            if data > b'\x00' and data < b'\x2E' and data != b'1B' and data != b'27':
                config.append("&")
            elif data < b'\x7F' and data > b'\x20':
                try :
                    config.append(data.decode("utf-8"))
                except:
                    pass

        config = ''.join(config)            
        config = config.split("&")
        address_regex = "(.+\.){2,}(.+)"
        
        for param in config:
            match = re.search(address_regex, param)
            if (match):
                return match.group(0)
            
        return ""
    config = Regex(
        "c2",
        "custom",
        (
                b"\\x47\\x65\\x74\\x57\\x69\\x6E\\x64\\x6F\\x77\\x54\\x65\\x78\\x74(.*)\\x00\\x00"
        ),
        extract)
    
    return Extractor("njrat", [config])