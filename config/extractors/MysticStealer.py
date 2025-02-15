import re

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex


def MysticStealer():
    def decrypt(sample: Sample, regex_result: re.Match):
        physical_address = sample.getPhysicalAddress(int.from_bytes(regex_result[1], "little"))
        ecnrypted_config = sample.readBytesString(physical_address)
        print(ecnrypted_config)

        return ""

    c2_url = Regex(
        "c2",
        "custom",
        (
            b"\\x0F\\x84.{4}"
            b"\\xBD.{4}"
            b"\\x66\\xC7\\x44\\x24\\x10\\x7C\\x00"
            b"\\xB8(.{4})"
        ),
        decrypt)

    return Extractor("MysticStealer", [c2_url])
