import re

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex


def SmokeLoader():
    def decrypt(sample: Sample, regex_result: re.Match):
        pass

    c2 = Regex(
        "c2",
        "ascii_ptr",
        (
            b"[\\x6A\\x68].{1,4}"
            b"\\x68(.{4})"
            b"\\x50"
            b"\\xE8.{4}"
            b"\\x83\\xC4\\x0C"
        ),
        decrypt)

    return Extractor("SmokeLoader", [c2])
