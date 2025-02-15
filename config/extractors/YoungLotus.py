from ..extractor import Extractor
from ..regex import Regex


def YoungLotus():
    c2 = Regex(
        "c2",
        "ascii_ptr",
        (
            b"\\x68(.{4})"
            b"\\x68.{4}"
            b"."
            b"\\xFF\\x15.{4}"
            b"\\x83\\xC4."
        ))

    c2_port = Regex(
        "c2_port",
        "int32_ptr",
        (
            b"\\x8B\\x46\\x64"
            b"\\xB9.{4}"
            b"\\xA3(.{4})"
        ))

    return Extractor("YoungLotus", [c2, c2_port])
