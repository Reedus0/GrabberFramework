from extractor import Extractor
from config.regex import Regex

def LeprechaunVNC():
    c2 = Regex(
        "c2",
        "ascii_ptr",
        (
                b"[\\x6A\\x68].{1,4}"
                b"\\x68(.{4})"
                b"\\x50"
                b"\\xE8.{4}"
                b"\\x83\\xC4\\x0C"
        ))
    user_agent = Regex(
        "user_agent",
        "ascii_ptr",
        (
                b"\\x6A\\x00"
                b"\\x6A\\x00"
                b"\\x6A\\x00"
                b"\\x6A\\x01"
                b"\\x68(.{1,4})"
                b"\\xFF\\x15.{4}"
                b"\\xC3"
        ))
    
    return Extractor("LeprechaunVNC", [c2, user_agent])