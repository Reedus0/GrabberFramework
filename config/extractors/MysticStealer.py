import re

from extractor import Extractor
from sample import Sample
from config.regex import Regex

def MysticStealer():
    def decrypt(sample: Sample, regex_result: re.Match):
        decrypted = []
        physical_address = sample.getPhysicalAddress(int.from_bytes(regex_result[1], "little"))
        ecnrypted_config = sample.readBytesString(physical_address)
        for i in range(0, len(ecnrypted_config), 8):
            first_block = int.from_bytes(bytes(ecnrypted_config[i:i + 4]), "little")
            second_block = int.from_bytes(bytes(ecnrypted_config[i + 4:i + 8]), "little")
            const = 0xC6EF3720
            for j in range(32):
                second_block -= ((16 * (first_block + 0x352247C) & 0xFFFFFFFF) ^ (((first_block >> 5) + 0x46287644) ^ (const + first_block)) & 0xFFFFFFFF) & 0xFFFFFFFF
                second_block = second_block & 0xFFFFFFFF
                tmp = ((second_block + const) & 0xFFFFFFFF) ^ (16 * second_block - 0x58A318FB) & 0xFFFFFFFF
                tmp = tmp & 0xFFFFFFFF
                const += 0x61C88647
                const = const & 0xFFFFFFFF
                first_block -= ((second_block >> 5) - 0x4C7FA897) & 0xFFFFFFFF ^ tmp & 0xFFFFFFFF
                first_block = first_block & 0xFFFFFFFF
            
            for k in range(4):
                decrypted.append((first_block >> k * 8) & 0xFF)
            for k in range(4):
                decrypted.append((second_block >> k * 8) & 0xFF)
        return "".join(chr(x) if x != 0 else "" for x in decrypted)

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