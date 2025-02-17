import re

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex

from Cryptodome.Cipher import ARC4


def SmokeLoader():

    def decrypt_strings(data, strings_start):
        key = bytes(data[strings_start:strings_start + 4])
        offset = strings_start + 4

        for i in range(20):
            string_length = data[offset]

            string = bytes(data[offset + 1:offset + string_length + 1])
            offset += string_length + 1

            cipher = ARC4.new(key)
            msg = cipher.decrypt(string)
            print(msg)

    def get_final_stage(sample: Sample, regex_result: re.Match):
        if (regex_result):
            offset = int.from_bytes(regex_result.group(1), "little")
            size = int.from_bytes(regex_result.group(2), "little")
            return [offset, size]
        return None
    
    # 2D 4C 45 9F CD 28 6F 46 50 18 A8 73 A8 06 1C C6 05 CE 3A 82 AD C7 A5 15 57 97 19 DE CF A0 29 DC A6 29 A6 D5 A1 2B F7 E2 77 41 D8 BE 32 56 24 77 5E 8D C9 2C 34 1B 1A 20 8B 69 E5 13 1C DA 0D C4 2B F1 96 CC A2 1F 49 8F 19 95 81 84 3C C9 F7 2B BD D3 A1 0C 45 55 9D DC 2B 3C 5A 4D 52 A2 6C EA 09 68 5E 88 DC 2F 3C 06 11 46 0B 54 5D 9E DA 32 3B 36 0C 15 BC 65 06 51 42 8E CF 68 67 08 45 55 9D DC 2B 3C 5A 4D 06 51 43 87 D0 34 3B 05 4B 5D 8E 8E 69 07 53 58 85 D5 2F 21 19 06 53 42 D9 E2 68 67 06 40 5F 98 DC 2B 3C 07 57 59 8E D1 37 66 5B 07 57 59 87 CA 3A 25 00 0A 57 47 88 EB 3E 27 1A 16 13 A8 07 72 54 99 CE 32 3A 07 04 0A 53 82 C9 04 01 42 AD FB 04 01 01 D9 C5 0A 01 42 CE 8D 63 0D 4C 4F 44 9E 0C 01 31 98 BD 07 55 4C 7F 14 C6 73 86 08 01 31 98 BD 7E 55 1A 7F 1C 56 31 8E BD 3C 55 1A 7F 0A C6 72 86 52 73 9B 62 82 5F 82 DF D1 D6 5A 3B C4 7C 92 A1 12 01 31 AA BD 0B 55 39 7F 38 C6 41 86 35 73 E8 62 87 5F 0C 01 31 BF BD 1E 55 24 7F 2C C6 25 86 08 0A 31 8E BD 23 55 0C 7F 08 0A 31 8F BD 37 55 05 7F 08 0A 31 89 BD 3A 55 1D 7F 20 1E 31 B1 BD 34 55 07 7F 19 C6 2E 86 28 73 CD 62 C7 5F C3 DF D6 D6 13 3B 87 7C 88 A1 A4 44 CB 9B 08 74 31 A4 BD 08 55 3D 7F 5E 67 31 84 BD 35 55 1D 7F 19 C6 6E 86 15 73 84 62 F6 5F D4 DF D2 D6 1F 3B DB 7C C1 A1 A0 44 C9 9B 34 CF DA D3 2D 84 EE 11 54 F6 A9 5D 52 14 2F 97 5A 3F 16 AD B5 FD B2 E9 48 B2 AF B6 75 DF 54 23 9E 6E 4E 9F 7D 4A 33 B0 E4 A5 3D CF 3F DA 61 0F 52 0F DA 87 BD 69 0F 2D 9A B2 3B 53 3C 34 08 4B 31 9B BD 3E 55 07 7F 10 6C 31 84 BD 28 55 1D 7F 46 C6 20 86 44 73 DA 62 0A 74 31 BF BD 6A 55 59 7F 31 C6 26 15 31 D2 BD 62 55 50 7F 51 C6 31 86 50 73 84 62 91 5F 9D DF F6 D6 4A 3B D1 7C DB A1 F1 44 89 9B 7E CF 86 D3 74 84 42 62 31 82 BD 29 55 0C 7F 1A C6 6F 86 19 73 89 62 E6 5F C8 DF C4 D6 1B 3B 94 7C 8D A1 B5 44 99 9B 06 CF C4 D3 2B 84 FA 11 46 F6 B8 5D 49 14 60 97 75 3F 5E AD A8 FD F1 E9 4B B2 F8 B6 27 DF 11 23 8B 6E 44 65 31 88 BD 38 55 0C 7F 0C C6 74 86 5B 73 89 62 88 5F 82 DF 88 D6 77 3B EB 7C B3 A1 A4 44 DF 9B 21 CF C4 D3 21 84 FF 11 0F F6 FD 5D 53 14 34 97 40 3F 49 AD F7 FD B0 E9 10 B2 FD B6 51 DF 5C 23 8B 6E 0E 9F 46 65 31 88 BD 38 55 0C 7F 0C C6 74 86 5B 73 89 62 88 5F 82 DF 88 D6 77 3B EB 7C B3 A1 A4 44 DF 9B 21 CF C4 D3 21 84 FF 11 0F F6 FD 5D 53 14 34 97 40 3F 49 AD BE FD A5 E9 10 B2 F7 B6 27 DF 2A 23 DD 6E 52 9F 20 4A 08 0A 31 88 BD 34 55 04 7F 08 0A 31 84 BD 29 55 0E 7F 08 0A 31 85 BD 3E 55 1D 7F 18 41 31 93 BD 2B 55 05 7F 13 C6 72 86 04 73 DB 62 8C 5F C8 DF DA D6 1F 3B
    # 2D 4C 45 9F CD 28 6F 46 50 18 A8 73 A8 06 1C C6 05 CE 3A 82 AD C7 A5 15 57 97 19 DE CF A0 29 DC A6 29 A6 D5 A1 2B F7 E2 77 41 D8 BE 32 56 24 77 5E 8D C9 2C 34 1B 1A 20 8B 69 E5 13 1C DA 0D C4 2B F1 96 CC A2 1F 49 8F 19 95 81 84 3C C9 F7 2B BD D3 A1 0C 45 55 9D DC 2B 3C 5A 4D 52 A2 6C EA 09 68 5E 88 DC 2F 3C 06 11 46 0B 54 5D 9E DA 32 3B 36 0C 15 BC 65 06 51 42 8E CF 68 67 08 D6 20 78 97 43 87 D0 34 3B 05 4B 5D 8E 8E
    final_stage = Regex(
        "final_stage",
        "custom",
        (
            b"\\xEB."
            b"\\x8D\\x83(.{4})"
            b"\\xB9(.{4})"
        ),
        get_final_stage)

    final_stage_extractor = Extractor("final_stage", [final_stage])

    xor_key = Regex(
        "xor_key",
        "int32",
        (
            b"\\xBA(.{4})"
            b"\\x8B\\x4D\\x0C"
        ))

    xor_key_extractor = Extractor("xor_key", [xor_key])

    def decrypt(sample: Sample, regex_result: re.Match):
        original_data = sample.getData()

        final_stage = []

        for i in range(255):
            sample.setData(bytearray([x ^ i for x in original_data]))
            final_stage_extractor.extract(sample)
            final_stage = final_stage_extractor.getResult()["final_stage"]
            if (final_stage):
                break
        else:
            return

        final_offset = final_stage[0]
        final_size = final_stage[1]

        xor_key = 0

        for i in range(255):
            sample.setData(bytearray([x ^ i for x in original_data]))
            xor_key_extractor.extract(sample)
            xor_key = xor_key_extractor.getResult()["xor_key"]
            if (xor_key):
                break

        final_data = []

        bytes_key = xor_key.to_bytes(4, byteorder="little")
        physical_offset = sample.getPhysicalAddress(0x400000 + final_offset)

        for i in range(final_size):
            final_data.append(original_data[physical_offset + i] ^ bytes_key[i % len(bytes_key)])

        strings_start = 0

        for i in range(0x400, 0x800):
            key = bytes(final_data[i:i + 4])
            data = bytes(final_data[i + 5: i + 9])

            cipher = ARC4.new(key)
            msg = cipher.decrypt(data)
            if (msg == b"http"):
                strings_start = i
                break
        else:
            return ""

        decrypt_strings(final_data, strings_start)

    c2 = Regex(
        "c2",
        "custom",
        (
            b"(.)"
        ),
        decrypt)

    return Extractor("SmokeLoader", [c2])
