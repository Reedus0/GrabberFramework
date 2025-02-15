import re

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex


def SmokeLoader():

    def get_final_stage(sample: Sample, regex_result: re.Match):
        if (regex_result):
            return [int.from_bytes(regex_result.group(1), "little"), int.from_bytes(regex_result.group(2), "little")]
        return None

    final_stage = Regex(
        "final_stage",
        "custom",
        (
            b"\\xEB."
            b"\\x8D\\x83(.{4})"
            b"\\xB9(.{4})"
        ),
        get_final_stage)

    final_stage_extractor = Extractor("", [final_stage])

    xor_key = Regex(
        "xor_key",
        "int32",
        (
            b"\\xBA(.{4})"
            b"\\x8B\\x4D\\x0C"
        ))

    xor_key_extractor = Extractor("", [xor_key])

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

        print(hex(final_offset), hex(final_size), hex(xor_key))

        bytes_key = xor_key.to_bytes(4, byteorder="big")
        physical_offset = sample.getPhysicalAddress(0x400000 + final_offset)

        for i in range(final_size):
            final_data.append(original_data[physical_offset + i] ^ bytes_key[i % len(bytes_key)])

        # with open("out", "wb") as file:
        #     file.write(bytearray(final_data))

    c2 = Regex(
        "c2",
        "custom",
        (
            b"(.)"
        ),
        decrypt)

    return Extractor("SmokeLoader", [c2])
