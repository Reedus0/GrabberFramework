import re
import ctypes

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex

from Cryptodome.Cipher import ARC4


def SmokeLoader(lib_path: str):

    def decompress(buffer):
        if (buffer[-1] != 0xE8 and buffer[-1] != 0xEE):
            return []
        if (buffer[-1] == 0xEE):
            buffer[-1] = 0xE8
            
        lzsa = ctypes.CDLL(lib_path + "/" + "lzsa.so")

        lzsa.lzsa2_decompress.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]

        pointer_buffer = (ctypes.c_char * len(buffer))(*buffer)
        pointer_out = (ctypes.c_char * 0x40000)()

        lzsa.lzsa2_decompress(
            ctypes.cast(pointer_out, ctypes.POINTER(ctypes.c_char)),
            ctypes.cast(pointer_buffer, ctypes.POINTER(ctypes.c_char))
        )

        return pointer_out[:]

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

        with open("out", "wb") as file:
            file.write(bytes(final_data))

        decompressed_data = decompress(final_data[4:])

        strings_start = 0

        for i in range(len(decompressed_data)):
            key = bytes(decompressed_data[i:i + 4])
            data = bytes(decompressed_data[i + 5: i + 9])

            cipher = ARC4.new(key)
            msg = cipher.decrypt(data)
            if (msg == b"http"):
                strings_start = i
                break
        else:
            return ""

        decrypt_strings(decompressed_data, strings_start)

    c2 = Regex(
        "c2",
        "custom",
        (
            b"(.)"
        ),
        decrypt)

    return Extractor("SmokeLoader", [c2])
