import re
import base64
import binascii
import hashlib
from Cryptodome.Cipher import AES

from ..extractor import Extractor
from ..sample import Sample
from ..regex import Regex


def XWorm():
    def decrypt(sample: Sample, regex_result: re.Match):
        strings = []
        string_offset = int.from_bytes(regex_result[1], "little")

        current_string = sample.readCLIString(string_offset)

        while (1):
            try:
                base64.decodebytes(current_string.encode())
                strings.append(current_string[:-1])
                string_offset += len(current_string * 2)
                current_string = sample.readCLIString(string_offset)

            except binascii.Error:
                strings.pop()
                break
        try:
            mutex = strings[-1]
        except:
            return ""

        md5 = hashlib.md5(mutex.encode()).digest()
        key = bytearray(32)
        key[0:16] = md5
        key[15:31] = md5

        result = base64.b64decode(strings[0])
        cipher = AES.new(bytes(key), AES.MODE_ECB)
        try:
            decrypted_result = cipher.decrypt(bytes(result)).decode()
            decrypted_result = re.sub(r'[^\x20-\x7f]', r'', decrypted_result)
        except:
            return ""

        return decrypted_result

    c2 = Regex(
        "c2",
        "custom",
        (
            b"\\x72(.{3})\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72.{3}\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72.{3}\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72.{3}\\x70"
        ),
        decrypt)

    c2_port = Regex(
        "c2_port",
        "custom",
        (
            b"\\x72.{3}\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72(.{3})\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72.{3}\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72.{3}\\x70"
        ),
        decrypt)

    aes_key = Regex(
        "aes_key",
        "custom",
        (
            b"\\x72.{3}\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72.{3}\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72(.{3})\\x70"
            b"\\x80.{3}\\x04"
            b"\\x72.{3}\\x70"
        ),
        decrypt)

    return Extractor("XWorm", [c2, c2_port, aes_key])
