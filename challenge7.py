# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #7
# The Base64-encoded content in this file has been encrypted via AES-128 in
# ECB mode under the key
#    "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like
# "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
# Decrypt it. You know the key, after all.


from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

src_file = '7.txt'
KEY = b"YELLOW SUBMARINE"


with open(src_file) as file:
    data = b64decode(file.read())
# print(data)
# print (type(data))


decryptor = Cipher(
        algorithms.AES(KEY),
        modes.ECB(),
        ).decryptor()

plain_text = decryptor.update(data) + decryptor.finalize()
print(plain_text.decode())
