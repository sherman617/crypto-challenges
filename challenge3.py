# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #3
# Single-byte XOR cipher
# The hex encoded string:
# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character. Find the key, decrypt the message.

src = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'


def english_score(pt):
    """Score a string pt based on how many characters are in the alphabet."""
    str_score = 0
    for b in pt:
        if bytes([b]).isalpha():
            str_score += 1

    return str_score


def byte_xor(src, h):
    """Perform byte-wise XOR of the src string with byte h and return string."""
    xor_bytes = bytearray()
    for b in src:
        xor_bytes.append(b ^ h)

    return xor_bytes


src_bytes = bytes.fromhex(src)
high_score = 0
hexlist = bytearray([x for x in range(256)])
for h in hexlist:
    new_str = byte_xor(src_bytes, h)
    new_score = english_score(new_str)
    if new_score > high_score:
        high_score = new_score
        xor_byte = h

best = byte_xor(src_bytes, xor_byte)

print('XOR byte = ', hex(xor_byte))
print(best.decode())
