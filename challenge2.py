# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #2
# Write a function that takes two equal-length buffers and produces their XOR
# combination.
# If your function works properly, then when you feed it the string:
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
# 686974207468652062756c6c277320657965
# ... should produce:
# 746865206b696420646f6e277420706c6179

src1 = '1c0111001f010100061a024b53535009181c'
src2 = '686974207468652062756c6c277320657965'
dst = '746865206b696420646f6e277420706c6179'


def buf_xor(src1, src2):
    """Perform byte xor of string src1 and src2 and return string value."""
    src1_bytes = bytes.fromhex(src1)
    src2_bytes = bytes.fromhex(src2)
    xor_bytes = []
    if len(src1_bytes) != len(src2_bytes):
        print(' ERROR: buffers are different sizes')
        return None
    for a, b in zip(src1_bytes, src2_bytes):
        xor_bytes.append(a ^ b)

    return bytes(xor_bytes).hex()


if buf_xor(src1, src2) == dst:
    print('Success!')
else:
    print(buf_xor(src1, src2))
    print(dst)
    print('Failure. :-(')
