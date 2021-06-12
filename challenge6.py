# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #6
# Break repeating-key XOR
# file6.txt has been base64'd after being encrypted with repeating-key XOR
# Decrypt it.

src_file = 'file6.txt'
test1 = 'this is a test'
test2 = 'wokka wokka!!!'
hamm_res = 37


def __hamming_distance(a, b):
    dist = buf_xor(a, b)
    count = sum(bin(byte).count('1') for byte in dist)
    return count


def __count_set_bits(n):
    count = 0
    while n:
        n &= n - 1
        count += 1
    return count


def buf_xor(s1, s2):
    """Perform byte xor of string s1 and s2 and return string value."""
    xor_bytes = []
    if len(s1) != len(s2):
        print(' ERROR: buffers are different sizes')
        return None
    for a, b in zip(s1, s2):
        xor_bytes.append(a ^ b)

    return bytes(xor_bytes)


if __hamming_distance(test1.encode('utf-8'), test2.encode('utf-8')) == hamm_res:
    print('Success!')
else:
    print('Failure. :-(')
    print(__hamming_distance(test1, test2))
