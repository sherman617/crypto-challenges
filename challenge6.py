# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #6
# Break repeating-key XOR
# file6.txt has been base64'd after being encrypted with repeating-key XOR
# Decrypt it.

from base64 import b64decode

src_file = '6.txt'
test1 = 'this is a test'
test2 = 'wokka wokka!!!'
hamm_res = 37
hamm_res_dict = dict()

KEYSIZE = list(range(2, 41))


def __hamming_distance(a, b):
    # print(a, b)
    dist = buf_xor(a, b)
    count = sum(bin(byte).count('1') for byte in dist)
    return count


def english_score(pt):
    """Score a string pt based on how many characters are in the alphabet."""
    str_score = 0
    for b in pt:
#         print(b)
        if bytes([b]).isalpha() or (b == 32):
            str_score += 500
        if bytes([b]).isdigit() or (b == 96):
            str_score += 25
        if (b > 127) or (b < 31):
            str_score -= 1000
        if (b > 21) and (b < 46):
            str_score -= 25
    return str_score


def crack_single_xor(d):
    high_score = -999999
    hexlist = bytearray([x for x in range(256)])
    for h in hexlist:
        new_str = byte_xor(d, h)
        new_score = english_score(new_str)
#        print(h, new_str, english_score(new_str))
        if new_score > high_score:
            high_score = new_score
            xor_byte = h
#        print(high_score, xor_byte)
    return xor_byte


def byte_xor(src, h):
    """Perform byte-wise XOR of the src string with byte h and return string."""
    xor_bytes = bytearray()
    for b in src:
        xor_bytes.append(b ^ h)
    return xor_bytes


def buf_xor(s1, s2):
    """Perform byte xor of string s1 and s2 and return string value."""
    xor_bytes = []
    if len(s1) != len(s2):
        print(' ERROR: buffers are different sizes')
        return None
    for a, b in zip(s1, s2):
        xor_bytes.append(a ^ b)
    return bytes(xor_bytes)


def __repeat_string(string, length):
    num_repeats = length // len(string) + 1
    repeat_str = string * num_repeats
    repeat_str2 = repeat_str[:length]
    return repeat_str2


with open(src_file) as file:
    data = b64decode(file.read())
# print(data)
# print (type(data))

for key in KEYSIZE:
    edit_distance = 0
    num_samples = len(data) // (2*key) - 1
    for i in range(num_samples):
        edit_distance += __hamming_distance(data[i*key:(i+1)*key],
                                            data[(i+1)*key:(i+2)*key])
    edit_distance = edit_distance / (num_samples * key)
    hamm_res_dict[key] = edit_distance

min_hamm_distance = min(hamm_res_dict, key=hamm_res_dict.get)
# print(min_hamm_distance)

bb = bytearray()
block = bytes()
# for j in range(min_hamm_distance):
for j in range(0, min_hamm_distance):
    block = bytes()
    for i in range(len(data) // min_hamm_distance):
        block = block + data[i*min_hamm_distance+j:i*min_hamm_distance + j + 1]
#    print("BLOCK:", i, j, block)
    xbyte = crack_single_xor(block)
#    print("XBYTE:", xbyte)
    bb.append(xbyte)
#    print(bb)
#    print("BYTE_XOR:", xbyte, byte_xor(block, xbyte))
print("KEY:", bb)

key1 = __repeat_string(bb, len(data))
# result1 = buf_xor(data.encode('utf-8'), key1.encode('utf-8'))
result1 = buf_xor(data, key1)
print(result1)


if __hamming_distance(test1.encode('utf-8'), test2.encode('utf-8')) == hamm_res:
    print('Success!')
else:
    print('Failure. :-(')
    print(__hamming_distance(test1, test2))
