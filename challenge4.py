# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #4
# Detect single-character XOR
# One of the 60-character strings in this file has been encrypted by single-character XOR.
# Find it.

src = '4.txt'


def english_score(pt):
    """Score a string pt based on how many characters are in the alphabet."""
    str_score = 0
    for b in pt:
#        if bytes([b]).isprintable():
        if (b==32) or (b>96 and b<123) or (b> 64 and b<91):
            str_score += 1

    return str_score


def byte_xor(src, h):
    """Perform byte-wise XOR of the src string with byte h and return string."""
    xor_bytes = bytearray()
    for b in src:
        xor_bytes.append(b ^ h)

    return xor_bytes


hexlist = bytearray([x for x in range(256)])
high_score = 0
f = open(src, "r")

for l in f:
    l_bytes = bytes.fromhex(l.rstrip())
    for h in hexlist:
        new_str = byte_xor(l_bytes, h)
        new_score = english_score(new_str)
        if new_score >= high_score:
            high_score = new_score
            xor_byte = h
            line = l_bytes

best = byte_xor(line, xor_byte)
print('XOR byte = ', hex(xor_byte))
print("Original Line")
print(line)
print(best.decode())
f.close()
