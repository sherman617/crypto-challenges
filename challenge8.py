# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #8
# In this file are a bunch of hex-encoded ciphertexts.
#
# One of them has been encrypted with ECB.
#
# Detect it.
#
# Remember that the problem with ECB is that it is stateless and deterministic;
# the same 16 byte plaintext block will always produce the same 16 byte
# ciphertext.


from binascii import unhexlify

src_file = '8.txt'
blocksize = 16

with open(src_file) as file:
    for line in file:
        numblocks = len(line) // blocksize
        for i in range(numblocks):
            for j in range(i+1, numblocks):
                if line[i*blocksize:(i+1)*blocksize] == \
                   line[j*blocksize:(j+1)*blocksize]:
                    match = {i, j}
                    matchline = line

print(match)
print(matchline)
print(unhexlify(matchline.strip()))
