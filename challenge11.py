# -*- coding: utf-8 -*-

# Write a function to generate a random AES key; that's just 16 random bytes.
#
# Write a function that encrypts data under an unknown key --- that is, a
# function that generates a random key and encrypts under it.
#
# The function should look like:

# encryption_oracle(your-input)
# => [MEANINGLESS JIBBER JABBER]
# Under the hood, have the function append 5-10 bytes (count chosen randomly)
# before the plaintext and 5-10 bytes after the plaintext.
#
# Now, have the function choose to encrypt under ECB 1/2 the time, and under
# CBC the other half (just use random IVs each time for CBC). Use rand(2) to
# decide which to use.
#
# Detect the block cipher mode the function is using each time. You should end
# up with a piece of code that, pointed at a block box that might be encrypting
# ECB or CBC, tells you which one is happening.


import os
import random
from libcrypto import (detect_ecb, add_pkcs7_pad, xor, 
                       ecb_encode, ecb_decode, cbc_encode, cbc_decode,
                       generate_random_key16)
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def encryption_oracle(data):
    """Encrypt data using random key and encryption to use. Return data."""
    key = generate_random_key16()
    iv = os.urandom(16)
    encryption_type = random.randint(1, 2)
    pre_num_bytes = random.randint(1, 5)
    post_num_bytes = random.randint(1, 5)

    data = bytes([4] * pre_num_bytes) + data + bytes([4] * post_num_bytes)
    print("DATA:", data)
    print("KEY: ", key)
    print("IV:  ", iv)
    print("TYPE:", encryption_type)
    print("PRE: ", pre_num_bytes)
    print("POST:", post_num_bytes)

    data = add_pkcs7_pad(data, 16)
    print("PAD: ", data)

    if encryption_type == 1:
        ct = cbc_encode(data, key, iv)
    else:
        ct = ecb_encode(data, key)

    print("CT:  ", ct)

    return ct


DATA = bytes([0]*64)
unknown_ct = encryption_oracle(DATA)

key = generate_random_key16()
iv = os.urandom(16)
print("CBC: ", cbc_decode(unknown_ct, key, iv))
print("ECB: ", ecb_decode(unknown_ct, key))
print(detect_ecb(unknown_ct))
