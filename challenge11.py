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
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def detect_ecb(ct):
    blocksize = 16
    match = False
    numblocks = len(ct) // blocksize
    for i in range(numblocks):
        for j in range(i+1, numblocks):
            if ct[i*blocksize:(i+1)*blocksize] == \
               ct[j*blocksize:(j+1)*blocksize]:
                match = True
    return match


def add_pkcs7_pad(pt, pad, length):
    """Add pad to pt to a block length of length."""
    num_to_add = len(pt) % length
    pad_str = pad * (length - num_to_add)
    # pt_pad = pt + bytes(pad_str, '-utf-8')
    pt_pad = pt + (pad_str)
    return pt_pad


def xor(src1, src2):
    """Perform byte xor of string src1 and src2 and return string value."""
    xor_bytes = []
    if len(src1) != len(src2):
        print(' ERROR: buffers are different sizes')
        return None
    for a, b in zip(src1, src2):
        xor_bytes.append(a ^ b)
    return bytes(xor_bytes)


def ecb_encode(pt, key):
    """Encode pt using key using ECB encryption."""
    encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            ).encryptor()
    ct = encryptor.update(pt) + encryptor.finalize()
    return ct


def ecb_decode(ct, key):
    """Decode ct using key using ECB encryption."""
    decryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            ).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt


def cbc_encode(pt, key, iv):
    """Return CBC mode ciphertext of plaintext, pt, using key and iv."""
    block_size = 16
    number_blocks = len(pt) // block_size
    cipher = ''

    for block in range(number_blocks):
        # print(block, ": ", pt[block*block_size:(block+1)*block_size])
        if block == 0:
            temp_buff = xor(pt[:block_size], iv)
            # print("0:", temp_buff)
            cipher = ecb_encode(temp_buff, key)
            # print("0C", cipher)
        else:
            temp_buff = xor(pt[(block*block_size):((block+1)*block_size)],
                            cipher[((block-1)*block_size):(block*block_size)])
            # print("X:", temp_buff)
            cipher += ecb_encode(temp_buff, key)
            # print("XC", cipher)
    return cipher


def cbc_decode(ct, key, iv):
    """Return CBC mode ciphertext of plaintext, pt, using key and iv."""
    block_size = 16
    number_blocks = len(ct) // block_size
    plain = ""

    for block in range(number_blocks):
        # print(block, ": ", ct[block*block_size:(block+1)*block_size])
        if block == 0:
            temp_buff = ecb_decode(ct[:block_size], key)
            # print("0:", temp_buff)
            plain = xor(temp_buff, iv)
            # print("X0", plain)
        else:
            temp_buff = ecb_decode(ct[(block*block_size):((block+1)*block_size)],
                                   key)
            # print("X:", temp_buff)
            plain += xor(temp_buff, ct[(block-1)*block_size:(block*block_size)])
            # print("XP", plain)
    return plain


def generate_random_key16():
    """Generate 16 bytes of random data and return value."""
    return os.urandom(16)


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

    data = add_pkcs7_pad(data, bytes([4]), 16)

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
