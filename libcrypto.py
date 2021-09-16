# -*- coding: utf-8 -*-
#
# Library of crypto functions used for CryptoPals challenges

import os
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def detect_ecb(ct):
    """Detect if crypto text, ct, looks like it is encoded with ECB."""
    blocksize = 16
    match = False
    numblocks = len(ct) // blocksize
    for i in range(numblocks):
        for j in range(i+1, numblocks):
            if ct[i*blocksize:(i+1)*blocksize] == \
               ct[j*blocksize:(j+1)*blocksize]:
                match = True
    return match


def add_pkcs7_pad(pt, length):
    """Add pad to pt to a block length of length."""
    num_to_add = length - len(pt) % length
    pad_str = bytes([num_to_add] * num_to_add)
    if num_to_add == 16:
        pt_pad = pt
    else:
        pt_pad = pt + (pad_str)
    return pt_pad


def remove_pkcs7_pad(pt, length):
    """Remove pad bytes from pt with a block length of length."""
    num_to_remove = pt[-1]
    return pt[:- num_to_remove]


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

