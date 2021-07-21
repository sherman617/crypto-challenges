# -*- coding: utf-8 -*-

# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
# messages, despite the fact that a block cipher natively only transforms
# individual blocks.
#
# In CBC mode, each ciphertext block is added to the next plaintext block
# before the next call to the cipher core.
#
# The first plaintext block, which has no associated previous ciphertext block,
# is added to a "fake 0th ciphertext block" called the initialization vector,
# or IV.

# Implement CBC mode by hand by taking the ECB function you wrote earlier,
# making it encrypt instead of decrypt (verify this by decrypting whatever you
# encrypt to test), and using your XOR function from the previous exercise to
# combine them.

# The file here is intelligible (somewhat) when CBC decrypted against
# "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def add_pkcs7_pad(pt, pad, length):
    """Add pad to pt to a block length of length."""
    num_to_add = length - len(pt) % length
    pad_str = bytes([num_to_add] * num_to_add)
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
    block_size = 16
    encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            ).encryptor()

    ct = encryptor.update(pt) + encryptor.finalize()
    return ct


def ecb_decode(ct, key):
    decryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            ).decryptor()

    pt = decryptor.update(ct) + decryptor.finalize()
    return pt


def cbc_encode(pt, key, iv):
    """Return CBC mode ciphertext of plaintext, pt, using key and iv."""
    block_size = 16
    pt = add_pkcs7_pad(pt, '\x04', 16)
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


KEY = b'YELLOW SUBMARINE'
src_file = '10.txt'
test_file = '10_test2.txt'
block_size = 16

print("Read File")
with open(src_file) as file:
    challenge_data = b64decode(file.read())
with open(test_file) as file:
    pt_data = (file.read())
pt_data = bytes(pt_data, 'utf-8')

print("create initialization vector")
iv = b'\x00' * block_size

# TEST DECRYPT
print("Encrypt test code")
print(pt_data)
cipher = cbc_encode(pt_data, KEY, iv)
print(cipher)
print("Decrypt test code")
plain = cbc_decode(cipher, KEY, iv)
print(plain)

print("Decrypt challenge code")
challenge = cbc_decode(challenge_data, KEY, iv)

print(challenge)
