# -*- coding: utf-8 -*-

# Byte-at-a-time ECB decryption (Simple)


from libcrypto import (detect_ecb, add_pkcs7_pad,
                       ecb_encode,
                       generate_random_key16)
from base64 import b64decode


ct_data = b64decode(
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
    'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
    'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
    'YnkK')


def encryption_oracle(data, key):
    """Encrypt data using random key and encryption to use. Return data."""
    data = add_pkcs7_pad(data, 16)
    ct = ecb_encode(data, key)

    return ct


def find_block_size(data, key):
    """Determine block size of encryption using oracle."""
    ct = encryption_oracle(b"A" + ct_data, key)
    for i in range(2, 20):
        prev_ct = ct
        ct = encryption_oracle((b"A" * i) + ct_data, key)
        if (prev_ct[:4] == ct[:4]):
            return i-1


data = bytes([0]*64)
key = generate_random_key16()
block_size = find_block_size(data, key)
assert block_size == 16

is_ecb = detect_ecb(encryption_oracle((b"A" * 50) + ct_data, key))
assert is_ecb

pt = b''
for i in range(len(ct_data)):
    ct_byte = encryption_oracle((b"A" * 15) + ct_data[i:], key)
    for j in range(256):
        check_byte = encryption_oracle((b"A" * 15) + bytes([j]), key)
        if check_byte[:16] == ct_byte[:16]:
            pt = pt + bytes([j])
print(pt.decode())
