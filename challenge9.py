# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #9
# A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
# plaintext into ciphertext. But we almost never want to transform a single
# block; we encrypt irregularly-sized messages.
# One way we account for irregularly-sized messages is by padding, creating a
# plaintext that is an even multiple of the blocksize. The most popular padding
# scheme is called PKCS#7.
# So: pad any block to a specific block length, by appending the number of
# bytes of padding to the end of the block. For instance,
# "YELLOW SUBMARINE"
# ... padded to 20 bytes would be:
# "YELLOW SUBMARINE\x04\x04\x04\x04"


def add_pkcs7_pad(pt, pad, length):
    """Add pad to pt to a block length of length."""
    num_to_add = len(pt) % length
    pad_str = pad * (length - num_to_add)
    pt_pad = pt + pad_str.decode()
    return pt_pad


print(add_pkcs7_pad("YELLOW SUBMARINE", b'\x04', 20).encode())
