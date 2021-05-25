# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #1
# Convert hex to base64
# The string:
# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# Should produce:
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

src = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
dst = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

import base64


def str_to_b64(src):
    """Convert string src and return as base64."""
    src_bytes = bytes.fromhex(src)
    return base64.b64encode(src_bytes).decode('utf-8')


if str_to_b64(src) == dst:
    print('Success!')
else:
    print (str_to_b64(src))
    print('Failure. :-(')
