# -*- coding: utf-8 -*-

# Cryptopals Cryptochallenge #5
# Implement repeating-key XOR
# Here is opening stanza of an important work of the English language:
#   Burning 'em, if you ain't quick and nimble
#   I go crazy when I hear a cymbal
# Encrypt it, under the key "ICE", using repeating-key XOR.

src = ("Burning 'em, if you ain't quick and nimble\n"
       "I go crazy when I hear a cymbal")
key = 'ICE'

dst = ('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622'
       '6324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b'
       '20283165286326302e27282f')


def __repeat_string(string, length):
    num_repeats = length // len(string) + 1
    repeat_str = string * num_repeats
    repeat_str2 = repeat_str[:length]
    return repeat_str2


def buf_xor(s1, s2):
    """Perform byte xor of string s1 and s2 and return string value."""
    s1_bytes = (s1)
    s2_bytes = (s2)
    xor_bytes = []
    if len(s1_bytes) != len(s2_bytes):
        print(' ERROR: buffers are different sizes')
        return None
    for a, b in zip(s1_bytes, s2_bytes):
        xor_bytes.append(a ^ b)

    return bytes(xor_bytes).hex()


key1 = __repeat_string(key, len(src))

result1 = buf_xor(src.encode('utf-8'), key1.encode('utf-8'))

if result1 == dst:
    print('Success!')
else:
    print('Failure. :-(')
    print(buf_xor(src.encode('utf-8'), key1.encode('utf-8')))
    print(dst)
    