# -*- coding: utf-8 -*-

# ECB cut-and-paste

from libcrypto import (detect_ecb, add_pkcs7_pad,
                       ecb_encode, ecb_decode, remove_pkcs7_pad,
                       generate_random_key16)


def kvdecode(string):
    """Decode key-value string into dictionary of key-value pairs."""
    kv_dict = {}
    pairs = string.split('&')
    for p in pairs:
        kv = p.split('=')
        kv_dict[kv[0]] = kv[1]

    return kv_dict


def kvencode(d):
    """Encode dictionary email, uid, and role into a key-value string."""
    string = 'email=' + removemeta(str(d['email'])) + \
             '&uid=' + removemeta(str(d['uid'])) + \
             '&role=' + removemeta(str(d['role']))
    return string


def removemeta(string):
    """Remove meta characters & and = from string and return new value."""
    for char in '&=':
        string = string.replace(char, '')
    return string


def profile_for(email):
    #email = bytes(removemeta(str(email)), 'utf-8')
    #print ('email2', email)
    return b'email=' + email + b'&uid=10&role=user'

def encode(string, key):
    d = kvencode(string)
    d = add_pkcs7_pad(bytes(d, 'utf-8'), 16)
    f = ecb_encode(d, key)
    return f

test_str = 'foo=bar&baz=qux&zap=zazzle'
c = kvdecode(test_str)
print(c)

key = generate_random_key16()
key = b'\x9a\xac\xeb+u\xf1\x8d\xcf\xcelIS\x96\xe5\x80\xab'
print('key', key)

u1 = {'email': 'jake3456617@att.net', 'uid': 10, 'role': 'user&='}
print(u1)
f = encode(u1, key)
print(f)

u1 = {'email': 'jake345661723456789012@att.net', 'uid': 10, 'role': 'admin'}
print(u1)
f = encode(u1, key)
print(f)

u1 = 'admin'
d = add_pkcs7_pad(bytes(u1, 'utf-8'), 16)
j = ecb_encode(d, key)
print('admin', f)

f = profile_for(b'jake34561723456789012@att.net')
print('email', f)
print(len(f))
f = add_pkcs7_pad(f, 16)
print(f)
f = ecb_encode(f, key)
print(f)
g = f[:48]
print(g)
g = g + j
print(g)
c = ecb_decode(g,key)
print(c)
c = remove_pkcs7_pad(c, 16)
print(c)
