# -*- coding: utf-8 -*-

""" reference implementation of TLS PRF from tlslite
"""

import hashlib
import math
import hmac


def P_hash(hashmod, secret, seed, length):
    bytes = ['\x00'] * length
    A = seed
    index = 0
    while 1:
        A = hmac.HMAC(secret, A, hashmod).digest()
        output = hmac.HMAC(secret, A+seed, hashmod).digest()
        for c in output:
            if index >= length:
                return ''.join(bytes)
            bytes[index] = c
            index += 1
    return ''.join(bytes)


def PRF(secret, label, seed, length):
    half = int(math.ceil(len(secret)/2.0))
    S1 = secret[:half]
    S2 = secret[half:]
    p_md5 = P_hash(hashlib.md5, S1, label + seed, length)
    p_sha1 = P_hash(hashlib.sha1, S2, label + seed, length)
    res = []
    for x in range(length):
        res.append(chr(ord(p_md5[x]) ^ ord(p_sha1[x])))
    return ''.join(res)
