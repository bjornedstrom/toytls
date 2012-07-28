# -*- coding: utf-8 -*-

import math
import struct
import hashlib

from M2Crypto import m2


def mpi_to_num(mpi):
    return int(m2.bn_to_hex(m2.mpi_to_bn(mpi)), 16)

def num_to_mpi(num):
    return m2.bn_to_mpi(m2.dec_to_bn(str(num)))

def num_to_bytes(num, padding=None):
    def raw():
        if num == 0:
            return ''
        b = num_to_mpi(num)[4:]
        if b[0] == '\x00':
            return b[1:]
        return b
    ret = raw()
    if padding is None:
        return ret
    return '\x00' * (padding - len(ret)) + ret

def bytes_to_num(bytes):
    return mpi_to_num(struct.pack('!Lb', len(bytes) + 1, 0) + bytes)

def getRandomBytes(howMany):
    s = os.urandom(howMany)
    assert(len(s) == howMany)
    return s

class RSA(object):
    def __init__(self, n, e):
        self.rsa = None
        self.n = n
        self.e = e

        self.rsa = m2.rsa_new()
        m2.rsa_set_n(self.rsa, num_to_mpi(self.n))
        m2.rsa_set_e(self.rsa, num_to_mpi(self.e))

        self.n_bytes = len(num_to_bytes(self.n))

    def encrypt(self, bytes):
        padded = self._pkcs1_padding(bytes)
        m = bytes_to_num(padded)
        if m >= self.n:
            raise ValueError()
        c = self._public_crypt(m)
        enc = num_to_bytes(c, self.n_bytes)
        return enc

    def verify(self, signature, bytes):
        if len(signature) != self.n_bytes:
            return False
        padded_bytes = self._pkcs1_padding(bytes, True)
        c = bytes_to_num(signature)
        if c >= self.n:
            return False
        m = self._public_crypt(c)
        check_bytes = num_to_bytes(m, self.n_bytes)
        #print (check_bytes, padded_bytes)
        return check_bytes == padded_bytes

    def _pkcs1_padding(self, bytes, signature=False):
        pad_length = (self.n_bytes - (len(bytes)+3))

        if signature:
            pad = [0xFF] * pad_length
            padding_type = 1
        else:
            pad = []
            padding_type = 2
            while len(pad) < pad_length:

# XXX (bjorn): Avoid this
#               pad_bytes = getRandomBytes(pad_length * 2)
                pad_bytes = [1]*(pad_length*2)
###
                pad = [b for b in pad_bytes if b != 0]
                pad = pad[:pad_length]


        padding = ''.join(map(chr,[0, padding_type] + pad + [0]))
        return padding + bytes

    def _public_crypt(self, c):
        s = num_to_bytes(c, self.n_bytes)
        m = bytes_to_num(m2.rsa_public_decrypt(self.rsa, s, m2.no_padding))
        return m
