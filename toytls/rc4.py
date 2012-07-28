# -*- coding: utf-8 -*-

from M2Crypto import m2

class RC4(object):
    def __init__(self, key):
        if len(key) < 16 or len(key) > 256:
            raise ValueError()
        self.rc4 = m2.rc4_new()
        m2.rc4_set_key(self.rc4, key)

    def __del__(self):
        m2.rc4_free(self.rc4)

    def encrypt(self, plaintext):
        return m2.rc4_update(self.rc4, plaintext)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)
