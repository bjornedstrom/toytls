#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime
import hashlib
import os
import socket
import sys
import struct

import toytls.tls as tls
import toytls.rsa
import toytls.x509


def hexdump(bytes, step=32):
    i = 0
    while True:
        sub = bytes[i:i+step]
        if not sub:
            break
        print sub.encode('hex')
        i += step


def main():
    try:
        path = sys.argv[1]
    except Exception, e:
        print >> sys.stderr, 'usage: %s PATH' % (sys.argv[0],)
        sys.exit(1)

    certificate = file(path + '.certificate.der').read()
    signature = file(path + '.signature').read()
    bytes = file(path + '.bytes').read()

    rsa = toytls.rsa.RSA(*toytls.x509.parse_der(certificate))
    check = rsa.verify(signature, hashlib.md5(bytes).digest() + hashlib.sha1(bytes).digest())

    if check:
        print 'Signature Verification SUCCESS'
        print
    else:
        print >> sys.stderr, 'Signature Verification FAILURE'
        sys.exit(1)

    print 'Bytes signed:'
    hexdump(bytes)
    print
    print 'Bytes signed, user supplied messsage (hex):'
    hexdump(bytes[0:32])
    print
    print 'Bytes signed, user supplied messsage (repr):'
    print repr(bytes[0:32])
    print
    print 'Bytes signed, server unix timestamp:'
    ts, = struct.unpack('!L', bytes[32:32+4])
    print ts
    print
    print 'Bytes signed, server UTC timestamp:'
    print datetime.datetime.utcfromtimestamp(ts)
    print
    print 'Signature:'
    hexdump(signature)
    print
    print 'Server certificate. For more details, do:'
    print ' $ openssl asn1parse -inform DER -in %s' % (path + '.certificate.der',)
    print
    hexdump(certificate)



if __name__ == '__main__':
    main()
