#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import socket
import sys

import toytls.tls as tls


def hexdump(bytes, step=32):
    i = 0
    while True:
        sub = bytes[i:i+step]
        if not sub:
            break
        print sub.encode('hex')
        i += step


def do_handshake_socket(ctx, host, port):
    s = socket.socket()
    s.connect((host, port))

    def send_func(buf):
        s.sendall(buf)

    def recv_func(n=0):
        ret = s.recv(16*1024)
        return ret

    try:
        tls.do_handshake(ctx, send_func, recv_func)
    finally:
        s.close()


def main():
    try:
        host, port, path = sys.argv[1:]
        port = int(port)
    except Exception, e:
        print >> sys.stderr, 'usage: %s HOST PORT PATH' % (sys.argv[0],)
        sys.exit(1)

    message = sys.stdin.read()

    if len(message) > 32:
        print >> sys.stderr, 'error: message length must be less than 32 bytes'
        sys.exit(1)
    message += '\x00' * (32 - len(message))
    assert len(message) == 32

    print 'Signing message:'
    hexdump(message)
    print

    ctx = tls.TLSContext()
    ctx.ciphers = [tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                   tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]
    ctx.client_random = message
    ctx.pre_master_secret = tls.TLS_VERSION_STR + 'b'*46

    do_handshake_socket(ctx, host, port)

    print 'Bytes signed:'
    hexdump(ctx.signed_bytes)
    file(path + '.bytes', 'w').write(ctx.signed_bytes)
    print
    print 'Signature:'
    hexdump(ctx.signed_signature)
    file(path + '.signature', 'w').write(ctx.signed_signature)
    print
    print 'Server certificate:'
    hexdump(ctx.certificates[0])
    file(path + '.certificate.der', 'w').write(ctx.certificates[0])


if __name__ == '__main__':
    main()
