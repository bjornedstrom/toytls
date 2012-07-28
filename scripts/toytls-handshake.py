#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
import sys

import toytls.tls as tls


def do_handshake_socket(ctx, host, port):
    s = socket.socket()
    s.connect((host, port))

    def send_func(buf):
        print '>>>', buf.encode('hex')
        s.sendall(buf)

    def recv_func(n=0):
        ret = s.recv(16*1024)
        print '<<<', ret.encode('hex')
        return ret

    try:
        tls.do_handshake(ctx, send_func, recv_func)
    finally:
        s.close()


def main():
    try:
        host, port = sys.argv[1:]
        port = int(port)
    except Exception, e:
        print >> sys.stderr, 'usage: %s HOST PORT' % (sys.argv[0],)
        sys.exit(1)

    ctx = tls.TLSContext()
    ctx.ciphers = [tls.TLS_RSA_WITH_RC4_128_SHA]
    ctx.client_random = 'a'*32
    ctx.pre_master_secret = tls.TLS_VERSION_STR + 'b'*46

    do_handshake_socket(ctx, host, port)


if __name__ == '__main__':
    main()
