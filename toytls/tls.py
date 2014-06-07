# -*- coding: utf-8 -*-
#
# Copyright (c) 2012 Björn Edström <be@bjrn.se>
# See license for details.

"""
http://tools.ietf.org/html/rfc5246#section-7.4.2
http://tools.ietf.org/html/rfc4492#section-5.4
http://tools.ietf.org/html/rfc6066
"""

import hashlib
import hmac
import struct
import cStringIO as stringio
import socket
import time

import toytls.rc4
import toytls.rsa
import toytls.hash
import toytls.x509


TLS_VERSION = 0x0302 # TLS 1.1
TLS_VERSION_STR = '\x03\x02' # TLS 1.1

TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_CIPHER_SPEC = 20

TLS_HANDSHAKE_CLIENT_HELLO = 1
TLS_HANDSHAKE_SERVER_HELLO = 2
TLS_HANDSHAKE_CERTIFICATE = 11
TLS_HANDSHAKE_SERVER_HELLO_DONE = 14
TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 0x10
TLS_HANDSHAKE_FINISHED = 0x14

TLS_RSA_WITH_RC4_128_SHA = 0x0005
TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014


TLS_CIPHER_SUITE = [
    # name, mac length, key length, iv length
    (TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 20, 16, 0)
]


class TLSContext(object):
    def __init__(self):
        self.cipher = None
        self.ciphers = None
        self.client_random = None
        self.server_random = None
        self.pre_master_secret = None
        self.rsa = None
        self.certificates = []
        self.client_num = 0
        self.server_num = 0
        self.signed_bytes = None
        self.signed_signature = None

        # private
        self._handshake_hash_sha1 = hashlib.sha1()
        self._handshake_hash_md5 = hashlib.md5()

    def master_secret(self):
        return toytls.hash.PRF(self.pre_master_secret,
                               'master secret',
                               self.client_random + self.server_random,
                               48)

    def update_hash(self, buf):
        self._handshake_hash_sha1.update(buf)
        self._handshake_hash_md5.update(buf)

    def setup_crypto(self):
        crypto_settings = TLS_CIPHER_SUITE[0] # XXX Hard coded

        material = stringio.StringIO(toytls.hash.PRF(self.master_secret(),
                           'key expansion',
                           self.server_random + self.client_random,
                           crypto_settings[1]*2 + crypto_settings[2]*2 + crypto_settings[3]*2))

        client_mac = material.read(crypto_settings[1])
        server_mac = material.read(crypto_settings[1])

        client_key = material.read(crypto_settings[2])
        server_key = material.read(crypto_settings[2])

        client_iv = material.read(crypto_settings[3])
        server_iv = material.read(crypto_settings[3])

        self.client_enc = toytls.rc4.RC4(client_key)
        self.server_enc = toytls.rc4.RC4(server_key)

        hmac_func = lambda k: hmac.new(k, digestmod=hashlib.sha1)

        self.client_mac = hmac_func(client_mac)
        self.server_mac = hmac_func(server_mac)

    def get_client_verify_data(self):
        handshake_hashes = self._handshake_hash_md5.digest() + self._handshake_hash_sha1.digest()
        self.client_verify_data = toytls.hash.PRF(self.master_secret(),
                                           'client finished', handshake_hashes, 12)

    def get_server_verify_data(self):
        handshake_hashes = self._handshake_hash_md5.digest() + self._handshake_hash_sha1.digest()
        self.server_verify_data = toytls.hash.PRF(self.master_secret(),
                                           'server finished', handshake_hashes, 12)


def header(content_type, msg):
    return struct.pack('!bHH', content_type, TLS_VERSION, len(msg))


def sub_header_handshake(msg_type, msg):
    header = struct.pack('!L', (msg_type << 24) | len(msg))
    return header + msg


def make_msg_client_hello(ctx):
    assert ctx.client_random and len(ctx.client_random) == 32

    # 7.4.1.4.1. Signature Algorithms
    #ext_data = '\x02\x01\x02\x02' # sha1-rsa
    #extension = struct.pack('!HH', 13, len(ext_data)) + ext_data

    extension = ''

    # http://tools.ietf.org/html/rfc4492#section-5.4  0xc011  TLS_ECDHE_RSA_WITH_RC4_128_SHA (TLS 3.1)

    ciphers = ''
    for cipher in ctx.ciphers:
        ciphers += struct.pack('!H', cipher)

    client_hello = TLS_VERSION_STR + ctx.client_random + \
        struct.pack('!bH%ssHH' % len(ciphers),
                    0,
                    len(ciphers), # cipher suites length
                    ciphers,
                    0x0100, # no compression
                    len(extension)
                    ) + extension

    client_hello = sub_header_handshake(TLS_HANDSHAKE_CLIENT_HELLO, client_hello)

    ctx.update_hash(client_hello)

    return (TLS_CONTENT_HANDSHAKE, client_hello)


def make_msg_client_key_exchange(ctx):
    assert ctx.rsa
    assert ctx.pre_master_secret and len(ctx.pre_master_secret) == 48

    encrypted_pre_master_secret = ctx.rsa.encrypt(ctx.pre_master_secret)

    key = '\x00\x80' + str(encrypted_pre_master_secret)

    client_key_exchange = sub_header_handshake(TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE, key)

    ctx.update_hash(client_key_exchange)

    return (TLS_CONTENT_HANDSHAKE, client_key_exchange)


def make_msg_change_cipher_spec(ctx):

    return (TLS_CONTENT_CIPHER_SPEC, '\x01')


def parse_change_cipher_spec(ctx, s):

    header_type, header_version, header_length = \
            struct.unpack('!bHH', s.read(1 + 2 + 2))

    assert s.read(1) == '\x01'


def make_msg_finished(ctx):
    assert ctx.client_verify_data

    finished = sub_header_handshake(TLS_HANDSHAKE_FINISHED, str(ctx.client_verify_data))

    ctx.update_hash(finished)

    return  (TLS_CONTENT_HANDSHAKE, finished)


def parse_finished(ctx, s):

    header_type, header_version, header_length = \
            struct.unpack('!bHH', s.read(1 + 2 + 2))

    assert header_type == 0x16

    msg = decrypt_msg(ctx, 'server', header_type, s.read(header_length))

    ss = stringio.StringIO(msg[1])

    type_length, = struct.unpack('!L', ss.read(4))
    msg_type = type_length >> 24
    msg_length = type_length & 0xffffff

    assert msg_type == 0x14 # XXX

    assert ss.read() == ctx.server_verify_data


def parse_server_hello(ctx, s):
    header_type, header_version, header_length = \
            struct.unpack('!bHH', s.read(1 + 2 + 2))

    buf = s.read(header_length)

    ctx.update_hash(buf)

    ss = stringio.StringIO(buf)

    type_length, = struct.unpack('!L', ss.read(4))
    msg_type = type_length >> 24
    msg_length = type_length & 0xffffff

    assert msg_type == TLS_HANDSHAKE_SERVER_HELLO

    assert ss.read(2) == TLS_VERSION_STR # version

    ctx.server_random = ss.read(32)

    session_length, = struct.unpack('!b', ss.read(1))
    session_id = ss.read(session_length)
    yy = ss.read(3)
    ctx.cipher, compression = struct.unpack('!Hb', yy)


def parse_server_key_exchange(ctx, s):

    if ctx.ciphers in ([TLS_RSA_WITH_RC4_128_SHA],):
        return

    assert ctx.rsa

    header_type, header_version, header_length = \
            struct.unpack('!bHH', s.read(1 + 2 + 2))

    buf = s.read(header_length)

    ctx.update_hash(buf)

    ss = stringio.StringIO(buf)

    type_length, = struct.unpack('!L', ss.read(4))
    msg_type = type_length >> 24
    msg_length = type_length & 0xffffff

    assert msg_type == 12

    raw = []
    def get_field(ss):
        x = ss.read(2)
        length, = struct.unpack('!H', x)
        y = ss.read(length)
        raw.append(x + y)
        return y

    #opaque dh_p<1..2^16-1>;
    #opaque dh_g<1..2^16-1>;
    #opaque dh_Ys<1..2^16-1>;

    if ctx.cipher == TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        dh_p = get_field(ss)
        dh_g = get_field(ss)
        df_Ys = get_field(ss)

    elif ctx.cipher in (TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA):
        tmp = ss.read(1) # type
        assert tmp == '\x03'
        raw.append(tmp)
        tmp = ss.read(2) # named curve
        raw.append(tmp)
        length_str = ss.read(1)
        raw.append(length_str)
        point = ss.read(ord(length_str))
        raw.append(point)

    bytes = ctx.client_random + ctx.server_random + ''.join(raw)

    ctx.signed_bytes = bytes

    length, = struct.unpack('!H', ss.read(2))
    signature = ss.read(length)
    ctx.signed_signature = signature
    assert ss.read() == ''



def parse_server_hello_done(ctx, s):
    header_type, header_version, header_length = \
            struct.unpack('!bHH', s.read(1 + 2 + 2))

    buf = s.read(header_length)

    ctx.update_hash(buf)

    ss = stringio.StringIO(buf)

    type_length, = struct.unpack('!L', ss.read(4))
    msg_type = type_length >> 24
    msg_length = type_length & 0xffffff

    assert msg_type == TLS_HANDSHAKE_SERVER_HELLO_DONE


def parse_server_certificate(ctx, s):
    header_type, header_version, header_length = \
            struct.unpack('!bHH', s.read(1 + 2 + 2))

    buf = s.read(header_length)

    ctx.update_hash(buf)

    ss = stringio.StringIO(buf)

    type_length, = struct.unpack('!L', ss.read(4))
    msg_type = type_length >> 24
    msg_length = type_length & 0xffffff

    assert msg_type == TLS_HANDSHAKE_CERTIFICATE

    length, = struct.unpack('!L', '\x00' + ss.read(3))

    while length:
        length2, = struct.unpack('!L', '\x00' + ss.read(3))
        certificate = ss.read(length2)
        #print repr(certificate)

        ctx.certificates.append(certificate)

        length -= 3 + length2


def encrypt_msg(ctx, who, content_type, msg):
    if who == 'client':
        enc_obj = ctx.client_enc
        mac_obj = ctx.client_mac
    else:
        enc_obj = ctx.server_enc
        mac_obj = ctx.server_mac

    # mac
    if who == 'client':
        seq = struct.pack('!Q', ctx.client_num)
        ctx.client_num += 1
    else:
        seq = struct.pack('!Q', ctx.server_num)
        ctx.server_num += 1

    mac_obj = mac_obj.copy()
    mac_obj.update(seq)
    mac_obj.update(header(content_type, msg))
    mac_obj.update(msg)
    msg_mac = mac_obj.digest()

    #print 'MAC', repr(msg_mac)

    # crypto
    msg_crypted = enc_obj.encrypt(msg + msg_mac)

    return content_type, msg_crypted


def decrypt_msg(ctx, who, content_type, msg):
    if who == 'client':
        enc_obj = ctx.client_enc
        mac_obj = ctx.client_mac
    else:
        enc_obj = ctx.server_enc
        mac_obj = ctx.server_mac

    # crypto
    plaintext = enc_obj.decrypt(msg)
    msg, msg_mac = plaintext[:-20], plaintext[-20:] # XXX hard coded size of

    # mac
    if who == 'client':
        seq = struct.pack('!Q', ctx.client_num)
        ctx.client_num += 1
    else:
        seq = struct.pack('!Q', ctx.server_num)
        ctx.server_num += 1

    mac_obj = mac_obj.copy()
    mac_obj.update(seq)
    mac_obj.update(header(content_type, msg))
    mac_obj.update(msg)
    msg_mac_calculated = mac_obj.digest()

    #print 'MAC', repr(msg_mac), repr(msg_mac_calculated)

    assert msg_mac == msg_mac_calculated

    return content_type, msg


def do_handshake(ctx, send_func, recv_func):

    def send(msg):
        ret = (header(*msg) + msg[1])
        send_func(ret)

    def recv():
        ret = recv_func()
        return ret

    msg = make_msg_client_hello(ctx)
    send(msg)
    time.sleep(0.5) # XXX
    ret = stringio.StringIO(recv())
    parse_server_hello(ctx, ret)
    parse_server_certificate(ctx, ret)
    ctx.rsa = toytls.rsa.RSA(*toytls.x509.parse_der(ctx.certificates[0]))

    parse_server_key_exchange(ctx, ret)
    parse_server_hello_done(ctx, ret)

    if TLS_RSA_WITH_RC4_128_SHA not in ctx.ciphers:
        return

    msg = make_msg_client_key_exchange(ctx)
    send(msg)
    msg = make_msg_change_cipher_spec(ctx)
    send(msg)
    ctx.get_client_verify_data()
    ctx.setup_crypto()

    # encrypted step
    msg = make_msg_finished(ctx)
    msg = encrypt_msg(ctx, 'client', msg[0], msg[1])
    send(msg)

    ctx.get_server_verify_data()

    time.sleep(1.5)
    ret = stringio.StringIO(recv())
    parse_change_cipher_spec(ctx, ret)
    parse_finished(ctx, ret)


def do_handshake_socket(ctx, host, port):
    s = socket.socket()
    s.connect((host, port))

    def send_func(buf):
        s.sendall(buf)
    def recv_func(n=0):
        return s.recv(16*1024)

    try:
        do_handshake(ctx, send_func, recv_func)
    finally:
        s.close()


def do_handshake_transcript(transcript):
    send_buf = []
    recv_buf = []

    for line in transcript.split('\n'):
        if line.startswith('>>> '):
            send_buf.append(line[4:].decode('hex'))
        elif line.startswith('<<< '):
            recv_buf.append(line[4:].decode('hex'))

    def send_func(buf):
        pass

    def recv_func(n=0):
        s = recv_buf[0]
        del recv_buf[0]
        return s

    do_handshake(send_func, recv_func)
