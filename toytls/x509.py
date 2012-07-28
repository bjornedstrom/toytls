# -*- coding: utf-8 -*-

from M2Crypto import m2, X509

def mpi_to_num(mpi):
    return int(m2.bn_to_hex(m2.mpi_to_bn(mpi)), 16)

def parse_der(der):
    cert = X509.load_cert_der_string(der)

    #log.debug('PARSING CERTIFICATE %s', cert.get_subject().as_text())

    rsa = cert.get_pubkey().get_rsa()
    e = mpi_to_num(m2.rsa_get_e(rsa.rsa))
    n = mpi_to_num(m2.rsa_get_n(rsa.rsa))
    return (n, e)
