#
# RSAPKCS1.py - Implementation of the RSA encrypt/decrypt with PKCS1 v1.5
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAMath import *
from RSAPadding import *

def RSAEncrypt_PKCS1(pt, n, e):
    pt_padded = RSAES_PKCS1_v15_Encode(n, e, pt)
    ipt = int.from_bytes(pt_padded, 'big')
    ct = pow(ipt, e, n)
    bytelen = (n.bit_length()+7)//8
    return ct.to_bytes(bytelen, 'big')

def RSADecrypt_PKCS1(ct, p, q, d):
    ict = int.from_bytes(ct, 'big')
    n = p*q
    ipt = pow(ict, d, n)
    bytelen = (n.bit_length()+7)//8
    pt_padded = ipt.to_bytes(bytelen, 'big')
    pt = RSAES_PKCS1_v15_Decode(pt_padded)
    return pt

def Test_RSA_PKCS1(p,q,N,e,d,pt):
    ct = RSAEncrypt_PKCS1(pt, N, e)
    pt_out = RSADecrypt_PKCS1(ct, p, q, d)
    if (pt == pt_out):
        print("PASSED.")
    else:
        print("FAILED.")

