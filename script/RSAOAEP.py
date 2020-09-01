#
# RSAOAEP.py - Implementation of the RSA encrypt/decrypt with OAEP
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAMath import *
from RSAPadding import *

def RSAEncrypt_OAEP(pt, n, e, hashfn, OAEPLabel=None):
    if (str != type(hashfn)):
        raise TypeError("Hash function argument hashfn must be type str.")
    pt_padded = RSAES_OAEP_EME_Encode(n, e, pt, OAEPLabel, hashfn)
    ipt = int.from_bytes(pt_padded, 'big')
    ct = pow(ipt, e, n)
    bytelen = (n.bit_length()+7)//8
    return ct.to_bytes(bytelen, 'big')

def RSADecrypt_OAEP(ct, p, q, d, hashfn, OAEPLabel=None):
    if (str != type(hashfn)):
        raise TypeError("Hash function argument hashfn must be type str.")
    ict = int.from_bytes(ct, 'big')
    n = p*q
    ipt = pow(ict, d, n)
    bytelen = (n.bit_length()+7)//8
    pt_padded = ipt.to_bytes(bytelen, 'big')
    (pt, padding_correct) = RSAES_OAEP_EME_Decode(n, pt_padded, OAEPLabel, hashfn)
    if (not padding_correct):
        raise ValueError("Decrypted plaintext padding was incorrect.")
    return pt

def Test_RSA_OAEP(p,q,N,e,d,pt,hashfn):
    ct = RSAEncrypt_OAEP(pt, N, e, hashfn)
    pt_out = RSADecrypt_OAEP(ct, p, q, d, hashfn)
    if (pt == pt_out):
        print("PASSED.")
    else:
        print("FAILED.")

