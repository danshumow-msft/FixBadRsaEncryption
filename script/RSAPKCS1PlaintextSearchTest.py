#
# RSAPKCS1PlaintextSearchTest.py - Test for the PKCS1 Plaintext Search
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#


from RSAPKCS1PlaintextSearch import *

def print_pt_list(pt_list):
    print("Found " + str(len(pt_list)) + " valid plaintext search.")
    for pt_dict in pt_list:
        pt = hex(pt_dict["plaintext"])
        padLen = pt_dict["paddinglength"]
        ptLen = pt_dict["plaintextlength"]
        print("plaintext: " + pt + " plaintext length: " + str(ptLen) + " padding length: " + str(padLen))

def test_plaintext_search(p, q, N, e, pt):
    ct = RSAEncrypt_PKCS1(pt, N, e)
    cti = int.from_bytes(ct, 'big')
    pt_list = RSAPKCS1_plaintext_search(p, q, e, cti)
    print_pt_list(pt_list)

import RSATestCases

pt = RSATestCases.pt

for bad_prvk in RSATestCases.bad_priv_keys:
    p = bad_prvk["p"]
    q = bad_prvk["q"]
    N = bad_prvk["N"]
    e = bad_prvk["e"]
    bitlen = bad_prvk["bitlength"]
    print("RSA PKCS1 plaintext search " + str(bitlen) + "bit test case:\n")
    test_plaintext_search(p,q,N,e,pt)
    print("\n\n")
