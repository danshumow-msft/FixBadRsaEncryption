#
# RSAOAEPPlaintextSearchTest.py - Test for the OAEP Plaintext Search
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAOAEPPlaintextSearch import *

def print_pt_list(pt_list):
    print("Found " + str(len(pt_list)) + " valid plaintext search.")
    for pt_dict in pt_list:
        pt = hex(pt_dict["plaintext"])
        ptLen = pt_dict["plaintextlength"]
        print("plaintext: " + pt + " plaintext length: " + str(ptLen))

def test_oaep_plaintext_search(p, q, N, e, pt, hashfn):
    ct = RSAEncrypt_OAEP(pt, N, e, hashfn)
    cti = int.from_bytes(ct, 'big')
    pt_list = RSAOAEP_plaintext_search(p, q, e, cti, hashfn)
    print_pt_list(pt_list)

import RSATestCases

pt = RSATestCases.pt

for bad_prvk in RSATestCases.bad_priv_keys:
    p = bad_prvk["p"]
    q = bad_prvk["q"]
    N = bad_prvk["N"]
    e = bad_prvk["e"]
    bitlen = bad_prvk["bitlength"]
    for hashfn in allowed_hashes:
        dl = hashlib.new(hashfn).digest_size
        nl = (bitlen+7)//8
        if (len(pt) >= (nl - 2*(dl+1))):
            continue
        print("RSA OAEP plaintext search " + str(bitlen) + "bit test case with " + hashfn +":\n")
        test_oaep_plaintext_search(p,q,N,e,pt, hashfn)
        print("\n\n")

