#
# RSAOAEPTest.py - Tests for RSA OAEP encrypt/decrypt
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAOAEP import *

import RSATestCases

print("\n\nRunning OAEP Test Cases:")

for prvk in RSATestCases.valid_priv_keys:
    p = prvk["p"]
    q = prvk["q"]
    N = prvk["N"]
    e = prvk["e"]
    d = prvk["d"]

    pt = RSATestCases.pt

    for hashfn in allowed_hashes:
        nl = (N.bit_length()+7)//8
        dl = hashlib.new(hashfn).digest_size
        if (len(pt) >= nl - 2*(dl+1)):
            continue
        Test_RSA_OAEP(p, q, N, e, d, pt, hashfn)
