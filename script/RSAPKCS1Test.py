#
# RSAPKCS1Test.py - Test of the RSA encrypt/decrypt with PKCS1 v1.5
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAPKCS1 import *

import RSATestCases

print("\n\nRunning PKCS1 Test Cases:")

for prvk in RSATestCases.valid_priv_keys:
    p = prvk["p"]
    q = prvk["q"]
    N = prvk["N"]
    e = prvk["e"]
    d = prvk["d"]
    
    pt = RSATestCases.pt
    
    Test_RSA_PKCS1(p, q, N, e, d, pt)
