#
# RSAPKCS1PlaintextSearchTest.py - Implementation of the PKCS1 plaintext search
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAMath import *
from RSAPadding import *
from RSAPKCS1 import *

def RSAPKCS1_plaintext_search(p,q,e,ct):
    if (((2**16)+1) < e):
        print("ERROR: Supplied public exponent is larger than Fermat-4.")
        return None

    N = p*q
    phi_N = (p-1)*(q-1)

    if (0 != (phi_N % e)):
        print("ERROR: (p-1)(q-1) is not divisible by the exponent.")

    if (0 == (phi_N % (e*e))):
        print("ERROR: (p-1)(q-1) is divisible by the square of the public exponent.")

    phihat_N = phi_N//e

    bytelen = (N.bit_length() + 7)//8
    print("RSA Key Byte Length: " + str(bytelen))
    print(phihat_N)

    d = modinv(e,phihat_N)

    print(phi_N)
    print(phi_N//e)

    print(xgcd(e,phihat_N))
    print(phihat_N % e)

    print("Searching for good generator...");
    with Timer() as t:
        g = find_generator(e,phihat_N,N)
    print("Good generator found in " + str(t.interval) + " seconds.");

    print(g)

    with Timer() as t:
        (Mp,Mq) = rsa_crt_precompute(p,q)
        g_e_torsion = rsa_crt_mod_exp(g, phihat_N, p, q, Mp, Mq)
        z = rsa_crt_mod_exp(ct, d, p, q, Mp, Mq)
    print("private key operations done in " + str(t.interval) + " seconds.");

    print("g of e torsion group = " + str(g_e_torsion))

    pt_list = []

    print("Searching for plaintext...")
    with Timer() as t:
        i = 1
        ell = g_e_torsion
        while (i < e):
            pt_hat = ell*z % N
            ptb = pt_hat.to_bytes(bytelen , 'big')
            (paddingValid, j, ptLen)=RSAES_PKCS1_v15_PaddingCheck(ptb)
            if (paddingValid and (8 <= j)):
                print("plaintext found.")
                M = RSAES_PKCS1_v15_Decode(ptb)
                pti = int.from_bytes(M, 'big')
                pt_dict = {"plaintext":pti, "paddinglength":j, "plaintextlength":ptLen}
                pt_list.append(pt_dict)
            i = i + 1
            ell = ell*g_e_torsion % N
    print("Plaintext search finished in " + str(t.interval) + " seconds.");

    return pt_list

