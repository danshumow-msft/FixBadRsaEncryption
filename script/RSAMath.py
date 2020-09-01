#
# RSAMath.py - Mathematics functions used in RSA and plaintext search
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

import time
import random

class Timer:
    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()  #TODO: remove deprecated function
        self.interval = self.end - self.start

def xgcd(x,y):
    if (x < y):
        (x,y) = (y,x)
    (a,b,g,u,v,w) = (1,0,x,0,1,y)
    while (w > 0):
        q = g//w
        (a,b,g,u,v,w) = (u,v,w,a-q*u,b-q*v,g-q*w)
    return (a,b,g)

def modinv(x,N):
    if (x >= N):
        x = x%N
    (a,b,g) = xgcd(N,x)
    if (1 != g):
        return None
    if (b < 0):
        b = (b + N) % N
    return b

def find_generator(a,b,N):
    g = 2
    found = False
    while ((g < 1000) and (~found)):
        (a_order_good,b_order_good) = (1 != pow(g,a,N),1 != pow(g,b,N))
        if (a_order_good and b_order_good):
            found = True;
            break;
        g = g + 1
    if (not found):
        print("ERROR: Unable to find a generator.")
        return None
    return g


def calculate_decrypt_exponent(p, q, e):
    phiN = (p-1)*(q-1)
    d = modinv(e, phiN)
    if (None == d):
        print("ERROR calculating decrypt exponent.")
    return d

def rsa_crt_precompute(p, q):
    N = p*q
    pinv = modinv(p,q)
    qinv = modinv(q,p)
    Mp = qinv*q % N
    Mq = pinv*p % N
    return (Mp, Mq)

def rsa_crt_mod_exp(x, a, p, q, Mp, Mq):
    N = p*q
    xp = x % p
    xq = x % q
    ap = a % (p-1)
    aq = a % (q-1)
    yp = pow(xp, ap, p)
    yq = pow(xq, aq, q)
    y = (yp*Mp + yq*Mq) % N
    return y
    

def fix_bad_rsa_encryption(p,q,e,ct,pt):
    if (((2**16)+1) < e):
        print("ERROR: Supplied public exponent is larger than Fermat-4.")
        return None

    (bad_p,bad_q) = (0 == ((p-1)%e),0 == ((q-1)%e))

    if (bad_p and bad_q):
        print("ERROR: both p and q are divisible by the public exponent.")
        return None

    # Make p the bad prime
    if (bad_q):
        (p,q) = (q,p)

    if (0 == (p-1)%(e*e)):
        print("ERROR: bad prime is divisible by square of public exponent.")

    N = p*q
    phi_N = (p-1)*(q-1)

    phihat_N = phi_N//e

    print(phihat_N)

    d = modinv(e,phihat_N)

    print(phi_N)
    print(phi_N/e)

    print(xgcd(e,phihat_N))
    print(phihat_N % e)

    print("Searching for good generator...");
    with Timer() as t:
        g = find_generator(e,phihat_N,N)
    print("Good generator found in " + str(t.interval) + " seconds.");

    print(g)

    with Timer() as t:
        g_e_torsion = pow(g, phihat_N, N)
        z = pow(ct,d,N)
    print("non crt private key operations done in " + str(t.interval) + " seconds.");
    
    with Timer() as t:
        (Mp,Mq) = rsa_crt_precompute(p,q)
        g_e_torsion = rsa_crt_mod_exp(g, phihat_N, p, q, Mp, Mq)
        z = rsa_crt_mod_exp(ct, d, p, q, Mp, Mq)
    print("crt private key operations done in " + str(t.interval) + " seconds.");

    print("g of e torsion group = " + str(g_e_torsion))

    print("Searching for plaintext...")
    with Timer() as t:
        i = 1
        ell = g_e_torsion
        while (i < e):
            pt_hat = ell*z % N
            if (pt_hat == pt):
                print("plaintext found.")
                break
            i = i + 1
            ell = ell*g_e_torsion % N
    print("Plaintext search finished in " + str(t.interval) + " seconds.");

    return pt_hat

