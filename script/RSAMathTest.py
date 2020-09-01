#
# RSAMathTest.py - Tests for the mathematics functions
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAMath import *

def Test_Mod_CRT(N, p, q,ntests=10):
    phiN = (p-1)*(q-1)
    (Mp,Mq) = rsa_crt_precompute(p,q)
    for _ in range(ntests):
        x = random.randint(1, N)
        a = random.randint(1, phiN)
        y = pow(x, a, N)
        ycrt = rsa_crt_mod_exp(x, a, p, q, Mp, Mq)
        if (y != ycrt):
            print("MOD EXP CRT FAILED!")
            return False
    return True

# 256-bit n
n = 29865191353574605527576142154665662760069157332722232908944465250541370923717
p = 105943264837628291368588115498666759579
q = 281897970572710409379912902924766414623
e = 65537

print("256 bit experiment")

pt = random.randint(2**255, 2**256)
pt = pt % n

ct = pow(pt, e, n)

pt_out = fix_bad_rsa_encryption(p, q, e, ct, pt)

print("pt=", pt)
print("pt_out=", pt_out)

Test_Mod_CRT(n, p, q)

# 512 bit n
n = 6020354501838682015849080079806375252444005783890216702874271917419622372892423281524120196835379431670180440627091319438156749830861865663944510389977981
p = 56707933411172887678109258450273054838756057952372116336034264615184143162319
q = 106164237342010437583582702908636891659657542364161656282054650336691404243699
e = 65537

print("512 bit experiment")

pt = random.randint(2**511, 2**512)
pt = pt % n

ct = pow(pt, e, n)

pt_out = fix_bad_rsa_encryption(p, q, e, ct, pt)

print("pt=", pt)
print("pt_out=", pt_out)

Test_Mod_CRT(n, p, q)

# 1024 bit n
n = 3283820208958447696987943374117448908009765357285654693385347327161990683145362435055078968569512096812028089118865534433123727617331619214412173257331161
p = 34387544593670505224894952205499074005031928791959611454481093888481277920639
q = 95494466027181231798633086231116363926111790946014452380632032637864163116199
e = 65537

print("1024 bit experiment")

pt = random.randint(2**1023, 2**1024)
pt = pt % n

ct = pow(pt, e, n)

pt_out = fix_bad_rsa_encryption(p, q, e, ct, pt)

print("pt=", pt)
print("pt_out=", pt_out)

Test_Mod_CRT(n, p, q)
