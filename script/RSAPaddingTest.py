#
# RSAPaddingTest.py - Testing for RSA PKCS1 v.5 and OAEP Padding functions
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

from RSAPadding import *

n = 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
e = 0x101

n2048_bytes = b'\x80' + bytearray(255)
n2048 = int.from_bytes(n2048_bytes, 'big')

def Test_PKCS1_v15(n, e, M):
    EM = RSAES_PKCS1_v15_Encode(n,e,M)
    M2 = RSAES_PKCS1_v15_Decode(EM)

    print("Decrypted Plaintext == Encrypted Plaintext? " + str(M==M2))

    (pc, j, hashLen) = RSAES_PKCS1_v15_PaddingCheck(EM)
    print("padding checked out " + str(pc) + ".  padding length = " + str(j) +", hash length = " + str(hashLen))

def Test_OAEP(n, e, M, L):
    for hashfn in allowed_hashes:
        print(hashfn)
        EM = RSAES_OAEP_EME_Encode(n, e, M, L, hashfn)
        (M_decoded, padding_correct) = RSAES_OAEP_EME_Decode(n, EM, L, hashfn)

        print("Decoded message == input message? " + str(M == M_decoded))
        if (M != M_decoded):
            print("M  = " + hex(int.from_bytes(M, 'big')))
            print("M' = " + hex(int.from_bytes(M_decoded, 'big')))
        print("padding checked out " + str(padding_correct) + " Decoded message length: " + str(len(M_decoded))) 

testhash160 = 0x0123456789012345678901234567890123456789
testhash256 = 0x0123456789012345678901234567890123456789012345678901234567890123
testhash384 = 0x012345678901234567890123456789012345678901234567890123456789012345678901234567890123
testhash512 = 0x01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123

M1 = testhash160.to_bytes(20, 'big')
Test_PKCS1_v15(n, e, M1)

M2 = testhash256.to_bytes(32, 'big')
Test_PKCS1_v15(n, e, M2)

M3 = testhash384.to_bytes(48, 'big')
Test_PKCS1_v15(n, e, M3)

M4 = testhash512.to_bytes(64, 'big')
Test_PKCS1_v15(n, e, M4)

nonce = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
nonceb = nonce.to_bytes(64, 'big')

hSha1 = hashlib.sha1()
hSha1.update(nonceb)
M5 = hSha1.digest()

Test_PKCS1_v15(n, e, M5)

hMd5 = hashlib.md5()
hMd5.update(nonceb)
M6 = hMd5.digest()

Test_PKCS1_v15(n, e, M6)

hSha256 = hashlib.sha256()
hSha256.update(nonceb)
M7 = hSha256.digest()

Test_PKCS1_v15(n, e, M7)

hSha384 = hashlib.sha384()
hSha384.update(nonceb)
M8 = hSha384.digest()

Test_PKCS1_v15(n, e, M8)


hSha512 = hashlib.sha512()
hSha512.update(nonceb)
M9 = hSha512.digest()

Test_PKCS1_v15(n, e, M9)

messages = [M1, M2, M3, M4, M5, M6, M7, M8, M9]
              
for M in messages:
    Test_OAEP(n2048, e, M, None)
