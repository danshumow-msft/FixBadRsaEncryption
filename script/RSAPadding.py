#
# RSAPadding.py - RSA PKCS1 v.5 and OAEP Padding functions
#
# Copyright (c) Microsoft Corporation. Licensed under the MIT license.
#

import secrets
import hashlib
import math

def RSAES_PKCS1_v15_Encode(n, e, M):

    if ((int != type(n)) or (int != type(e))):
        raise TypeError("Public key arguments n and e must by type int.")
    if (bytes != type(M)):
        raise TypeError("Message argument M must be type class bytes.")

    k = (n.bit_length() + 7)//8

    mLen = len(M)

    if (mLen > (k - 11)):
        raise ValueError("Message mLen is too long.")

    padLen = k - mLen - 3

    PS = bytearray(secrets.randbits(8*padLen).to_bytes(padLen, "big"))

    for i in range(padLen):
        while (0 == PS[i]):
            PS[i] = secrets.randbits(8)

    EM = bytearray(k)

    EM[0] = 0x00
    EM[1] = 0x02
    EM[2:1+padLen] = PS
    EM[padLen+2] = 0x00
    EM[padLen+3:] = M

    return bytes(EM)


def RSAES_PKCS1_v15_PaddingCheck(EM):

    if (bytes != type(EM)):
        raise TypeError("Encoded Message must be type class bytes.")

    k = len(EM)

    paddingValid = False
    j = -1

    ptLen = 0

    if ((0x00 == EM[0]) and (0x02 == EM[1])):
        paddingValid = True

    if (paddingValid):
        j = EM.find(0x00, 2)

        if ((-1 == j) or (j < 10)):
            paddingValid = False
        else:
            j = j - 2
            ptLen = k - j - 3

    return (paddingValid, j, ptLen)
    

# Testing purpose only
# This function is not constant time and can leak information 
# about the private key via a bleichenbacher timing attack.
# Also, the exceptions returned will leak information as well.
def RSAES_PKCS1_v15_Decode(EM):

    if (bytes != type(EM)):
        raise TypeError("Encoded Message must be type class bytes.")
    
    if ((0x00 != EM[0]) or (0x02 != EM[1])):
        raise ValueError("Padding format is invalid.")

    j = EM.find(0x00, 2)

    if ((-1 == j) or (j < 10)):
        raise ValueError("Padding length is incorrect.")

    M = EM[j+1:]

    return M

allowed_hashes = {'md5', 'sha384', 'sha3_256', 'sha3_384', 'sha512', 'blake2s', 'sha1', 'sha3_512', 'sha256', 'sha224', 'blake2b', 'sha3_224'}

def RSAES_PKCS1_v22_OAEP_MGF1(mgfSeed, maskLen, hashfn):
    if (bytes != type(mgfSeed)):
        raise TypeError("Mask generation seed argument mgfSeed must be type bytes.")
    if (int != type(maskLen)):
        raise TypeError("Mask length argument maskLen must be type int.")
    if (str != type(hashfn)):
        raise TypeError("Hash function argument hashfn must be type str.")
    if (hashfn not in allowed_hashes):
        raise ValueError("Hash function argument hashfn must be a gauranteed algorithm in hashlib.")

    h = hashlib.new(hashfn)
    hLen = h.digest_size

    if ((2**32)*hLen < maskLen):
        raise ValueError("Mask length argument masklen must be at most (2^32)*hashLen. (mask too long)")

    h.update(mgfSeed)

    T = bytearray()

    for counter in range((maskLen+hLen)//hLen):
        C = counter.to_bytes(4, 'big')
        h2 = h.copy()
        h2.update(C)
        T.extend(h2.digest())

    return bytes(T[0:maskLen])
    

def RSAES_OAEP_EME_Encode(n, e, M, L, hashfn):

    if ((int != type(n)) or (int != type(e))):
        raise TypeError("Public key arguments n and e must be type int.")
    if (bytes != type(M)):
        raise TypeError("Message argument M must be type class bytes.")
    if ((None != L) and (bytes != type(L))):
        raise TypeError("Optional Label argument L must be None or type class bytes.")
    if (str != type(hashfn)):
        raise TypeError("Hash function argument hashfn must be type str.")
    if (hashfn not in allowed_hashes):
        raise ValueError("Hash function argument hashfn must be a gauranteed algorithm in hashlib.")

    #
    # 1. Length checking:
    #

    # get lengths of parameters
    k = (n.bit_length() + 7)//8
    mLen = len(M)

    h = hashlib.new(hashfn)
    hLen = h.digest_size

    # step 1a
    if ((None != L) and ((2**61 - 1) < len(L))):
        raise ValueError("Optional Label argument L must be at most 2**61 - 1 bytes long.  label too long.")

    # step 1b
    if ((k - 2*hLen - 2) < mLen):
        raise ValueError("Message argument M must be less than (modulus_length - 2*hash_digest_length - 2) bytes.  message too long.")

    #
    # 2. EME-OAEP encoding (see Figure 1 in section 7.1.1 of PKCS#1 v 2.2):
    #

    # step 2a
    if (None != L):
        h.update(L)
        
    lHash = h.digest()

    # step 2b    
    lPS = k - mLen - 2*hLen - 2
    PS = bytes(lPS)

    # step 2c
    DB = lHash + PS + b'\x01' + M

    # step 2d
    seedi = secrets.randbits(8*hLen)
    seed = seedi.to_bytes(hLen, 'big')

    # step 2e
    lDB = k - hLen - 1
    dbMask = RSAES_PKCS1_v22_OAEP_MGF1(seed, lDB, hashfn)

    # step 2f
    DBi = int.from_bytes(DB, 'big')
    dbMaski = int.from_bytes(dbMask, 'big')
    maskedDBi = DBi^dbMaski
    maskedDB = maskedDBi.to_bytes(lDB, 'big')

    # step 2g
    seedMask = RSAES_PKCS1_v22_OAEP_MGF1(maskedDB, hLen, hashfn)

    # step 2h
    seedMaski = int.from_bytes(seedMask, 'big')
    maskedSeedi = seedi ^ seedMaski
    maskedSeed = maskedSeedi.to_bytes(hLen, 'big')

    # step 2i
    EM = b'\x00' + maskedSeed + maskedDB

    return EM


def RSAES_OAEP_EME_Decode(n, EM, L, hashfn):
    
    if (int != type(n)):
        raise TypeError("Public key arguments n and e must be type int.")
    if (bytes != type(EM)):
        raise TypeError("Encoded Message argument EM must be type class bytes.")
    if ((None != L) and (bytes != type(L))):
        raise TypeError("Optional Label argument L must be None or type class bytes.")
    if (str != type(hashfn)):
        raise TypeError("Hash function argument hashfn must be type str.")
    if (hashfn not in allowed_hashes):
        raise ValueError("Hash function argument hashfn must be a gauranteed algorithm in hashlib.")

    #
    # 1. Length checking:
    #

    # get lengths of parameters
    k = (n.bit_length() + 7)//8
    EMlen = len(EM)

    h = hashlib.new(hashfn)
    hLen = h.digest_size

    # step 1a
    if ((None != L) and ((2**61 - 1) < len(L))):
        raise ValueError("Optional Label argument L must be at most 2**61 - 1 bytes long.  label too long.")

    # step 1b
    if (k != EMlen):
        raise ValueError("Encoded Message argument EM must have length equal to byte length of modulus n.  decryption error.")

    # step 1c
    if (k < (2*hLen + 2)):
        raise ValueError("modulus_length must be >= 2*hash_digest_length.  decryption error.")

    #
    # 2. RSA decryption:
    # This step is skipped and the output is assumed to be passed to this function.

    #
    # 3. EME-OAEP decoding:
    #

    # step 3a
    if (None != L):
        h.update(L)

    lHash = h.digest()

    # step 3b
    # parse EM = Y || masked_seed || maskedDB
    Y = EM[0]
    maskedSeed = EM[1:hLen+1]
    maskedDB = EM[hLen+1:]
    maskedDBi = int.from_bytes(maskedDB, 'big')

    # step 3c
    seedMask = RSAES_PKCS1_v22_OAEP_MGF1(maskedDB, hLen, hashfn)

    # step 3d
    seedMaski = int.from_bytes(seedMask, 'big')
    maskedSeedi = int.from_bytes(maskedSeed, 'big')
    seedi = seedMaski ^ maskedSeedi
    seed = seedi.to_bytes(hLen, 'big')

    # step 3e
    dbMask = RSAES_PKCS1_v22_OAEP_MGF1(seed, k-hLen-1, hashfn)

    # step 3f
    maskedDBi = int.from_bytes(maskedDB, 'big')
    dbMaski = int.from_bytes(dbMask, 'big')
    DBi = maskedDBi ^ dbMaski
    DB = DBi.to_bytes(k-hLen-1, 'big')

    # step 3g
    # parse DB = lHash_decoded || PS || 0x01 || M

    lHash_decoded = DB[0:hLen]

    i = hLen
    while (0x00 == DB[i]) :
        i = i + 1

    S = DB[i]

    M = DB[i+1:]

    mLen = len(M)

    padding_correct = True

    padding_correct = (0x00 == Y) and padding_correct
    padding_correct = (0x01 == S) and padding_correct
    padding_correct = (lHash_decoded == lHash) and padding_correct
    padding_correct = ((i-hLen) == (k - mLen - 2*hLen - 2)) and padding_correct

    return (M, padding_correct)

