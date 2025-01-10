# Writeup: Long Live 1337

## Challenge Description:

We are given a Sage script that encrypts a flag using AES-ECB with a key derived from a secret value (`secret_of_life`). This secret is split into two halves, `half_way` and `way_half`. The script constructs two polynomial expressions, `TimeMaster1` and `TimeMaster2`, based on these halves, and prints values `Past` and `Future`, derived from these expressions. Finally, the flag is encrypted using AES and the SHA-256 hash of the full secret.

Our task is to retrieve the flag by recovering the secret and decrypting the flag.

### Sage Script:

```python
#! /usr/bin/env sage
#
# [Crypto/Medium] Long Live 1337

import os
import hashlib
from Crypto.Util.number import bytes_to_long
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

FLAG = os.environ.get("FLAG", "flag{REDACTED}").encode()

secret_of_life = os.urandom(64)
half_way, way_half = secret_of_life[:32], secret_of_life[32:]

F.<x> = RealField(1337)[]
TimeMaster1 = sum([coeff * (x - 1337)**i for i, coeff in enumerate(half_way)])
TimeMaster2 = sum([coeff * (x - 1337)**i for i, coeff in enumerate(way_half)])

Past = TimeMaster1.roots()[0][0]
Future = TimeMaster2(bytes_to_long(way_half)).integer_part()

print(f"{Past = }")
print(f"{Future = }")

KEY = hashlib.sha256(secret_of_life).digest()
ENC_FLAG = AES.new(KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16)).hex()

print(f"{ENC_FLAG = }")
```

## Challenge Analysis

* Secret Generation:
	* A 64-byte random secret (secret_of_life) is split into two parts: half_way and way_half.
	* Two polynomials, TimeMaster1 and TimeMaster2, are created from these two parts. The coefficients of these polynomials are derived from the bytes of the two halves.
	* `Past` is a root for TimeMaster1 and `Future` is the evaluation of `way_half` with `TimeMaster2`
* Encryption
	* The AES key is created by hashing the entire 64-byte secret_of_life with SHA-256.
	* The flag is padded to a 16-byte boundary and encrypted using AES in ECB mode, with the resulting ciphertext printed in hexadecimal format.

Our goal is to retrieve both values of `way_half` and `half_way` to be able to reconstruct the key and decrypt the flag.

## Solution

### Travel to the Past

At first, we start by looking for the value of `Past`. `TimeMaster1` is a polynomial in the Real field in the form: $T_1(X)=\sum_{n=0}^{31}h_n(X-1337)^n$ with $h_n$ are the the bytes of `half_way`. And Past ($p$), is an approximative value of a real root of that polynomial: $T_1(p) = 0$. 

This reminds us of one of the use cases of the lattice reduction for algebraic number approximation. In short, given $\alpha$ (`Past` in our case) an approximation of an algebraic number (the real root of the polynomial), we can find a polynomial $f$ such that $f(\alpha)$ is small usin lattice reduction algorithm LLL.

This video explains the process of the lattice construction in details [LLL Algorithm - Approximation of Algebraic Numbers](https://www.youtube.com/watch?v=U8MI2a_BHHo&t=925s)

With this method, we can recover the first pard of the secret.

### Go back to The Future

Like the first pars, we are given `TimeMaster2` which is a polynomial in the Real field in the form: $T_2(X)=\sum_{n=0}^{31}w_n(X-1337)^n$ with $w_n$ are the the bytes of `way_half`. And Future ($F$), is the result of $T_2(w)=F$ where $w$ is `way_half`. 

F can be written like that: $T_2(w)=\sum_{n=0}^{31}w_n(w-1337)^n$. Given that `way_half` is a 256 bits long integer, $\lfloor \sqrt[63]{F / w_{31}} \rfloor$ + 1337 is a good approximation of $w$. And we can bruteforce to get the value of $w_{31}$ since it is smaller than 256.

With that we can reconstruct the secret, and decrypt the flag.

## Solve script

```python
#! /usr/bin/env sage
from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib

R = RealField(1337)

Past = ...
Future = ...
ENC_FLAG = ...

ENC_FLAG = bytes.fromhex(ENC_FLAG)

Past = Past - 1337
real = [Past ** i for i in range(32)]
K = 2 ** (1337 - 1)
M = matrix([[round(K * x) for x in real]]).T.augment(
    matrix.identity(32)
)

M = M.LLL()
rec_half_way = bytes([abs(x) for x in M[0][1:]])

for i in range(1,256):
    rec_way_half = round((Future//i)^(1/31))+1337
    rec_way_half = long_to_bytes(rec_way_half)

    rec_secret_of_life = rec_half_way + rec_way_half
    KEY = hashlib.sha256(rec_secret_of_life).digest()
    rec_flag = AES.new(KEY, AES.MODE_ECB).decrypt(ENC_FLAG)
    if b"flag" in rec_flag:
        print(rec_flag)
        break
```