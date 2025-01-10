# Writeup: EZFHE

## Solution:

The challenge is an implementation of the BFV crypto system. 
For some PK given `(a,b)`, we are given `(c0,c1) = (u*a + M, u*b)`.
We can hence calculate `u = c1/b`, then `M = c0 - a*u`, and scale the message down. 
This gives us the raw encrypted data, which we can parse out for the flag.
(Note: All arithmetic is over `GF(q)['x']`)

## Solve script
```python
q = 4294967377
N = 2048
R.<x> = PolynomialRing(GF(q), 'x').quotient(x^N + 1)
exec(open(__import__("sys").argv[1]).read())
to_poly = lambda arr: sum(arr[i] * x^i for i in range(len(arr)))
p0 = to_poly(p0)
p1 = to_poly(p1)
c0 = to_poly(c0)
c1 = to_poly(c1)

p1_inv = p1^-1
u = c1 * p1_inv
u_inv = u^-1
M_scaled = c0 - p0*u

plain_modulus = 256
ciph_modulus = 4294967377
sf = ciph_modulus // plain_modulus
pt = list(M_scaled/sf)
data = bytes(pt)

data = data[data.index(b'flag{'):]
data = data[:data.index(b'}')+1]
print(data.decode())
```