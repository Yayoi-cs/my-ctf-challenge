from sympy import primerange
from Crypto.Util.number import getPrime,bytes_to_long,isPrime
import math
import re

flag = "flag{***REDACTED***}"
assert(re.match(r"^flag\{.+!\}$",flag.decode()))

p = getPrime(16)
q = getPrime(16)
n = p*q
a = 0
b = 0
primes = list(primerange(1,n))
for prime in primes:
    a += math.log(prime**2 + 1)
    b += math.log(prime**2 - 1)

e = round(math.exp(a-b) * 10)

f = bytes_to_long(flag)
cipher = f - p * e
print(f"{cipher=}")
