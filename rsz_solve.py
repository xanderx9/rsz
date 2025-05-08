# -*- coding: utf-8 -*-
"""


@credit: KV
"""
import random
import secp256k1 

G = scalar_multiplication(1)
N = N

# ==============================================================================

def inv(a):
    return pow(a, N - 2, N)


def valid_rsz(r, s, z, pub_point):
    RP1 = pub2upub('02' + hex(r)[2:].zfill(64))
    RP2 = pub2upub('03' + hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    FF1 = point_subtraction( point_multiplication(RP1, sdr),
                                scalar_multiplication(zdr) )
    FF2 = point_subtraction( point_multiplication(RP2, sdr),
                                scalar_multiplication(zdr) )
    if FF1 == pub_point or FF2 == pub_point:
        return True
    else:
        return False


def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * inv(dr)) % N


def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = inv((s1 * r2 - s2 * r1) % N)
    x = (x1 * xi) % N
    return x

def getx(Q):
    return int(Q[1:33].hex(), 16)
# ==============================================================================

pvk = random.SystemRandom().randint(1, 2 ** 256)
print('=' * 72)
print('  True Privatekey = ', hex(pvk))
print('=' * 72)
Q = scalar_multiplication(pvk)

k1 = random.SystemRandom().randint(1, 2 ** 256)
P1 = scalar_multiplication(k1)
r1 = getx(P1)
z1 = random.SystemRandom().randint(1, 2 ** 256)
s1 = (inv(k1) * (z1 + r1 * pvk)) % N

k2 = random.SystemRandom().randint(1, 2 ** 256)
P2 = scalar_multiplication(k2)
r2 = getx(P2)
z2 = random.SystemRandom().randint(1, 2 ** 256)
s2 = (inv(k2) * (z2 + r2 * pvk)) % N

diff = (k2 - k1) % N
# ==============================================================================
print(f'k1: {hex(k1)}\nr1: {hex(r1)}\ns1: {hex(s1)}\nz1: {hex(z1)}')
if valid_rsz(r1, s1, z1, Q): print('  Tx1 Correct: rsz Validated the Pubkey')
print('=' * 72)
print(f'k2: {hex(k2)}\nr2: {hex(r2)}\ns2: {hex(s2)}\nz2: {hex(z2)}')
if valid_rsz(r2, s2, z2, Q): print('  Tx2 Correct: rsz Validated the Pubkey')

# ==============================================================================
# Generation Complete. Now let's start to solve it using 2 rsz and diff.
# ==============================================================================
print('=' * 72)
print('  Starting to solve rsz using difference of k between 2 Tx')
k = getk1(r1, s1, z1, r2, s2, z2, diff)
x = getpvk(r1, s1, z1, r2, s2, z2, diff)
print(f'  Extracted Privatekey = {hex(x)}')
if getx(scalar_multiplication(k)) == r1 or getx(scalar_multiplication(k)) == r2:
    print(f'====   Nonce Found using 2 rsz diff   = {hex(k)}')
