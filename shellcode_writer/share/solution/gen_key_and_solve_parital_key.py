#!/usr/bin/env python2

from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from timeit import default_timer as timer

import os
import gmpy2
import itertools as it


def extract2(inp):
    two = 0
    while inp % 2 == 0:
        inp //= 2
        two += 1
    return inp, two

def genkey():
    while 1:
        while 1:
            p = getPrime(512)
            q = getPrime(512)
            if len(bin(abs(p - q))[2:]) < 450 or (p + q) & 1 != 0:
                continue

            phi = (p - 1) * (q - 1)
            e = 257
            print (gmpy2.gcd(phi, e))
            try:
                d = int(gmpy2.invert(e, phi))
            except:
                continue

            assert (d * e) % phi == 1
            ret = (d*e - 1) // phi
            break

        print ('d : ', d)
        r = 256
        mod = 2 ** r
        d0 = d % mod

        d0e = d0 * e
        print (bin(d0e)[-10:])

        if d0e & (1 << 2):
            x = RSA.construct((p*q, e, d, p, q))
            output = x.exportKey("PEM")
            with open('pri.pem', 'w') as f:
                f.write(output)
            output = x.publickey().exportKey("PEM")
            with open('pub.pem', 'w') as f:
                f.write(output)
            break
    return ret


def solve():
    x = RSA.importKey(open('pub.pem', 'rb').read())

    # LSb you can get
    # you should put the leaked private key here
    d0 = THE_LEAKED_PRIVATE_KEY % mod
    r = 304
    mod = 2 ** r
    e = x.e
    N = x.n
    d0e = d0 * e

    cnt = 0
    now = timer()
    total_time = 0
    for k in range(1, e, 2):
        print ('k : ', k)
        k_left, two_right = extract2(k)
        k_left_1 = gmpy2.invert(k_left, mod)

        left = N + 1 + k_left_1 - k_left_1 * d0e
        left %= mod
        _, two_left = extract2(left)
        assert two_left - two_right > 0

        poss_s = []
        random_length = two_left - two_right - 1
        poss_set = it.product('01', repeat=random_length)
        poss_set = map(''.join, poss_set)

        os.system('rm -rf ./ans')
        for s in poss_set:
            s += bin(left)[2:].rjust(r, '0')
            assert len(s) == r
            # Hensel
            os.system('python3.6 ./tools_on_git/Hensel.py {} {}'.format(int(s, 2), N))
            # solving univariate polynomial, similar to sage's small_roots
            os.system('sage ./tools_on_git/coppersmith.sage {}'.format(N))
            cnt += 1
            total_time += timer() - now
            now = timer()
        print ('\tcnt : ', cnt)
        print ('\tavg : ', total_time * 1.0 / cnt)
        if os.path.isfile('ans'):
            print ('answer found !')
            exit()


#ret = genkey()
#print ('mutiplier : ', ret)
solve()




