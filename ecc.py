# Basics of Elliptic Curve Cryptography implementation on Python
# Based on code from https://gist.github.com/bellbind/1414867
# Adapted by Dominik Schoop
# Version: 15.06.2025
# Changes:
# - 15.06.2025
#   - corrected calculation of order of point, order can be larger than q
#   - included sqrt, jacobi, egcd functions from same source to speed up computation

import collections
import random # randint
import math   # math.sqrt
import sympy  # isprime
from sympy.ntheory.residue_ntheory import sqrt_mod# sqrt_mod(a, modulus)

Coord = collections.namedtuple("Coord", ["x", "y"])
Sig = collections.namedtuple("Sig", ["r", "s"])

##############################################################
# Numerical helper functions

def curve(x, a, b, p):
    return (x**3 + a*x + b) % p 

def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q
    >>> assert n * inv(n, q) % q == 1
    """
    # n*inv % q = 1 => n*inv = q*m + 1 => n*inv + q*-m = 1
    # => egcd(n, q) = (inv, -m, 1) => inv = egcd(n, q)[0] (mod q)
    return egcd(n, q)[0] % q


def egcd(a, b):
    """extended GCD
    returns: (s, t, gcd) as a*s + b*t == gcd
    >>> s, t, gcd = egcd(a, b)
    >>> assert a % gcd == 0 and b % gcd == 0
    >>> assert a * s + b * t == gcd
    """
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a


def sqrt(n, q):
    """sqrtmod for bigint
    - Algorithm 3.34 of http://www.cacr.math.uwaterloo.ca/hac/about/chap3.pdf
    """
    # b: some non-quadratic-residue
    b = 0 
    while b == 0 or jacobi(b, q) != -1:
        b = random.randint(1, q - 1)
    # q = t * 2^s + 1, t is odd
    t, s = q - 1, 0 
    while t & 1 == 0:
        t, s = t >> 1, s + 1
    assert q == t * pow(2, s) + 1 and t % 2 == 1
    ni = inv(n, q)
    c = pow(b, t, q)
    r = pow(n, (t + 1) // 2, q)
    for i in range(1, s):
        d = pow(pow(r, 2, q) * ni % q, pow(2, s - i - 1, q), q)
        if d == q - 1:
            r = r * c % q
        c = pow(c, 2, q)
    return (r, q - r)


def jacobi(a, q):
    """quick jacobi symbol
    - algorithm 2.149 of http://www.cacr.math.uwaterloo.ca/hac/about/chap2.pdf
    """
    if a == 0: return 0
    if a == 1: return 1
    a1, e = a, 0
    while a1 & 1 == 0:
        a1, e = a1 >> 1, e + 1
    m8 = q % 8
    s = -1 if m8 == 3 or m8 == 5 else 1 # m8 = 0,2,4,6 and 1,7
    if q % 4 == 3 and a1 % 4 == 3: s = -s
    return s if a1 == 1 else s * jacobi(q % a1, a1)


##############################################################
# Classes for elliptic curves and EC groups

class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert sympy.isprime(q)
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2)) % q != 0
        self.a = a
        self.b = b
        self.q = q
        # just as unique ZERO value representation for "add": (not on curve)
        self.zero = Coord(0, 0)

    def is_valid(self, p):
        """check whether point p is on curve""" 
        if p == self.zero:
            return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        """find points on curve at x
        - x: 0 <= int < q
        - returns: ((x, y), (x,-y)) or not found exception
        >>> a, ma = ec.at(x)
        >>> assert a.x == ma.x and a.x == x
        >>> assert a.x == ma.x and a.x == x
        >>> assert ec.neg(a) == ma
        >>> assert ec.is_valid(a) and ec.is_valid(ma)
        """
        assert 0<= x and x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y1, y2 = sqrt(ysq, self.q)
        return Coord(x, y1), Coord(x, y2)

    def at_sympy(self,x):
        """find points on curve at x using sympy'?''?'s function sqrt_mod"""
        assert 0<= x and x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        roots = sqrt_mod(ysq, self.q, all_roots=True)
        if len(roots) < 2: # type: ignore
            raise ValueError(f"No roots found for x={x}")
        y1, y2 = roots[:2] # type: ignore
        print(y1, y2)
        return Coord(x, y1), Coord(x, y2)

    def neg(self, p):
        """negate p
        >>> assert ec.is_valid(ec.neg(p))
        """
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        """<add> of elliptic curve: negate of 3rd cross point of (p1,p2) line
        >>> d = ec.add(a, b)
        >>> assert ec.is_valid(d)
        >>> assert ec.add(d, ec.neg(b)) == a
        >>> assert ec.add(a, ec.neg(a)) == ec.zero
        >>> assert ec.add(a, b) == ec.add(b, a)
        >>> assert ec.add(a, ec.add(b, c)) == ec.add(ec.add(a, b), c)
        """
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            # p1 + -p1 == 0
            return self.zero
        if p1.x == p2.x:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """n times <mul> of elliptic curve
        >>> m = ec.mul(p, n)
        >>> assert ec.is_valid(m)
        >>> assert ec.mul(p, 0) == ec.zero
        """
        r = self.zero
        m2 = p
        # O(log2(n)) add
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
            n, m2 = n >> 1, self.add(m2, m2)
        return r

    def order(self, g, offset=1):
        """order of point g, brute force of order starting at factor offset
        >>> o = ec.order(g)
        >>> assert ec.is_valid(a) and ec.mul(a, o) == ec.zero
        >>> assert o <= ec.q
        """
        assert self.is_valid(g) and g != self.zero
        """ original code with wrong assumption of order of curve
        for i in range(1, self.q + 1):
            if self.mul(g, i) == self.zero:
                return i
            pass
        raise Exception("Invalid order")
        """
        i = offset
        r = self.mul(g,i)
        bound = 2*math.sqrt(self.q)+self.q-1
        while r != self.zero:
            r = self.add(r,g)
            i += 1
            assert i <= bound
            if i % 1000 == 0:
                print(f'Order > {i}')
        return i


class EcGroup(object):
    """Elliptic Curve Group"""
    def __init__(self, ec, g, n=None):
        """elliptic curve group defined by ellipti curve ec and generator g
        - ec: elliptic curve
        - g: generator
        - n: order of generator
        """
        assert ec.is_valid(g)
        self.ec = ec
        self.g = g
        if n:
            self.n = n
        else:
            print(f'Calculating order of group generated by {self.g} ...')
            self.n = self.ec.order(g)


##############################################################
# Classes for cryptographic schemes

class EcCrypto(object):
    """Super class for elliptic curve cryptography schemes"""
    def __init__(self, ecg, sk = None, pk = None):
        """
        - ecg: elliptic curve group
        - pk: public key (point of group)
        """
        assert sympy.isprime(ecg.n), "Order of EC group for crypto must be prime!"
        self.ecg = ecg
        if pk:
            assert self.ecg.ec.is_valid(pk)
            self.pk = pk
            self.sk = sk
        else:
            sk, pk = self.genKeyPair()
            self.pk = pk
            self.sk = sk
            
    def genKeyPair(self):
        """generate secret and public key pair """
        sk = random.randint(2, self.ecg.n-2)
        assert 1 < sk and sk < self.ecg.n-1
        pk = self.ecg.ec.mul(self.ecg.g, sk)
        assert self.ecg.ec.is_valid(pk)
        return sk, pk


class ElGamal(object):
    """ElGamal Encryption
    pub key encryption as replacing (mulmod, powmod) to (ec.add, ec.mul)
    - ec: elliptic curve
    - g: (random) a point on ec
    """
    def __init__(self, ec, g):
        assert ec.is_valid(g)
        self.ec = ec
        self.g = g
        self.n = ec.order(g)
        pass

    def gen(self, priv):
        """generate pub key
        - priv: priv key as (random) int < ec.q
        - returns: pub key as points on ec
        """
        return self.ec.mul(self.g, priv)

    def enc(self, plain, pub, r):
        """encrypt
        - plain: data as a point on ec
        - pub: pub key as points on ec
        - r: randam int < ec.q
        - returns: (cipher1, ciper2) as points on ec
        """
        assert self.ec.is_valid(plain)
        assert self.ec.is_valid(pub)
        return (self.ec.mul(self.g, r), self.ec.add(plain, self.ec.mul(pub, r)))

    def dec(self, cipher, priv):
        """decrypt
        - chiper: (chiper1, chiper2) as points on ec
        - priv: private key as int < ec.q
        - returns: plain as a point on ec
        """
        c1, c2 = cipher
        assert self.ec.is_valid(c1) and self.ec.is_valid(c2)
        return self.ec.add(c2, self.ec.neg(self.ec.mul(c1, priv)))
    pass


class DiffieHellman(object):
    """Elliptic Curve Diffie Hellman (Key Agreement)
    - ec: elliptic curve
    - g: a point on ec
    """
    def __init__(self, ec, g):
        self.ec = ec
        self.g = g
        self.n = ec.order(g)
        pass

    def gen(self, priv):
        """generate pub key"""
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def secret(self, priv, pub):
        """calc shared secret key for the pair
        - priv: my private key as int
        - pub: partner pub key as a point on ec
        - returns: shared secret as a point on ec
        """
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        return self.ec.mul(pub, priv)
    pass


class DSA(EcCrypto):
    """ECDSA
    - ecg: elliptic curve group
    """
    def __init__(self, ecg, sk = None, pk = None):
        super(DSA, self).__init__(ecg, sk, pk)

    def sign(self, hashval):
        """generate signature
        - hashval: hash value of message as int
        - returns: signature as (r, s) = (int, int)
        """
        k = random.randint(2, self.ecg.n-2)
        R = self.ecg.ec.mul(self.ecg.g, k)
        r = R.x
        assert 0 <= r and r <= self.ecg.ec.q
        kinv = inv(k, self.ecg.n)
        s = (kinv *(r * self.sk + hashval)) % self.ecg.n
        print(f'sk={self.sk} pk={self.pk} k={k} R={R} r={r} kinv={kinv} s={s}')
        return Sig(r, s)

    def signSEC1(self, hashval):
        """generate signature
        - hashval: hash value of message as int
        - returns: signature as (r, s) = (int, int)
        """
        k = random.randint(2, self.ecg.n-2)
        k = 5
        R = self.ecg.ec.mul(self.ecg.g, k)
        r = R.x
        assert 0 <= r and r <= self.ecg.ec.q
        kinv = inv(k, self.ecg.n)
        s = (kinv *(r * self.sk + hashval)) % self.ecg.n
        print(f'sk={self.sk} pk={self.pk} k={k} R={R} r={r} kinv={kinv} s={s}')
        return Sig(R, s)

    def validate(self, hashval, sig):
        """validate signature
        - hashval: hash value of message as int
        - sig: signature as (int, int)
        """
        assert self.ecg.ec.mul(self.pk, self.ecg.n) == self.ecg.ec.zero
        r = sig.r
        s = sig.s
        sinv = inv(s, self.ecg.n)
        u1 = (sinv * hashval) % self.ecg.n
        u2 = (sinv * r) % self.ecg.n
        assert 0 <= u1 and u1 <= self.ecg.n
        assert 0 <= u2 and u2 <= self.ecg.n
        P = self.ecg.ec.mul(self.ecg.g, u1)
        Q = self.ecg.ec.mul(self.pk, u2)
        R = self.ecg.ec.add(P, Q)
        return R.x % self.ecg.n == r

    def validateSEC1(self, hashvalue, sig):
        """validate signature according to SEC1: sR = hG + rQ_s
        - hashvalue: hash value of message as int
        - sig: signature as (Point R, s)
        """
        assert self.ecg.ec.mul(self.pk, self.ecg.n) == self.ecg.ec.zero
        R = sig.r
        s = sig.s
        r = R.x
        print('r=',r)
        sR = self.ecg.ec.mul(R, s)
        assert self.ecg.ec.is_valid(sR)
        print('sR=', sR)
        hG = self.ecg.ec.mul(self.ecg.g, hashvalue)
        assert self.ecg.ec.is_valid(hG)
        print('hG=', hG)
        print('Q=', self.pk)
        rQ = self.ecg.ec.mul(self.pk, r)
        assert self.ecg.ec.is_valid(rQ)
        print('rQ=', rQ)
        S = self.ecg.ec.add(hG, rQ)
        assert self.ecg.ec.is_valid(S)
        print('S=',S)
        return sR == S


# ECDSA with P-256
class ECDSAP256(DSA):
    # Initialise with P-256 as curve group
    def __init__(self, sk = None, pk = None):
        p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
        gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        ec = EC(a, b, p)
        G = Coord(gx, gy)
        assert ec.is_valid(G)
        ecg = EcGroup(ec, G, order)
        super(DSA, self).__init__(ecg)

# Lab 3: Task "Points on Elliptic Curves"
def task1():
    print('Task1')
    ec = EC(1, 6, 19)
    G, _ = ec.at(0)
    o = ec.order(G)
    print(f'Point {G} of order {o}')
    # A + B = 4G + 12G = 16G = (4,13) 
    A = ec.mul(G,4)
    B = ec.mul(G,12)
    ApB = ec.add(A,B)
    print(A, B, ApB)
    # P + Q = 15G + 8G = 5G = (14,3)
    P = ec.mul(G,15)
    Q = ec.mul(G,8)
    PpQ = ec.add(P,Q)
    print(P,Q,PpQ)


# Lab 3: Task "Elliptic Curve Signatures"
def signature(ec, G, order):
    ecg = EcGroup(ec, G, order)
    # Calculating DSA signature
    print('Calculating signature ...')
    hashval = 1111
    dsa = DSA(ecg)
    sig = dsa.sign(hashval)
    print(f'hashval = {hashval}, sig = (r,s) = {sig}')
    print('Validating signature ...')
    dsaval = DSA(ecg, dsa.pk)
    v = dsaval.validate(hashval, sig)
    print(f'Validation result: {v}')

def signature2(ec, G, order):
    ecg = EcGroup(ec, G, order)
    # Calculating DSA signature
    print('Calculating signature ...')
    hashval = 2222
    dsa = DSA(ecg)
    sig = dsa.sign(hashval)
    print(f'hashval = {hashval}, sig = (r,s) = {sig}')
    print('Validating signature ...')
    dsaval = DSA(ecg, dsa.pk)
    v = dsaval.validate(hashval, sig)
    print(f'Validation result: {v}')


"""
F'?''?'r Python ok (ecc.py in code):
Elliptic Curve defined by y^2 = x^3 + x + 4 over Finite Field of size 19991
Order of curve: 20107
Singular: False
Group is cyclic: True
Generator: (12461, 14735)
Order of generator: 20107
Order is prime: True
"""
def task2_19991():
    print('Task2')
    a = 1
    b = 4
    p = 19991
    order = 20107
    gx = 12461
    offset = 1
    ec = EC(a, b, p)
    G, _ = ec.at(gx)
    # order = ec.order(G, offset)
    print(f'Point {G} of order {order}')
    signature(ec, G, order)



"""
Elliptic Curve defined by y^2 = x^3 + x + 3 over Finite Field of size 989999
Order of curve: 988711
Singular: False
Group is cyclic: True
Generator: (312450, 693062)
Order of generator: 988711
Order is prime: True
"""
def task2_989999():
    print('Task2')
    a = 1
    b = 3
    p = 989999
    gx = 312450
    gy = 693062
    order = 988711
    ec = EC(a, b, p)
    G = Coord(gx, gy)
    #G, _ = ec.at(gx) # dauert zu lange
    #order = ec.order(G, offset)
    print(f'Point {G} of order {order}')
    signature(ec, G, order)


"""
Elliptic Curve defined by y^2 = x^3 + 2*x + 4 over Finite Field of size 1999119991111
Order of curve: 1999117407433
Singular: False
Group is cyclic: True
Generator: (1866387998426, 149355341077)
Order of generator: 1999117407433
Order is prime: True
"""
def task2():
    print('Task2')
    a = 2
    b = 4
    p = 1999119991111
    gx = 1866387998426
    gy = 149355341077
    order = 1999117407433
    ec = EC(a, b, p)
    G = Coord(gx, gy)
    print(f'Point {G} of order {order}')
    signature2(ec, G, order)


"""
Calculate the hash for verifying a V2X signature
 From IEEE Std 1609.2-2022
 5.3.1.2.2 Hashing data for use with ECDSA
 Hash ( Hash (Data input) || Hash (Signer identifier input) )
 Data input = the data to be signed
 Signer identifier = the certificate with which the message is to be verified,
canonicalized as specified in 6.4.3.
"""
from Crypto.Hash import SHA256

def V2Xhash(datainput, signerinput):
    from Crypto.Hash import SHA256
    from math import log, ceil
    di = datainput.to_bytes(ceil(log(datainput,10)))
    si = signerinput.to_bytes(ceil(log(signerinput,10)))
    hdi = SHA256.new(di)
    hsi = SHA256.new(si)
    h = SHA256.new()
    h.update(hdi.digest())
    h.update(hsi.digest())
    return h.hexdigest()


def V2XverifySignature(ec, G, order, pk, sig, hashval):
    """verify a signature from V2X message
    - ec elliptic curve
    - G generator of curve group
    - order of G
    - pk public key use for signature verification
    - sig signature sig = (r,s)
    - hashval hashvalue to verify
    """
    ecg = EcGroup(ec, G, order)
    dsa = DSA(ecg, pk=pk)
    # Verifying DSA signature
    print('Verifying signature ...')
    dsaval = DSA(ecg, dsa.pk)
    v = dsaval.validate(hashval, sig)
    print(f'Validation result: {v}')


def V2XverifySignatureSEC1(ec, G, order, pk, sig, hashval):
    """verify a signature from V2X message
    - ec elliptic curve
    - G generator of curve group
    - order of G
    - pk public key use for signature verification
    - sig signature sig = (r,s)
    - hashval hashvalue to verify
    """
    ecg = EcGroup(ec, G, order)
    dsa = DSA(ecg, pk=pk)
    # Verifying DSA signature
    print('Verifying signature ...')
    v = dsa.validateSEC1(hashval, sig)
    print(f'Validation result: {v}')
    

"""
Calculate with curve P-256
https://neuromancer.sk/std/nist/P-256
"""
def task3():
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    ec = EC(a, b, p)
    G = Coord(gx, gy)
    assert ec.is_valid(G)
    print(ec)
    pkx = 0xdafbe36affefccffdbab2f116476d15404a8e1796ab16f2743f908b09f858a64
    pkysq = curve(pkx, a, b, p)
    print('p =',p)
    print('y^2 =', pkysq)
    pk1, pk2 = ec.at_sympy(pkx)
    print(pk1, pk2)
    pk = pk1
    assert ec.is_valid(pk1)
    assert ec.is_valid(pk2)
    cert =0x800300800498fbf3b8b8c2491083000000000028012e358400a8010280012481040301000080012581050401901a25808083dafbe36affefccffdbab2f116476d15404a8e1796ab16f2743f908b09f858a6480801f35c743f172186d8bedb4642d71aa06d37a2383c83debbb1a29429187abb05d17339cc73a3f89a544e03f7a9834693fdd5fcaa297aa9c3811091a89e3dbdcd4
    tbsData =0x4003805620500280003201001400c6af9a8d233650f8e5931d0bf01b058cbcde898405090000a00007d1000002029a8d2336e79b005a561acbae1ad28222382304323ef814585060a4cb0302968a7f340382008e003fe013f9804001240002629c4c4901e9
    hashvalue = V2Xhash(cert, tbsData)
    print('hashvalue=', hashvalue)
    hashvalue = 0x52e9bb4a8e314fc652a79fe723a4e863834e8efe590918155e221512ad25e0e2
    print('hashvalue=', hashvalue)
    rSig = 0x9e0ab6ce4682581a6b042f5d167dca53541f67ea0949c809a48f2073d5421185
    # compressed-y-0
    pk1, pk2 = ec.at_sympy(pkx)
    print(pk1, pk2)
    rSig = pk2
    sSig = 0x9b0c4c1759b7913eb626ff7c4738c4802a06a0fc9d675ac09e4f64bcfaf24761
    sig = Sig(rSig, sSig)
    V2XverifySignatureSEC1(ec, G, order, pk, sig, hashvalue)
    # Umwandlung PER in COER
    # https://asn1.io/asn1playground
    # https://python-asn1.readthedocs.io/en/latest/usage.html
    # https://pypi.org/project/asn1tools/
    # https://pypi.org/project/pyasn1/
    # https://pypi.org/project/asn1/
    # https://github.com/erupikus/asn1PERser

def testECDSA():
    # Set up elliptic curve
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    ec = EC(a, b, p)
    G = Coord(gx, gy)
    assert ec.is_valid(G)
    sk = 123
    pk = ec.mul(G, sk)
    cert = 0x123
    tbsData = 0x456
    hashvalue = int(V2Xhash(cert, tbsData), 16)
    print('hashvalue=', hashvalue)
    # Calculating DSA signature
    print('Calculating signature ...')
    ecg = EcGroup(ec, G, order)
    dsa = DSA(ecg, sk=sk, pk=pk)
    sig = dsa.signSEC1(hashvalue)
    print(sig)
    V2XverifySignatureSEC1(ec, G, order, pk, sig, hashvalue)

"""
    (sage) demo@VMSecurity:~/Documents/Crypto/scritps$ sage ECDSA_V2X.sage 
Order of E: 
115792089210356248762697446949407573529996955224135760342422259061068512044369
Order of G: 
115792089210356248762697446949407573529996955224135760342422259061068512044369
(48439561293906451759052585252797914202762949526041747995844080717082404635286 :
36134250956749795798585127919587881956611106672985015071877198253568414405109 : 1)
T=(p,a,b,G,n,h) = 
115792089210356248762697446949407573530086143415290314195533631308867097853951
115792089210356248762697446949407573530086143415290314195533631308867097853948
41058363725152142129326129780047268409114441015993725554835256314039467401291
(48439561293906451759052585252797914202762949526041747995844080717082404635286,
36134250956749795798585127919587881956611106672985015071877198253568414405109)
115792089210356248762697446949407573529996955224135760342422259061068512044369 1
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
G.x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
G.y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
sk = ds =  123
pk = Qs = 
(58395042060992335878150939717354546788858832256123935708864336688468259941433 :
76502785570223235138250388011722477033795205918218849467160924186128156983140 : 1)
Hashvalue = 
87245272982239218952671407490051395694850518571422540432985895673502060242188
Calculating signature ...
k, inverse of k 5
23158417842071249752539489389881514705999391044827152068484451812213702408874
Point R = 
(36794669340896883012101473439538929759152396476648692591795318194054580155373,
101659946828913883886577915207667153874746613498030835602133042203824767462820)
x_r coordinate of R: 
36794669340896883012101473439538929759152396476648692591795318194054580155373
signature sig = (r,s) = 
((36794669340896883012101473439538929759152396476648692591795318194054580155373 :
101659946828913883886577915207667153874746613498030835602133042203824767462820 : 1),
42578042383803675291729931295170392386142197336410567242352837844322392333409)
s*R= (88367291879657791038091275291549022570775614704766584179331327050084061698110
: 2546397813935727133722539885063408520635603424604025708677030695813139914140 : 1)
hashvalue*G=
(36187701002620353671945351744963984730763367410724920900039353647426437401400 :
5115135642993953950863890135329579984031194112088995471344829656067274849704 : 1)
r*Qs= (28477335479679200023037129253302029166384941817515689862559900644767543323749
: 36055426110714409601253997282974987490501485183083825870439714765081598824668 : 1)
hG+rQs=
(88367291879657791038091275291549022570775614704766584179331327050084061698110 :
2546397813935727133722539885063408520635603424604025708677030695813139914140 : 1)
Valid? True
"""
    
def main():
    #task2_19991()
    #task2_989999()
    #task2()
    task3()
    #testECDSA()
    print('Done.')


if __name__ == "__main__":
    main()


def rest_original():
    # shared elliptic curve system of examples
    ec = EC(1, 18, 19)
    g, _ = ec.at(7)
    assert ec.order(g) <= ec.q
    
    # ElGamal enc/dec usage
    eg = ElGamal(ec, g)
    # mapping value to ec point
    # "masking": value k to point ec.mul(g, k)
    # ("imbedding" on proper n:use a point of x as 0 <= n*v <= x < n*(v+1) < q)
    mapping = [ec.mul(g, i) for i in range(eg.n)]
    plain = mapping[7] 
    
    priv = 5
    pub = eg.gen(priv)
    
    cipher = eg.enc(plain, pub, 15)
    decoded = eg.dec(cipher, priv)
    assert decoded == plain
    assert cipher != pub
    
    
    # ECDH usage
    dh = DiffieHellman(ec, g)
    
    apriv = 11
    apub = dh.gen(apriv)
    
    bpriv = 3
    bpub = dh.gen(bpriv)
    
    cpriv = 7
    cpub = dh.gen(cpriv)
    # same secret on each pair
    assert dh.secret(apriv, bpub) == dh.secret(bpriv, apub)
    assert dh.secret(apriv, cpub) == dh.secret(cpriv, apub)
    assert dh.secret(bpriv, cpub) == dh.secret(cpriv, bpub)
    
    # not same secret on other pair
    assert dh.secret(apriv, cpub) != dh.secret(apriv, bpub)
    assert dh.secret(bpriv, apub) != dh.secret(bpriv, cpub)
    assert dh.secret(cpriv, bpub) != dh.secret(cpriv, apub)
    
    
    # ECDSA usage
    dsa = DSA(ec, g)
    
    priv = 11
    pub = eg.gen(priv)
    hashval = 128
    r = 7
    
    ec = EC(a, b, p)
    G = Coord(gx, gy)
    assert ec.is_valid(G)
    ecg = EcGroup(ec, G, order)
    
    dsa = DSA(ecg, sk=priv, pk=pub)
    sig = dsa.sign(hashval)
    assert dsa.validate(hashval, sig)

    pass