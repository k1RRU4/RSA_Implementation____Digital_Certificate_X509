import random
import math
import secrets
RABIN_MILLER_ROUNDS = 128

def phi(p, q): # TODO: Ryma
    return (p-1)*(q-1)

def gcd(a, b):
    return math.gcd(a, b)

def inverse_modulo(x, m): # TODO: Ryma
    a, b = x, m
    prevAlpha, alpha = 1, 0
    prevBeta, beta = 0, 1

    while(b>0):
        q = a // b
        r = a % b
        alpha, prevAlpha = prevAlpha - q*alpha, alpha
        beta, prevBeta = prevBeta - q*beta, beta

        a, b = b, r

    return (prevAlpha % m)

def square_n_multiply(x, n, m):  # TODO: Ryma
    return pow(int(x), int(n), int(m))

def rabin_miller(n, rounds):  # TODO: Ryma
    s = n - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for _ in range(rounds): 
        a = random.randrange(2, n - 1)
        v = square_n_multiply(a, s, n)
        if v != 1: 
            i = 0
            while v != (n - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v*v) % n
    return True

def generate_random_nbits(n):  # TODO: Sabrina
    isPrime = False
    while (not isPrime):
        number = secrets.randbits(n)

        masque_fort = 2**(n -1)
        masque_faible = 1

        if (number & masque_fort != masque_fort):
            number += masque_fort
        if (number & masque_faible != masque_faible):
            number += masque_faible
        
        if (rabin_miller(number, RABIN_MILLER_ROUNDS)):
            isPrime = True     

    return number
