#!/usr/bin/env python
# -*- coding:utf8 -*-

import random
import base64


class RSA(object):

    def __init__(self,p=0,q=0,e=0,d=0):
        self.p=p
        self.q=q
        self.n=p*q
        self.d=d
        self.e=e
        self.p,self.q,self.n,self.e,self.d= self.gen_keys(self.p,self.q,self.e,self.d)

    def get_key(self):
        return {'p':self.p,'q':self.q,'n':self.n,'e':self.e,'d':self.d}

    def get_prime(self):
        prime = []
        for num in range(1000, 10000 + 1):
            # prime numbers are greater than 1
            if num > 1:
                for i in range(2, num):
                    if (num % i) == 0:
                        break
                else:
                    prime.append(num)
        y = len(prime)
        x = random.randint(1, y-1)
        return prime[x]

    def gen_keys(self,p=0,q=0,e=0,d=0):
        if p==0:
            p = self.get_prime()
        #print("p = ",p)
        if q==0:
            q = self.get_prime()
        #print("q = ",q)
        n = p * q
        m = (p - 1) * (q - 1)
        if e==0 or d==0:
            e = self.get_e(m)
            d = self.get_d(e, m)
        while d < 0:
            d += m
        return [p, q, n, e, d]


    def get_e(self,m):
        """Finds an e coprime with m."""
        #e = 2
        e = self.get_prime()
        while self.gcd(e, m) != 1:
            e += 1
        return e


    def gcd(self,a, b):
        """Euclid's Algorithm: Takes two integers and returns gcd."""
        while b > 0:
            a, b = b, a % b
        return a

    def get_d(self,e, m):
        x = lasty = 0
        lastx = y = 1
        while m != 0:
            q = e // m
            e, m = m, e % m
            x, lastx = lastx - q*x, x
            y, lasty = lasty - q*y, y
        return lastx

    def encode(self,plaintext):
        return self._encode(plaintext,self.n,self.e,self.d)

    def _encode(self,plaintext,n=0,e=0,d=0):
        def _encryption(c,d,n):
            x = pow(c,d,n)
            return x
        result=[]
        result.append(str(n))
        result.append(str(d))
        for char in plaintext:
            result.append(str(_encryption(ord(char),e,n)))
        return base64.encodestring(','.join(result))

    def decode(self,ciphertext):
        return self._decode(ciphertext,self.n,self.d)

    def _decode(self,ciphertext,n=0,d=0):
        def _decrypt(c,d,n):
            x = pow(c,d,n)
            return x
        result=[]
        text=base64.decodestring(ciphertext)
        chars=text.split(',')
        if len(chars)>2:
            if n==0 or d==0:
                n=int(chars[0])
                d=int(chars[1])
        for i in range(2,len(chars)):
            result.append(chr( _decrypt(int(chars[i]),d,n)))
        return ''.join(result)





if __name__ == "__main__":
    cc={'q': 9551, 'p': 1307, 'e': 6133, 'd': 10670497}
    rsa=RSA(**cc)
    print(rsa.get_key())
    print(rsa.n)
    print(rsa.d)
    m=rsa.encode("你好go ~!@#$%^&*()_QWERTYUIODCVBNM<asdfasf")
    print(m)
    print rsa._decode(m,cc['p']*cc['q'],cc['d'])
    #print rsa.gen_keys()